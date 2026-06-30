// Direct unit-style test for Http3's session-ticket cache: 10000-entry
// cap, LRU eviction order. Talks to Http3::storeSession/lookupSession
// statics — no network, no aioquic origin.
//
// Exit 0 on pass, non-zero on fail with a message on stderr.

#include "../Http3.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <vector>

namespace {

bool exists(const std::string &k)
{
    // Note: lookupSession touches the key (moves to MRU). Use sparingly
    // in assertions, or use it deliberately to bump a key.
    return Http3::lookupSession(k) != nullptr;
}

std::vector<uint8_t> blob_for(int i)
{
    std::string s = "blob-" + std::to_string(i);
    return std::vector<uint8_t>(s.begin(), s.end());
}

void check(bool cond, const char *what)
{
    if(!cond)
    {
        std::fprintf(stderr, "FAIL: %s\n", what);
        std::exit(1);
    }
}

// Reset state by overflowing the cache by 2x — every key from a prior
// section gets evicted. Cheap and avoids needing a clear() API.
void purge()
{
    for(int i = 0; i < 20000; ++i)
        Http3::storeSession("purge-" + std::to_string(i), {});
    // Then bulk-touch nothing else; the next test will overwrite freshly.
}

} // namespace

int main()
{
    constexpr int CAP = 10000;

    // ----- Sanity -----
    check(Http3::sessionCacheSize() == 0, "starts empty");

    // ----- Cap enforcement: never exceeds 10000 -----
    for(int i = 0; i < CAP + 500; ++i)
        Http3::storeSession("a" + std::to_string(i), blob_for(i));
    check(Http3::sessionCacheSize() == CAP, "exactly cap after overflow");

    // The first 500 entries (a0..a499) inserted should have been evicted.
    // a500..a10499 should survive.
    check(!exists("a0"),    "a0 evicted (oldest)");
    check(!exists("a499"),  "a499 evicted (oldest-500)");
    check(exists("a500"),   "a500 survives");
    check(exists("a10499"), "a10499 (newest) survives");

    // ----- LRU semantics: touching an old entry prevents eviction -----
    purge();
    check(Http3::sessionCacheSize() == CAP, "after purge still capped");

    // Start fresh fill: b0..b9999 are the only "real" entries we care
    // about. Reset state first via a bigger purge to push out all purge-X.
    for(int i = 0; i < CAP; ++i)
        Http3::storeSession("b" + std::to_string(i), blob_for(i));
    check(Http3::sessionCacheSize() == CAP, "b-fill capped");

    // b0 is now LRU. Touch it — should bypass the next eviction.
    Http3::lookupSession("b0");

    // Add one fresh entry. b1 should be the new LRU and the one evicted.
    Http3::storeSession("c-new", blob_for(42));
    check(exists("b0"),   "b0 survived (touched)");
    check(!exists("b1"),  "b1 evicted (oldest non-touched)");
    check(exists("c-new"),"new entry present");
    check(Http3::sessionCacheSize() == CAP, "still capped after touch+insert");

    // ----- Re-storeSession overwrites in place AND touches -----
    // Choose a mid-range entry that's still present.
    check(exists("b5000"), "b5000 present pre-overwrite");
    Http3::storeSession("b5000", blob_for(98765));
    check(Http3::sessionCacheSize() == CAP, "overwrite doesn't grow");
    const auto *p = Http3::lookupSession("b5000");
    check(p != nullptr, "b5000 found after overwrite");
    check(*p == blob_for(98765), "b5000 blob is new value");

    // After 9998 fresh inserts, b5000 should still be around because it was
    // touched (overwrite + lookup), but b2 should not.
    for(int i = 0; i < CAP - 2; ++i)
        Http3::storeSession("d" + std::to_string(i), blob_for(i));
    check(exists("b5000"), "b5000 survived (touched twice)");
    check(!exists("b2"),   "b2 evicted (deep LRU)");

    // ===== Origin-failure cache: three-phase confirmation =====
    //
    // Make the gate tiny so the test doesn't have to wait 15 minutes.
    // Drop the confirm-interval to 0 — any second failure (even within
    // the same second) is enough to confirm. The 72 h TTL stays at the
    // default; the test exercises only the LRU + state transitions, not
    // wall-clock expiry.
    Http3::kOriginFailureConfirmIntervalSeconds = 0;

    sockaddr_in6 t0{};
    t0.sin6_family = AF_INET6;
    t0.sin6_addr.s6_addr[15] = 1;          // ::1
    t0.sin6_port = htons(443);

    // Phase 1: single failure → pending only, NOT confirmed.
    check(!Http3::isOriginRecentlyFailed(t0), "fresh target not failed");
    Http3::markOriginFailed(t0);
    check(!Http3::isOriginRecentlyFailed(t0),
          "single failure does NOT confirm (transient-blip guard)");
    check(Http3::pendingFailureCacheSize() == 1,
          "single failure is in pending only");
    check(Http3::failureCacheSize() == 0,
          "single failure is NOT in confirmed");

    // Phase 2: second failure with elapsed gap → promoted to confirmed.
    Http3::markOriginFailed(t0);
    check(Http3::isOriginRecentlyFailed(t0),
          "two failures spanning the confirm interval → confirmed");
    check(Http3::failureCacheSize() == 1, "confirmed map has the entry");
    check(Http3::pendingFailureCacheSize() == 0,
          "promoting from pending empties pending entry");

    // Successful retry clears all phases.
    Http3::markOriginSuccess(t0);
    check(!Http3::isOriginRecentlyFailed(t0),
          "success clears confirmed");
    check(Http3::failureCacheSize() == 0, "success purges confirmed map");

    // Probation phase: simulate the 72 h TTL having elapsed. We can do
    // it deterministically by pushing the kOriginFailureTtlSeconds
    // down to 0 and triggering a lookup. The lookup re-classifies the
    // entry into probation; restore the TTL afterwards so the rest of
    // the test isn't affected.
    Http3::markOriginFailed(t0);
    Http3::markOriginFailed(t0);
    check(Http3::isOriginRecentlyFailed(t0), "re-confirmed before TTL trick");
    uint64_t savedTtl = Http3::kOriginFailureTtlSeconds;
    Http3::kOriginFailureTtlSeconds = 0;
    // First lookup after TTL=0: should evict from confirmed and move
    // to probation, returning false so the daemon retries H3 once.
    check(!Http3::isOriginRecentlyFailed(t0),
          "after TTL expiry, lookup moves entry to probation (returns false)");
    check(Http3::failureCacheSize() == 0, "no longer in confirmed map");
    Http3::kOriginFailureTtlSeconds = savedTtl;
    // The retry fails too → one post-expiry failure re-promotes (no
    // 15-min wait again).
    Http3::markOriginFailed(t0);
    check(Http3::isOriginRecentlyFailed(t0),
          "probation + one failure = immediate re-confirmation");

    // Different port for same IP is tracked independently.
    Http3::markOriginSuccess(t0);
    sockaddr_in6 t0_port2 = t0;
    t0_port2.sin6_port = htons(8443);
    check(!Http3::isOriginRecentlyFailed(t0_port2),
          "same IP different port is independent");

    // Bound enforcement: confirm map caps at 10000.
    for(int i = 0; i < 10500; ++i)
    {
        sockaddr_in6 t{};
        t.sin6_family = AF_INET6;
        t.sin6_addr.s6_addr[15] = static_cast<uint8_t>(i & 0xff);
        t.sin6_addr.s6_addr[14] = static_cast<uint8_t>((i >> 8) & 0xff);
        t.sin6_addr.s6_addr[13] = static_cast<uint8_t>((i >> 16) & 0xff);
        t.sin6_port = htons(443);
        Http3::markOriginFailed(t); // first failure → pending
        Http3::markOriginFailed(t); // second → confirmed
    }
    check(Http3::failureCacheSize() == 10000,
          "confirmed cache capped at 10000");

    std::fprintf(stderr,
        "PASS: session LRU + origin failure cache (pending/confirmed/probation)\n");
    return 0;
}
