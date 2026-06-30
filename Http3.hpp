#ifndef HTTP3_H
#define HTTP3_H

#include "EpollObject.hpp"

#include <cstdint>
#include <deque>
#include <list>
#include <string>
#include <vector>
#include <unordered_map>
#include <netinet/in.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>

// HTTP/3 backend leg (QUIC layer wired; HTTP/3 streams come next).
//
// One Http3 instance owns:
//  - one connected UDP socket (EpollObject::fd) to the origin,
//  - one ngtcp2_conn driving the QUIC state machine,
//  - one OpenSSL SSL + ngtcp2_crypto_ossl_ctx for QUIC-TLS,
//  - one timerfd (inner EpollObject) for ngtcp2 expiry.
//
// The session-ticket cache is RAM-only and process-lifetime. Each entry is
// an i2d_SSL_SESSION-serialized blob keyed by "host:port". Captured by the
// SSL_CTX new-session callback; consumed at SSL_new + SSL_set_session
// before SSL_do_handshake to enable resumption (and 0-RTT once we send app
// data). Nothing is written to disk.
class Http3 : public EpollObject
{
public:
    Http3();
    ~Http3() override;

    // One-time process init. Idempotent. Returns true on success.
    static bool globalInit();

    // Bring up a QUIC client connection. `remote` is the origin (IPv6
    // sockaddr; the Confiared address space invariant is enforced
    // upstream in Dns). `sni` is the TLS SNI / certificate hostname.
    // `sessionKey` is "host:port" (decimal port) and is also the
    // session-ticket cache key.
    bool start(const sockaddr_in6 &remote,
               const std::string &sni,
               const std::string &sessionKey);

    void parseEvent(const epoll_event &event) override;

    // RAM session-ticket cache. Key is "host:port" (printable host,
    // decimal port). Value is an i2d_SSL_SESSION blob (opaque to us).
    // Bounded by kSessionCacheMax with LRU eviction. Single-threaded
    // daemon, no locking needed.
    static const std::vector<uint8_t> *lookupSession(const std::string &key);
    static void storeSession(const std::string &key, std::vector<uint8_t> blob);
    static size_t sessionCacheSize();

    // Origin-failure cache.
    //
    // Three-phase to avoid skipping HTTP/3 because of a transient blip,
    // while still being strict about repeat offenders:
    //
    //   Phase 1 — *pending*. The first failure for a given target lands
    //     in a pending map (key -> first-failure timestamp). The target
    //     is NOT yet considered broken — subsequent fetches still
    //     attempt H3.
    //
    //   Phase 2 — *confirmed*. If another failure for the same target
    //     arrives at least kOriginFailureConfirmIntervalSeconds (default
    //     15 min) AFTER the pending timestamp, we have observed
    //     persistent failure across that window. The target is promoted
    //     to the confirmed-failure map, isOriginRecentlyFailed() now
    //     returns true, and subsequent fetches skip H3 and go straight
    //     to HTTP/1.1 for kOriginFailureTtlSeconds (default 72 h).
    //
    //   Phase 3 — *probation*. When a confirmed entry's 72 h TTL
    //     expires, isOriginRecentlyFailed() evicts it from the confirmed
    //     map but DOES NOT delete the key — it moves into a probation
    //     set. The daemon will now retry H3 once. If THAT retry also
    //     fails (markOriginFailed seeing the key in probation), the
    //     target is re-promoted to confirmed immediately, without
    //     waiting another 15 min. This covers the "next retry after 72 h
    //     expired" branch of the policy: persistent failure spanning
    //     the original 15-min window AND the 72 h cooling-off counts.
    //
    // markOriginSuccess() removes the target from all three sets — a
    // successful H3 fetch is strong evidence the path works and resets
    // the entire streak.
    //
    // Both maps are RAM-only (process lifetime), bounded to
    // kOriginFailureCacheMax entries each with LRU eviction. Confirmed
    // entries past the 72 h TTL are evicted on lookup. Key is the
    // 18-byte concatenation of the in6_addr (16) and the port (2, big-
    // endian) so origins on different ports are tracked independently.
    static void markOriginFailed(const sockaddr_in6 &target);
    static void markOriginSuccess(const sockaddr_in6 &target);
    static bool isOriginRecentlyFailed(const sockaddr_in6 &target);
    static size_t failureCacheSize();
    static size_t pendingFailureCacheSize();
    // Confirmed-failure TTL — the daemon must skip H3 to this target
    // for this long after confirmation. Tunable mostly for tests.
    static uint64_t kOriginFailureTtlSeconds;
    // Confirmation interval. The second failure has to land at least
    // this long after the first to promote the target from pending to
    // confirmed. Tunable mostly for tests.
    static uint64_t kOriginFailureConfirmIntervalSeconds;
    static constexpr size_t kOriginFailureCacheMax = 10000;

    // Called by the inner timer object when the timerfd expires.
    void handleExpiry();

    // Submit a GET request. Multiplexed: each call opens (or queues, if the
    // QUIC handshake hasn't completed or peer bidi-quota is exhausted) one
    // additional concurrent stream over the shared QUIC connection.
    // Returns false on hard failure (h3 setup failed). Issued requests
    // become entries in the `streams` map keyed by their QUIC stream id;
    // queued requests are flushed by handshake_completed and by
    // extend_max_local_streams_bidi.
    bool submitGet(const std::string &authority, const std::string &path);

    struct ResponseState
    {
        int status = 0;
        int64_t contentLength = -1;
        std::string contentType;
        std::string contentEncoding;
        std::string etag;
        std::string lastModified;
        std::vector<uint8_t> body;
        bool headersDone = false;
        bool streamDone = false;
        bool firstBodyByteSeen = false;
        uint64_t appErrorCode = 0;
    };

    // Per-stream response accessor; nullptr if no such stream.
    const ResponseState *getResponse(int64_t streamId) const;
    const std::unordered_map<int64_t, ResponseState> &allStreams() const { return streams; }
    size_t streamsSubmitted() const { return submittedCount; }
    size_t streamsCompleted() const;
    bool allStreamsDone() const;

    // Back-compat single-stream accessor — returns the state of the most
    // recently issued request (or an empty default if none have been
    // issued yet). The smoke driver still uses this for one-shot fetches.
    const ResponseState &response() const;

    bool handshakeCompleted() const { return handshakeDone; }
    bool isHealthy() const;

private:
    // Inner EpollObject for the per-connection timerfd. Forwards expiry
    // back to the owning Http3.
    class TimerFd : public EpollObject
    {
    public:
        TimerFd(Http3 *parent, int tfd);
        ~TimerFd() override;
        void parseEvent(const epoll_event &event) override;
    private:
        Http3 *parent;
    };

    bool drainSend();
    void armTimer(ngtcp2_tstamp expiry);
    void closeInternal();
    bool setupHttp3();          // builds nghttp3_conn + binds 3 uni streams
    bool flushPendingRequests();// drains pendingRequests against bidi quota
    bool issueRequest(const std::string &authority, const std::string &path,
                      bool &blocked);
    void recordHeader(int64_t streamId,
                      const uint8_t *name, size_t nlen,
                      const uint8_t *value, size_t vlen);

    // ngtcp2 callbacks (static thunks)
    static int cb_handshake_completed(ngtcp2_conn *conn, void *user_data);
    static void cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx);
    static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                        uint8_t *token, size_t cidlen,
                                        void *user_data);
    static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                                   int64_t stream_id, uint64_t offset,
                                   const uint8_t *data, size_t datalen,
                                   void *user_data, void *stream_user_data);
    static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                           uint64_t offset, uint64_t datalen,
                                           void *user_data, void *stream_user_data);
    static int cb_stream_close(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t app_error_code,
                               void *user_data, void *stream_user_data);
    static int cb_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                               uint64_t final_size, uint64_t app_error_code,
                               void *user_data, void *stream_user_data);
    static int cb_stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                                      uint64_t app_error_code, void *user_data,
                                      void *stream_user_data);
    static int cb_extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                                uint64_t max_streams,
                                                void *user_data);

    // nghttp3 callbacks
    static int h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                            const uint8_t *data, size_t datalen,
                            void *conn_user_data, void *stream_user_data);
    static int h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                   size_t consumed, void *conn_user_data,
                                   void *stream_user_data);
    static int h3_begin_headers(nghttp3_conn *conn, int64_t stream_id,
                                void *conn_user_data, void *stream_user_data);
    static int h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                              int32_t token, nghttp3_rcbuf *name,
                              nghttp3_rcbuf *value, uint8_t flags,
                              void *conn_user_data, void *stream_user_data);
    static int h3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                              void *conn_user_data, void *stream_user_data);
    static int h3_end_stream(nghttp3_conn *conn, int64_t stream_id,
                             void *conn_user_data, void *stream_user_data);
    static int h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                               uint64_t app_error_code, void *conn_user_data,
                               void *stream_user_data);
    static int h3_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                               uint64_t app_error_code, void *conn_user_data,
                               void *stream_user_data);
    static int h3_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                               uint64_t app_error_code, void *conn_user_data,
                               void *stream_user_data);
    // OpenSSL session callback (per-CTX, not per-conn)
    static int cb_new_session(SSL *ssl, SSL_SESSION *session);
    // ngtcp2_crypto_conn_ref helper
    static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref);

    // Once-per-process state
    static bool globalReady;
    static SSL_CTX *sslCtx;
    static ngtcp2_callbacks clientCallbacks;

    // LRU session-ticket cache. `lruOrder` keeps keys in usage order; the
    // front is the most-recently used, the back is the eviction candidate.
    // `sessionCache` maps key -> (blob, iterator into lruOrder) so both
    // lookup and touch-on-use are O(1).
    static constexpr size_t kSessionCacheMax = 10000;
    struct SessionEntry {
        std::vector<uint8_t> blob;
        std::list<std::string>::iterator lruIt;
    };
    static std::unordered_map<std::string, SessionEntry> sessionCache;
    static std::list<std::string> lruOrder;

    // Origin-failure cache state. Key as documented above; value is the
    // failure timestamp in seconds (monotonic CLOCK_MONOTONIC), paired
    // with an iterator into failLruOrder for O(1) LRU touch.
    struct FailureEntry {
        uint64_t whenSec;
        std::list<std::string>::iterator lruIt;
    };
    static std::unordered_map<std::string, FailureEntry> failureCache;
    static std::list<std::string> failLruOrder;
    // Phase 1: pending-failure map. Same key shape as failureCache;
    // value is the first-seen failure timestamp.
    static std::unordered_map<std::string, FailureEntry> pendingFailureCache;
    static std::list<std::string> pendingFailLruOrder;
    // Phase 3: probation set (key only — timestamp not load-bearing
    // beyond LRU ordering). A key here means "this origin was
    // confirmed-failed in the past 72 h window; the next failure
    // re-confirms immediately, no 15-min gate".
    static std::unordered_map<std::string, FailureEntry> probationCache;
    static std::list<std::string> probationLruOrder;
    static std::string failureKey(const sockaddr_in6 &target);
    static void lru_insert(std::unordered_map<std::string, FailureEntry> &cache,
                           std::list<std::string> &order,
                           std::string key, uint64_t whenSec, size_t cap);
    static void lru_erase(std::unordered_map<std::string, FailureEntry> &cache,
                          std::list<std::string> &order,
                          std::unordered_map<std::string, FailureEntry>::iterator it);

    // Per-instance state
    ngtcp2_conn *conn;
    SSL *ssl;
    // Conn-ref must outlive the SSL it's bound to (SSL_set_app_data).
    ngtcp2_crypto_conn_ref connRef;
    void *octx; // ngtcp2_crypto_ossl_ctx *, opaque to header consumers

    sockaddr_in6 localAddr;
    sockaddr_in6 remoteAddr;
    std::string sni;
    std::string sessionKey;

    TimerFd *timer;     // owns its timerfd; registered separately on epoll
    bool handshakeDone;

    // nghttp3 layer
    nghttp3_conn *h3conn;
    int64_t controlStreamId;
    int64_t qencStreamId;
    int64_t qdecStreamId;
    int64_t lastRequestStreamId; // most recent issued stream id (for
                                  // back-compat `response()` accessor)

    // Pending request bookkeeping. submitGet calls made before the
    // handshake completes, or once bidi quota is exhausted, end up here.
    // Drained FIFO on handshake_completed and on
    // extend_max_local_streams_bidi.
    struct PendingReq { std::string authority; std::string path; };
    std::deque<PendingReq> pendingRequests;
    size_t submittedCount;
    bool connFailed;             // hard QUIC/UDP failure flag; flips to
                                  // true on close paths so callers can
                                  // tell "no more streams will progress"
                                  // apart from "still healthy, just idle"

    // Per-stream response state; key is the QUIC bidi stream id.
    std::unordered_map<int64_t, ResponseState> streams;
};

#endif // HTTP3_H
