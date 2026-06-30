// Standalone smoke driver for confiacdn's HTTP/3 backend leg.
//
// Builds against Http3.o + EpollObject.o; no dependency on the rest of
// the daemon. Two modes:
//   - sequential (default): N GETs in sequence, each on its own Http3
//     instance. Same process so the RAM-only session cache is observable
//     across fetches.
//   - multiplexed (--mux): N GETs concurrently over one Http3 instance,
//     exercising QUIC stream multiplexing.
//
// Per-fetch summary line on stdout:
//   STATUS=<int> CT=<content-type> CE=<content-encoding> CL=<int>
//   BYTES=<int> SHA256=<hex> RESUMED=<0|1> CACHE_SIZE=<int> MUX=<0|1>
//   STREAM=<int>
//
// usage:
//   h3_smoke <ipv6> <port> <authority> <out-prefix> [--mux] <path1> [<path2> ...]

#include "../Http3.hpp"
#include "../EpollObject.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <algorithm>

namespace {

std::string sha256_hex(const std::vector<uint8_t> &b)
{
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256(b.data(), b.size(), out);
    static const char *hex = "0123456789abcdef";
    std::string r;
    r.reserve(SHA256_DIGEST_LENGTH * 2);
    for(unsigned char c : out)
    {
        r.push_back(hex[c >> 4]);
        r.push_back(hex[c & 0x0f]);
    }
    return r;
}

void pump_until(Http3 &h3, std::chrono::steady_clock::time_point deadline,
                bool (*done)(const Http3 &))
{
    epoll_event events[16];
    while(std::chrono::steady_clock::now() < deadline)
    {
        int waitMs = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count());
        if(waitMs <= 0) break;
        int n = ::epoll_wait(EpollObject::epollfd, events, 16, waitMs);
        if(n < 0) { if(errno == EINTR) continue; break; }
        for(int i = 0; i < n; ++i)
        {
            EpollObject *o = static_cast<EpollObject *>(events[i].data.ptr);
            o->parseEvent(events[i]);
        }
        if(done(h3)) return;
    }
}

void write_summary(const Http3::ResponseState &r, int64_t streamId,
                   const std::string &outFile, bool hadCachedSession,
                   bool mux)
{
    FILE *f = std::fopen(outFile.c_str(), "wb");
    if(f != nullptr)
    {
        if(!r.body.empty())
            std::fwrite(r.body.data(), 1, r.body.size(), f);
        std::fclose(f);
    }
    std::printf(
        "STATUS=%d CT=%s CE=%s CL=%lld BYTES=%zu SHA256=%s RESUMED=%d "
        "CACHE_SIZE=%zu MUX=%d STREAM=%lld\n",
        r.status,
        r.contentType.c_str(),
        r.contentEncoding.c_str(),
        static_cast<long long>(r.contentLength),
        r.body.size(),
        sha256_hex(r.body).c_str(),
        hadCachedSession ? 1 : 0,
        Http3::sessionCacheSize(),
        mux ? 1 : 0,
        static_cast<long long>(streamId));
}

bool fetch_one(const sockaddr_in6 &remote, const std::string &authority,
               const std::string &sessionKey, const std::string &path,
               const std::string &outFile, int timeoutMs)
{
    bool hadCachedSession = (Http3::lookupSession(sessionKey) != nullptr);
    Http3 h3;
    if(!h3.start(remote, authority, sessionKey))
    {
        std::fprintf(stderr, "Http3::start failed\n");
        return false;
    }
    if(!h3.submitGet(authority, path))
    {
        std::fprintf(stderr, "Http3::submitGet failed\n");
        return false;
    }
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs);
    pump_until(h3, deadline,
               [](const Http3 &x){ return x.response().streamDone; });

    if(!h3.response().streamDone)
    {
        std::fprintf(stderr, "timeout after %d ms\n", timeoutMs);
        return false;
    }

    // Post-stream drain so a NewSessionTicket frame has a chance to land
    // before teardown.
    pump_until(h3, std::chrono::steady_clock::now() +
                   std::chrono::milliseconds(500),
               [](const Http3 &){ return false; });

    int64_t sid = -1;
    if(!h3.allStreams().empty())
        sid = h3.allStreams().begin()->first;
    write_summary(h3.response(), sid, outFile, hadCachedSession, false);
    std::fflush(stdout);
    return true;
}

bool fetch_mux(const sockaddr_in6 &remote, const std::string &authority,
               const std::string &sessionKey,
               const std::vector<std::string> &paths,
               const std::string &outPrefix, int timeoutMs)
{
    bool hadCachedSession = (Http3::lookupSession(sessionKey) != nullptr);
    Http3 h3;
    if(!h3.start(remote, authority, sessionKey))
    {
        std::fprintf(stderr, "Http3::start failed\n");
        return false;
    }
    for(const std::string &p : paths)
    {
        if(!h3.submitGet(authority, p))
        {
            std::fprintf(stderr, "Http3::submitGet failed for %s\n", p.c_str());
            return false;
        }
    }
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs);
    pump_until(h3, deadline,
               [](const Http3 &x){ return x.allStreamsDone(); });

    if(!h3.allStreamsDone())
    {
        std::fprintf(stderr,
            "mux timeout: completed %zu/%zu\n",
            h3.streamsCompleted(), h3.streamsSubmitted());
        return false;
    }

    // Emit one line per submitted stream, in stream-id order so the harness
    // can correlate output position to the input path order. Bidi client
    // stream ids are 0, 4, 8, ... so sorted ascending matches submit order.
    std::vector<int64_t> ids;
    ids.reserve(h3.allStreams().size());
    for(const auto &kv : h3.allStreams()) ids.push_back(kv.first);
    std::sort(ids.begin(), ids.end());
    for(size_t i = 0; i < ids.size(); ++i)
    {
        const Http3::ResponseState *r = h3.getResponse(ids[i]);
        if(r == nullptr) continue;
        std::string outFile = outPrefix + "." + std::to_string(i);
        write_summary(*r, ids[i], outFile, hadCachedSession, true);
    }
    std::fflush(stdout);
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    if(argc < 6)
    {
        std::fprintf(stderr,
            "usage: %s <ipv6> <port> <authority> <out-prefix> "
            "[--mux] <path1> [<path2> ...]\n", argv[0]);
        return 2;
    }
    const char *ipv6 = argv[1];
    int port = std::atoi(argv[2]);
    std::string authority = argv[3];
    std::string outPrefix = argv[4];

    int firstPath = 5;
    bool mux = false;
    if(firstPath < argc && std::string(argv[firstPath]) == "--mux")
    {
        mux = true;
        ++firstPath;
    }
    if(firstPath >= argc)
    {
        std::fprintf(stderr, "no paths given\n");
        return 2;
    }

    sockaddr_in6 remote{};
    remote.sin6_family = AF_INET6;
    remote.sin6_port = htons(static_cast<uint16_t>(port));
    if(::inet_pton(AF_INET6, ipv6, &remote.sin6_addr) != 1)
    {
        std::fprintf(stderr, "inet_pton failed for %s\n", ipv6);
        return 2;
    }

    EpollObject::epollfd = ::epoll_create1(EPOLL_CLOEXEC);
    if(EpollObject::epollfd == -1)
    {
        std::perror("epoll_create1");
        return 2;
    }

    std::string sessionKey = authority + ":" + std::to_string(port);
    const int timeoutMs = 30000;

    if(mux)
    {
        std::vector<std::string> paths;
        for(int i = firstPath; i < argc; ++i) paths.emplace_back(argv[i]);
        return fetch_mux(remote, authority, sessionKey, paths, outPrefix,
                         timeoutMs) ? 0 : 1;
    }
    for(int i = firstPath; i < argc; ++i)
    {
        std::string outFile = outPrefix + "." + std::to_string(i - firstPath);
        if(!fetch_one(remote, authority, sessionKey, argv[i], outFile,
                      timeoutMs))
            return 1;
    }
    return 0;
}
