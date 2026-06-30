#include "Http3Probe.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <openssl/sha.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

bool Http3Probe::enabled = false;
std::unordered_set<Http3Probe *> Http3Probe::active;
Http3Probe::Reaper *Http3Probe::reaper = nullptr;

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
std::string ipv6_str(const sockaddr_in6 &a)
{
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &a.sin6_addr, buf, sizeof(buf));
    return buf;
}
} // namespace

// ===== Reaper =====

Http3Probe::Reaper::Reaper() :
    EpollObject(-1, Kind_Http3)
{
    fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if(fd == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3Probe::Reaper timerfd_create failed" << std::endl;
        return;
    }
    itimerspec its{};
    its.it_value.tv_sec    = 1;
    its.it_interval.tv_sec = 1;
    ::timerfd_settime(fd, 0, &its, nullptr);

    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = this;
    if(::epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3Probe::Reaper epoll_ctl failed" << std::endl;
        ::close(fd);
        fd = -1;
    }
}

Http3Probe::Reaper::~Reaper()
{
    if(fd != -1)
    {
        ::epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, nullptr);
        ::close(fd);
        fd = -1;
    }
}

void Http3Probe::Reaper::parseEvent(const epoll_event &event)
{
    (void)event;
    uint64_t drain;
    while(::read(fd, &drain, sizeof(drain)) > 0) {}
    Http3Probe::reapNow();
}

// ===== Http3Probe =====

Http3Probe::Http3Probe(const sockaddr_in6 &remote_,
                       const std::string &authority_,
                       const std::string &path_) :
    h3(nullptr),
    authority(authority_),
    path(path_),
    remote(remote_),
    launchedAt(std::chrono::steady_clock::now()),
    deadline(launchedAt + std::chrono::seconds(10)),
    firstByteLogged(false),
    handshakeLogged(false)
{
}

Http3Probe::~Http3Probe()
{
    if(h3 != nullptr)
    {
        delete h3;
        h3 = nullptr;
    }
}

void Http3Probe::launch(const sockaddr_in6 &remote,
                        const std::string &authority,
                        const std::string &path)
{
    if(!enabled) return;
    if(reaper == nullptr) reaper = new Reaper();
    Http3Probe *p = new Http3Probe(remote, authority, path);
    p->h3 = new Http3();
    std::string key = authority + ":" + std::to_string(ntohs(remote.sin6_port));
    if(!p->h3->start(remote, authority, key))
    {
        p->log("start-failed");
        // Treat a hard start-failure as an H3 failure for this origin —
        // the local code couldn't even open a UDP socket / set up TLS.
        // Subsequent fetches inform the failure cache so policy
        // decisions in future commits can skip H3 fast.
        Http3::markOriginFailed(remote);
        delete p;
        return;
    }
    if(!p->h3->submitGet(authority, path))
    {
        p->log("submit-failed");
        Http3::markOriginFailed(remote);
        delete p;
        return;
    }
    active.insert(p);
}

bool Http3Probe::isDone() const
{
    if(h3 == nullptr) return true;
    if(h3->response().streamDone) return true;
    if(std::chrono::steady_clock::now() >= deadline) return true;
    return false;
}

void Http3Probe::reapNow()
{
    if(active.empty()) return;
    auto now = std::chrono::steady_clock::now();
    std::vector<Http3Probe *> doneList;
    for(Http3Probe *p : active)
    {
        // Capture handshake / first-byte transition timestamps the moment
        // we observe them, so the timing data we log is bounded by the
        // 1s reaper jitter rather than by the wait-for-stream-done.
        if(!p->handshakeLogged && p->h3 != nullptr &&
           p->h3->handshakeCompleted())
        {
            p->handshakeAt = now;
            p->handshakeLogged = true;
        }
        if(!p->firstByteLogged && p->h3 != nullptr &&
           p->h3->response().firstBodyByteSeen)
        {
            p->firstByteAt = now;
            p->firstByteLogged = true;
        }
        if(p->isDone()) doneList.push_back(p);
    }
    for(Http3Probe *p : doneList)
    {
        active.erase(p);
        const bool streamDone = p->h3 != nullptr && p->h3->response().streamDone;
        const int  status     = p->h3 != nullptr ? p->h3->response().status : 0;
        p->log(streamDone ? "stream-done" : "deadline");
        // Feed the origin-failure cache. Treat a non-2xx/3xx response as
        // a failure too — a 5xx within bounded time is bad telemetry for
        // H3 even if the QUIC connection itself was healthy. 4xx are
        // legitimate origin responses (404/403/410 etc.) so they count
        // as success from a transport-health standpoint.
        const bool transport_ok =
            streamDone && status > 0 && status < 500;
        if(transport_ok)
            Http3::markOriginSuccess(p->remote);
        else
            Http3::markOriginFailed(p->remote);
        delete p;
    }
}

void Http3Probe::shutdown()
{
    for(Http3Probe *p : active)
    {
        p->log("shutdown");
        delete p;
    }
    active.clear();
    if(reaper != nullptr)
    {
        delete reaper;
        reaper = nullptr;
    }
}

void Http3Probe::log(const char *reason)
{
    auto ms = [&](std::chrono::steady_clock::time_point t) -> long {
        if(t.time_since_epoch().count() == 0) return -1;
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            t - launchedAt).count();
    };
    int status = 0;
    long long cl = -1;
    size_t bytes = 0;
    std::string sha;
    std::string ct;
    if(h3 != nullptr)
    {
        const auto &r = h3->response();
        status = r.status;
        cl     = r.contentLength;
        bytes  = r.body.size();
        ct     = r.contentType;
        sha    = sha256_hex(r.body);
    }
    std::cerr << "[http3-probe] reason=" << reason
              << " remote=" << ipv6_str(remote)
              << " port=" << ntohs(remote.sin6_port)
              << " authority=" << authority
              << " path=" << path
              << " status=" << status
              << " ct=" << ct
              << " cl=" << cl
              << " bytes=" << bytes
              << " handshake_ms=" << ms(handshakeAt)
              << " first_body_ms=" << ms(firstByteAt)
              << " sha=" << sha
              << " session_cache_size=" << Http3::sessionCacheSize()
              << " failure_pending=" << Http3::pendingFailureCacheSize()
              << " failure_confirmed=" << Http3::failureCacheSize()
              << std::endl;
}
