#ifndef HTTP3PROBE_H
#define HTTP3PROBE_H

#include "EpollObject.hpp"
#include "Http3.hpp"

#include <chrono>
#include <string>
#include <unordered_set>

// Telemetry-only HTTP/3 side-channel.
//
// When the daemon is started with --http3-probe, every HTTPS backend fetch
// causes one Http3Probe to be launched in parallel with the existing HTTP/1.1
// leg. The probe connects to the same origin over QUIC, GETs the same path,
// and logs handshake-completed time, first-body-byte time, response status,
// content-length, and body sha256 — then deletes itself.
//
// The probe NEVER:
//   - delivers bytes to a client,
//   - writes to the cache,
//   - cancels or alters the HTTP/1.1 leg.
//
// It exists only to gather data on whether H3 actually wins races on the
// VPN-constrained backend paths before we wire the race-cancel commit.
//
// Lifecycle: launched probes are owned by a static `active` set. A shared
// reaper timerfd (registered as its own EpollObject) ticks once per second,
// walks the set, logs+deletes any probe whose Http3 has hit streamDone or
// whose deadline has passed.
class Http3Probe
{
public:
    static bool enabled;
    static void launch(const sockaddr_in6 &remote, const std::string &authority,
                       const std::string &path);
    static void reapNow();
    static void shutdown();   // process-exit cleanup

    Http3Probe(const sockaddr_in6 &remote, const std::string &authority,
               const std::string &path);
    ~Http3Probe();

    bool isDone() const;

private:
    void log(const char *reason);

    Http3 *h3;
    std::string authority;
    std::string path;
    sockaddr_in6 remote;
    std::chrono::steady_clock::time_point launchedAt;
    std::chrono::steady_clock::time_point deadline;
    bool firstByteLogged;
    std::chrono::steady_clock::time_point firstByteAt;
    std::chrono::steady_clock::time_point handshakeAt;
    bool handshakeLogged;

    static std::unordered_set<Http3Probe *> active;

    // Reaper: a tiny EpollObject around a timerfd that calls reapNow() once
    // per second. Created lazily on first launch(); torn down by shutdown().
    class Reaper : public EpollObject
    {
    public:
        Reaper();
        ~Reaper() override;
        void parseEvent(const epoll_event &event) override;
    };
    static Reaper *reaper;
};

#endif // HTTP3PROBE_H
