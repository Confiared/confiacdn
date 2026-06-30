#include "Http3.hpp"

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <cstdlib>

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

// Static-member storage
bool Http3::globalReady = false;
SSL_CTX *Http3::sslCtx = nullptr;
ngtcp2_callbacks Http3::clientCallbacks;
std::unordered_map<std::string, Http3::SessionEntry> Http3::sessionCache;
std::list<std::string> Http3::lruOrder;
std::unordered_map<std::string, Http3::FailureEntry> Http3::failureCache;
std::list<std::string> Http3::failLruOrder;
std::unordered_map<std::string, Http3::FailureEntry> Http3::pendingFailureCache;
std::list<std::string> Http3::pendingFailLruOrder;
std::unordered_map<std::string, Http3::FailureEntry> Http3::probationCache;
std::list<std::string> Http3::probationLruOrder;
uint64_t Http3::kOriginFailureTtlSeconds = 72 * 3600;
uint64_t Http3::kOriginFailureConfirmIntervalSeconds = 15 * 60;

namespace {

// Monotonic timestamp in ngtcp2's expected unit (nanoseconds since some
// fixed epoch). We use steady_clock here — ngtcp2 only requires the values
// to be monotonically increasing and unit-consistent across all API calls.
ngtcp2_tstamp now_ns()
{
    auto t = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t).count());
}

bool fill_cid(ngtcp2_cid &cid, size_t len)
{
    cid.datalen = len;
    if(RAND_bytes(cid.data, static_cast<int>(len)) != 1)
        return false;
    return true;
}

} // namespace

// ===== TimerFd inner class =====

Http3::TimerFd::TimerFd(Http3 *parent_, int tfd) :
    EpollObject(tfd, Kind_Http3),
    parent(parent_)
{
}

Http3::TimerFd::~TimerFd()
{
    if(fd != -1)
    {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, nullptr);
        ::close(fd);
        fd = -1;
    }
}

void Http3::TimerFd::parseEvent(const epoll_event &event)
{
    (void)event;
    uint64_t drain;
    while(::read(fd, &drain, sizeof(drain)) > 0) {}
    parent->handleExpiry();
}

// ===== Static callbacks =====

ngtcp2_conn *Http3::get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return static_cast<Http3 *>(ref->user_data)->conn;
}

int Http3::cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    Http3 *self = static_cast<Http3 *>(user_data);
    self->handshakeDone = true;
    #ifdef DEBUGHTTPS
    std::cerr << __FILE__ << ":" << __LINE__
              << " Http3 handshake completed " << (void *)self
              << " key=" << self->sessionKey << std::endl;
    #endif
    if(!self->setupHttp3()) return NGTCP2_ERR_CALLBACK_FAILURE;
    if(!self->flushPendingRequests())
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

void Http3::cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    // RAND_bytes always succeeds with a seeded OpenSSL; we initialise
    // OpenSSL in main via SSL_library_init / OPENSSL_init_ssl.
    // RAND_bytes can fail only if OpenSSL's CSPRNG isn't seeded — never in
    // practice on Linux with /dev/urandom available. We don't carry an
    // additional fallback; this would mask a real misconfiguration.
    (void)RAND_bytes(dest, static_cast<int>(destlen));
}

int Http3::cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
    (void)conn;
    (void)user_data;
    if(RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    if(RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

int Http3::cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data)
{
    (void)offset; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(user_data);
    if(self->h3conn == nullptr) return 0;
    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
    nghttp3_ssize n = nghttp3_conn_read_stream(self->h3conn, stream_id,
                                               data, datalen, fin);
    if(n < 0)
    {
        #ifdef DEBUGHTTPS
        std::cerr << __FILE__ << ":" << __LINE__
                  << " nghttp3_conn_read_stream: "
                  << nghttp3_strerror(static_cast<int>(n)) << std::endl;
        #endif
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id,
                                         static_cast<uint64_t>(n));
    ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(n));
    return 0;
}

int Http3::cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data)
{
    (void)conn; (void)offset; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(user_data);
    if(self->h3conn == nullptr) return 0;
    if(nghttp3_conn_add_ack_offset(self->h3conn, stream_id, datalen) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

int Http3::cb_stream_close(ngtcp2_conn *conn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(user_data);
    if(self->h3conn == nullptr) return 0;
    if(!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
        app_error_code = NGHTTP3_H3_NO_ERROR;
    int rv = nghttp3_conn_close_stream(self->h3conn, stream_id, app_error_code);
    if(rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

int Http3::cb_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
    (void)conn; (void)final_size; (void)app_error_code; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(user_data);
    if(self->h3conn == nullptr) return 0;
    if(nghttp3_conn_shutdown_stream_read(self->h3conn, stream_id) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

int Http3::cb_stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id,
                                  uint64_t app_error_code, void *user_data,
                                  void *stream_user_data)
{
    (void)conn; (void)app_error_code; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(user_data);
    if(self->h3conn == nullptr) return 0;
    if(nghttp3_conn_shutdown_stream_read(self->h3conn, stream_id) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

int Http3::cb_extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                            uint64_t max_streams,
                                            void *user_data)
{
    (void)conn; (void)max_streams;
    Http3 *self = static_cast<Http3 *>(user_data);
    if(self->h3conn == nullptr) return 0;
    if(!self->flushPendingRequests())
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

int Http3::cb_new_session(SSL *ssl, SSL_SESSION *session)
{
    // SSL_CTX_sess_set_new_cb: takes ownership of the SSL_SESSION reference
    // when returning 1; we serialize + store, then return 0 so OpenSSL
    // frees the session itself (we keep only the i2d blob).
    void *app = SSL_get_app_data(ssl);
    if(app == nullptr) return 0;
    ngtcp2_crypto_conn_ref *ref = static_cast<ngtcp2_crypto_conn_ref *>(app);
    Http3 *self = static_cast<Http3 *>(ref->user_data);
    if(self == nullptr || self->sessionKey.empty()) return 0;

    int len = i2d_SSL_SESSION(session, nullptr);
    if(len <= 0) return 0;
    std::vector<uint8_t> blob(static_cast<size_t>(len));
    unsigned char *p = blob.data();
    if(i2d_SSL_SESSION(session, &p) <= 0) return 0;

    Http3::storeSession(self->sessionKey, std::move(blob));
    #ifdef DEBUGHTTPS
    std::cerr << __FILE__ << ":" << __LINE__
              << " Http3 session ticket cached key=" << self->sessionKey
              << " bytes=" << len
              << " cacheSize=" << Http3::sessionCacheSize() << std::endl;
    #endif
    return 0;
}

// ===== globalInit =====

bool Http3::globalInit()
{
    if(globalReady) return true;

    if(ngtcp2_crypto_ossl_init() != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " ngtcp2_crypto_ossl_init failed" << std::endl;
        return false;
    }

    sslCtx = SSL_CTX_new(TLS_client_method());
    if(sslCtx == nullptr)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " SSL_CTX_new failed" << std::endl;
        return false;
    }
    SSL_CTX_set_min_proto_version(sslCtx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sslCtx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(sslCtx);

    #ifdef BACKEND_ALLOW_SELF_SIGNED_TLS
    // Test-build only: harness uses a self-signed origin. Never set in
    // production builds. Guarded the same way as the TCP-HTTPS path.
    SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, nullptr);
    #else
    SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER, nullptr);
    #endif

    // RAM session-ticket capture. We disable the internal session cache
    // (we are the cache) but keep ticket support enabled.
    SSL_CTX_set_session_cache_mode(sslCtx,
        SSL_SESS_CACHE_CLIENT |
        SSL_SESS_CACHE_NO_INTERNAL_STORE |
        SSL_SESS_CACHE_NO_AUTO_CLEAR);
    SSL_CTX_sess_set_new_cb(sslCtx, &Http3::cb_new_session);

    // Build the client callbacks once. The crypto helpers from
    // ngtcp2_crypto handle every TLS-driven callback.
    std::memset(&clientCallbacks, 0, sizeof(clientCallbacks));
    clientCallbacks.client_initial          = ngtcp2_crypto_client_initial_cb;
    clientCallbacks.recv_crypto_data        = ngtcp2_crypto_recv_crypto_data_cb;
    clientCallbacks.encrypt                 = ngtcp2_crypto_encrypt_cb;
    clientCallbacks.decrypt                 = ngtcp2_crypto_decrypt_cb;
    clientCallbacks.hp_mask                 = ngtcp2_crypto_hp_mask_cb;
    clientCallbacks.recv_retry              = ngtcp2_crypto_recv_retry_cb;
    clientCallbacks.update_key              = ngtcp2_crypto_update_key_cb;
    clientCallbacks.delete_crypto_aead_ctx  = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    clientCallbacks.delete_crypto_cipher_ctx= ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    clientCallbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    clientCallbacks.version_negotiation     = ngtcp2_crypto_version_negotiation_cb;
    clientCallbacks.handshake_completed     = &Http3::cb_handshake_completed;
    clientCallbacks.rand                    = &Http3::cb_rand;
    clientCallbacks.get_new_connection_id   = &Http3::cb_get_new_connection_id;
    clientCallbacks.recv_stream_data        = &Http3::cb_recv_stream_data;
    clientCallbacks.acked_stream_data_offset= &Http3::cb_acked_stream_data_offset;
    clientCallbacks.stream_close            = &Http3::cb_stream_close;
    clientCallbacks.stream_reset            = &Http3::cb_stream_reset;
    clientCallbacks.stream_stop_sending     = &Http3::cb_stream_stop_sending;
    clientCallbacks.extend_max_local_streams_bidi
                                            = &Http3::cb_extend_max_local_streams_bidi;

    globalReady = true;
    return true;
}

// ===== ctor/dtor =====

Http3::Http3() :
    EpollObject(-1, Kind_Http3),
    conn(nullptr),
    ssl(nullptr),
    octx(nullptr),
    timer(nullptr),
    handshakeDone(false),
    h3conn(nullptr),
    controlStreamId(-1),
    qencStreamId(-1),
    qdecStreamId(-1),
    lastRequestStreamId(-1),
    submittedCount(0),
    connFailed(false)
{
    std::memset(&connRef, 0, sizeof(connRef));
    std::memset(&localAddr, 0, sizeof(localAddr));
    std::memset(&remoteAddr, 0, sizeof(remoteAddr));
}

Http3::~Http3()
{
    closeInternal();
}

void Http3::closeInternal()
{
    connFailed = true;
    // Mark any still-open streams as done so allStreamsDone() reports
    // truthfully and callers polling on it can move on. We don't fabricate
    // success — the body / headersDone flags stay as captured up to the
    // point of failure.
    for(auto &kv : streams)
        kv.second.streamDone = true;
    if(h3conn != nullptr)
    {
        nghttp3_conn_del(h3conn);
        h3conn = nullptr;
    }
    if(timer != nullptr)
    {
        delete timer;
        timer = nullptr;
    }
    if(ssl != nullptr)
    {
        // Per ngtcp2_crypto_ossl docs: clear app_data before SSL_free if
        // the conn isn't guaranteed to outlive the SSL.
        SSL_set_app_data(ssl, nullptr);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if(octx != nullptr)
    {
        ngtcp2_crypto_ossl_ctx_del(static_cast<ngtcp2_crypto_ossl_ctx *>(octx));
        octx = nullptr;
    }
    if(conn != nullptr)
    {
        ngtcp2_conn_del(conn);
        conn = nullptr;
    }
    if(fd != -1)
    {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, nullptr);
        ::close(fd);
        fd = -1;
    }
}

// ===== start =====

bool Http3::start(const sockaddr_in6 &remote, const std::string &sni_,
                  const std::string &sessionKey_)
{
    if(!globalInit()) return false;
    remoteAddr = remote;
    sni = sni_;
    sessionKey = sessionKey_;

    // UDP socket, IPv6, ephemeral local bind. We connect() so the kernel
    // pins the 4-tuple and surfaces ICMP errors via EPOLLERR.
    fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if(fd == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3 socket: " << strerror(errno) << std::endl;
        return false;
    }
    // Bind to in6addr_any:0 explicitly so getsockname returns a usable
    // local addr after connect().
    sockaddr_in6 bind_any{};
    bind_any.sin6_family = AF_INET6;
    if(::bind(fd, reinterpret_cast<sockaddr *>(&bind_any), sizeof(bind_any)) == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3 bind: " << strerror(errno) << std::endl;
        closeInternal();
        return false;
    }
    if(::connect(fd, reinterpret_cast<const sockaddr *>(&remoteAddr),
                 sizeof(remoteAddr)) == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3 connect: " << strerror(errno) << std::endl;
        closeInternal();
        return false;
    }
    socklen_t llen = sizeof(localAddr);
    if(::getsockname(fd, reinterpret_cast<sockaddr *>(&localAddr), &llen) == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3 getsockname: " << strerror(errno) << std::endl;
        closeInternal();
        return false;
    }

    // Register UDP socket with epoll. Edge-triggered, matching the rest
    // of the daemon's epoll discipline.
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.ptr = this;
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3 epoll_ctl: " << strerror(errno) << std::endl;
        closeInternal();
        return false;
    }

    // Connection IDs (client-chosen).
    ngtcp2_cid scid{}, dcid{};
    if(!fill_cid(scid, NGTCP2_MAX_CIDLEN) ||
       !fill_cid(dcid, NGTCP2_MIN_INITIAL_DCIDLEN))
    {
        closeInternal();
        return false;
    }

    ngtcp2_path path;
    path.local.addr    = reinterpret_cast<ngtcp2_sockaddr *>(&localAddr);
    path.local.addrlen = sizeof(localAddr);
    path.remote.addr   = reinterpret_cast<ngtcp2_sockaddr *>(&remoteAddr);
    path.remote.addrlen= sizeof(remoteAddr);
    path.user_data     = nullptr;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.max_tx_udp_payload_size = 1200;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    // Receive credits we offer to peer. HTTP/3 server needs 3 uni
    // streams (control + qpack enc + qpack dec).
    params.initial_max_data                   = 16 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 1 * 1024 * 1024;
    params.initial_max_stream_data_uni        = 256 * 1024;
    params.initial_max_streams_uni            = 3;
    params.initial_max_streams_bidi           = 0;
    params.max_idle_timeout                   = 30 * NGTCP2_SECONDS;

    int rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &path,
                                    NGTCP2_PROTO_VER_V1,
                                    &clientCallbacks, &settings, &params,
                                    nullptr, this);
    if(rv != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " ngtcp2_conn_client_new: " << ngtcp2_strerror(rv)
                  << std::endl;
        closeInternal();
        return false;
    }

    // SSL bring-up
    ssl = SSL_new(sslCtx);
    if(ssl == nullptr)
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " SSL_new failed" << std::endl;
        closeInternal();
        return false;
    }
    connRef.get_conn = &Http3::get_conn;
    connRef.user_data = this;
    SSL_set_app_data(ssl, &connRef);
    SSL_set_connect_state(ssl);
    if(!sni.empty())
    {
        SSL_set_tlsext_host_name(ssl, sni.c_str());
        // SSL_set1_host enables certificate hostname verification when
        // SSL_VERIFY_PEER is set; harmless in the self-signed test build.
        SSL_set1_host(ssl, sni.c_str());
    }
    // ALPN: "h3" only — this whole leg is HTTP/3.
    static const unsigned char alpn[] = { 2, 'h', '3' };
    SSL_set_alpn_protos(ssl, alpn, sizeof(alpn));

    if(ngtcp2_crypto_ossl_ctx_new(reinterpret_cast<ngtcp2_crypto_ossl_ctx **>(&octx),
                                  ssl) != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " ngtcp2_crypto_ossl_ctx_new failed" << std::endl;
        closeInternal();
        return false;
    }
    if(ngtcp2_crypto_ossl_configure_client_session(ssl) != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " ngtcp2_crypto_ossl_configure_client_session failed"
                  << std::endl;
        closeInternal();
        return false;
    }
    ngtcp2_conn_set_tls_native_handle(conn, octx);

    // 0-RTT path: replay the cached session ticket if we have one.
    if(const std::vector<uint8_t> *blob = Http3::lookupSession(sessionKey))
    {
        const unsigned char *p = blob->data();
        SSL_SESSION *sess = d2i_SSL_SESSION(nullptr, &p, static_cast<long>(blob->size()));
        if(sess != nullptr)
        {
            SSL_set_session(ssl, sess);
            SSL_SESSION_free(sess);
        }
    }

    // Per-connection timerfd. Registered separately on epoll so its
    // EPOLLIN dispatches to our inner TimerFd.
    int tfd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if(tfd == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " timerfd_create: " << strerror(errno) << std::endl;
        closeInternal();
        return false;
    }
    timer = new TimerFd(this, tfd);
    epoll_event tev{};
    tev.events = EPOLLIN | EPOLLET;
    tev.data.ptr = timer;
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, tfd, &tev) == -1)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " timerfd epoll_ctl: " << strerror(errno) << std::endl;
        closeInternal();
        return false;
    }

    // Kick off: ngtcp2 will produce Initial packets via writev_stream.
    if(!drainSend())
    {
        closeInternal();
        return false;
    }
    armTimer(ngtcp2_conn_get_expiry(conn));
    return true;
}

// ===== I/O =====

void Http3::parseEvent(const epoll_event &event)
{
    if(event.events & (EPOLLERR | EPOLLHUP))
    {
        // Surface ICMP unreachable / peer-down as a soft close.
        int err = 0;
        socklen_t sl = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl);
        #ifdef DEBUGHTTPS
        std::cerr << __FILE__ << ":" << __LINE__
                  << " Http3 socket err=" << err << " ("
                  << strerror(err) << ")" << std::endl;
        #endif
        closeInternal();
        return;
    }

    if(event.events & EPOLLIN)
    {
        uint8_t buf[2048];
        for(;;)
        {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if(n < 0)
            {
                if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                #ifdef DEBUGHTTPS
                std::cerr << __FILE__ << ":" << __LINE__
                          << " Http3 recv: " << strerror(errno) << std::endl;
                #endif
                closeInternal();
                return;
            }
            if(n == 0) break;

            ngtcp2_path path;
            path.local.addr    = reinterpret_cast<ngtcp2_sockaddr *>(&localAddr);
            path.local.addrlen = sizeof(localAddr);
            path.remote.addr   = reinterpret_cast<ngtcp2_sockaddr *>(&remoteAddr);
            path.remote.addrlen= sizeof(remoteAddr);
            path.user_data     = nullptr;
            ngtcp2_pkt_info pi{};
            int rv = ngtcp2_conn_read_pkt(conn, &path, &pi, buf,
                                          static_cast<size_t>(n), now_ns());
            if(rv != 0)
            {
                #ifdef DEBUGHTTPS
                std::cerr << __FILE__ << ":" << __LINE__
                          << " ngtcp2_conn_read_pkt: " << ngtcp2_strerror(rv)
                          << std::endl;
                #endif
                closeInternal();
                return;
            }
        }
    }

    if(!drainSend())
        return;
    if(conn != nullptr)
        armTimer(ngtcp2_conn_get_expiry(conn));
}

bool Http3::drainSend()
{
    if(conn == nullptr) return false;
    uint8_t out[1452];
    for(;;)
    {
        int64_t sid = -1;
        int fin = 0;
        nghttp3_vec vec[16];
        nghttp3_ssize sveccnt = 0;
        if(h3conn != nullptr && ngtcp2_conn_get_max_data_left(conn) > 0)
        {
            sveccnt = nghttp3_conn_writev_stream(h3conn, &sid, &fin,
                                                 vec, sizeof(vec) /
                                                 sizeof(vec[0]));
            if(sveccnt < 0)
            {
                #ifdef DEBUGHTTPS
                std::cerr << __FILE__ << ":" << __LINE__
                          << " nghttp3_conn_writev_stream: "
                          << nghttp3_strerror(static_cast<int>(sveccnt))
                          << std::endl;
                #endif
                closeInternal();
                return false;
            }
        }
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if(fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi{};
        ngtcp2_ssize ndatalen = 0;
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(
            conn, &ps.path, &pi, out, sizeof(out),
            &ndatalen, flags, sid,
            reinterpret_cast<const ngtcp2_vec *>(vec),
            sveccnt > 0 ? static_cast<size_t>(sveccnt) : 0,
            now_ns());

        if(n < 0)
        {
            switch(n)
            {
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                    if(sid != -1)
                        nghttp3_conn_block_stream(h3conn, sid);
                    continue;
                case NGTCP2_ERR_STREAM_SHUT_WR:
                    if(sid != -1)
                        nghttp3_conn_shutdown_stream_write(h3conn, sid);
                    continue;
                case NGTCP2_ERR_WRITE_MORE:
                    if(sid != -1 && ndatalen >= 0)
                        nghttp3_conn_add_write_offset(h3conn, sid,
                            static_cast<size_t>(ndatalen));
                    continue;
                default:
                    #ifdef DEBUGHTTPS
                    std::cerr << __FILE__ << ":" << __LINE__
                              << " writev_stream: "
                              << ngtcp2_strerror(static_cast<int>(n))
                              << std::endl;
                    #endif
                    closeInternal();
                    return false;
            }
        }
        if(ndatalen >= 0 && sid != -1)
            nghttp3_conn_add_write_offset(h3conn, sid,
                static_cast<size_t>(ndatalen));

        if(n == 0) break;
        ssize_t s = ::send(fd, out, static_cast<size_t>(n), 0);
        if(s < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            #ifdef DEBUGHTTPS
            std::cerr << __FILE__ << ":" << __LINE__
                      << " Http3 send: " << strerror(errno) << std::endl;
            #endif
            closeInternal();
            return false;
        }
        // If EAGAIN, we drop the packet — QUIC's loss recovery will
        // retransmit. Same posture as most QUIC stacks under a full UDP
        // sndbuf.
    }
    return true;
}

void Http3::handleExpiry()
{
    if(conn == nullptr) return;
    int rv = ngtcp2_conn_handle_expiry(conn, now_ns());
    if(rv != 0)
    {
        #ifdef DEBUGHTTPS
        std::cerr << __FILE__ << ":" << __LINE__
                  << " handle_expiry: " << ngtcp2_strerror(rv) << std::endl;
        #endif
        closeInternal();
        return;
    }
    if(!drainSend()) return;
    armTimer(ngtcp2_conn_get_expiry(conn));
}

void Http3::armTimer(ngtcp2_tstamp expiry)
{
    if(timer == nullptr || conn == nullptr) return;
    ngtcp2_tstamp t = now_ns();
    itimerspec its{};
    if(expiry <= t)
    {
        // Schedule immediate firing.
        its.it_value.tv_sec  = 0;
        its.it_value.tv_nsec = 1;
    }
    else
    {
        ngtcp2_tstamp delta = expiry - t;
        its.it_value.tv_sec  = static_cast<time_t>(delta / 1000000000ULL);
        its.it_value.tv_nsec = static_cast<long>(delta % 1000000000ULL);
    }
    ::timerfd_settime(timer->getFD(), 0, &its, nullptr);
}

// ===== nghttp3 setup and request submission =====

bool Http3::setupHttp3()
{
    if(h3conn != nullptr) return true;

    nghttp3_callbacks h3cb;
    std::memset(&h3cb, 0, sizeof(h3cb));
    h3cb.recv_data        = &Http3::h3_recv_data;
    h3cb.deferred_consume = &Http3::h3_deferred_consume;
    h3cb.begin_headers    = &Http3::h3_begin_headers;
    h3cb.recv_header      = &Http3::h3_recv_header;
    h3cb.end_headers      = &Http3::h3_end_headers;
    h3cb.end_stream       = &Http3::h3_end_stream;
    h3cb.stream_close     = &Http3::h3_stream_close;
    h3cb.stop_sending     = &Http3::h3_stop_sending;
    h3cb.reset_stream     = &Http3::h3_reset_stream;

    nghttp3_settings h3settings;
    nghttp3_settings_default(&h3settings);

    int rv = nghttp3_conn_client_new(&h3conn, &h3cb, &h3settings, nullptr, this);
    if(rv != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " nghttp3_conn_client_new: " << nghttp3_strerror(rv)
                  << std::endl;
        return false;
    }

    int64_t ctrl = -1, qenc = -1, qdec = -1;
    if(ngtcp2_conn_open_uni_stream(conn, &ctrl, nullptr) != 0 ||
       ngtcp2_conn_open_uni_stream(conn, &qenc, nullptr) != 0 ||
       ngtcp2_conn_open_uni_stream(conn, &qdec, nullptr) != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " ngtcp2_conn_open_uni_stream failed" << std::endl;
        return false;
    }
    if(nghttp3_conn_bind_control_stream(h3conn, ctrl) != 0 ||
       nghttp3_conn_bind_qpack_streams(h3conn, qenc, qdec) != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " nghttp3 bind streams failed" << std::endl;
        return false;
    }
    controlStreamId = ctrl;
    qencStreamId    = qenc;
    qdecStreamId    = qdec;
    return true;
}

bool Http3::submitGet(const std::string &authority, const std::string &path)
{
    pendingRequests.push_back(PendingReq{authority, path});
    if(h3conn != nullptr && handshakeDone)
        return flushPendingRequests();
    return true;
}

bool Http3::flushPendingRequests()
{
    if(h3conn == nullptr) return false;
    while(!pendingRequests.empty())
    {
        const PendingReq &p = pendingRequests.front();
        bool blocked = false;
        if(!issueRequest(p.authority, p.path, blocked))
        {
            if(blocked)
            {
                // Quota exhausted — retry on extend_max_local_streams_bidi.
                return true;
            }
            return false;
        }
        pendingRequests.pop_front();
    }
    return true;
}

bool Http3::issueRequest(const std::string &authority, const std::string &path,
                        bool &blocked)
{
    blocked = false;
    int64_t sid = -1;
    int rv = ngtcp2_conn_open_bidi_stream(conn, &sid, nullptr);
    if(rv == NGTCP2_ERR_STREAM_ID_BLOCKED)
    {
        blocked = true;
        return false;
    }
    if(rv != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " open_bidi_stream: " << ngtcp2_strerror(rv) << std::endl;
        return false;
    }
    auto nv = [](const char *n, size_t nl,
                 const char *v, size_t vl) -> nghttp3_nv {
        nghttp3_nv x;
        x.name  = reinterpret_cast<uint8_t *>(const_cast<char *>(n));
        x.value = reinterpret_cast<uint8_t *>(const_cast<char *>(v));
        x.namelen  = nl;
        x.valuelen = vl;
        x.flags    = NGHTTP3_NV_FLAG_NONE;
        return x;
    };
    nghttp3_nv hdrs[] = {
        nv(":method",    7, "GET",   3),
        nv(":scheme",    7, "https", 5),
        nv(":authority", 10, authority.data(), authority.size()),
        nv(":path",      5, path.data(),      path.size()),
        nv("user-agent", 10, "confiacdn-h3/0.1", 16),
    };
    rv = nghttp3_conn_submit_request(h3conn, sid, hdrs,
                                     sizeof(hdrs) / sizeof(hdrs[0]),
                                     nullptr, this);
    if(rv != 0)
    {
        std::cerr << __FILE__ << ":" << __LINE__
                  << " nghttp3_submit_request: " << nghttp3_strerror(rv)
                  << std::endl;
        return false;
    }
    streams.emplace(sid, ResponseState{});
    lastRequestStreamId = sid;
    submittedCount++;
    return true;
}

// ===== nghttp3 callback thunks =====

void Http3::recordHeader(int64_t streamId,
                         const uint8_t *name, size_t nlen,
                         const uint8_t *value, size_t vlen)
{
    auto it = streams.find(streamId);
    if(it == streams.end()) return;
    ResponseState &r = it->second;
    auto sv = [](const uint8_t *p, size_t n){
        return std::string(reinterpret_cast<const char *>(p), n);
    };
    if(nlen == 7 && std::memcmp(name, ":status", 7) == 0)
    {
        try { r.status = std::atoi(sv(value, vlen).c_str()); }
        catch(...) { r.status = 0; }
        return;
    }
    auto ieq = [&](const char *lit, size_t litlen){
        if(nlen != litlen) return false;
        for(size_t i = 0; i < litlen; ++i)
        {
            uint8_t a = name[i];
            uint8_t b = static_cast<uint8_t>(lit[i]);
            if(a >= 'A' && a <= 'Z') a = static_cast<uint8_t>(a + 32);
            if(b >= 'A' && b <= 'Z') b = static_cast<uint8_t>(b + 32);
            if(a != b) return false;
        }
        return true;
    };
    if(ieq("content-type", 12))         r.contentType     = sv(value, vlen);
    else if(ieq("content-encoding", 16))r.contentEncoding = sv(value, vlen);
    else if(ieq("etag", 4))             r.etag            = sv(value, vlen);
    else if(ieq("last-modified", 13))   r.lastModified    = sv(value, vlen);
    else if(ieq("content-length", 14))
    {
        try { r.contentLength = std::strtoll(sv(value, vlen).c_str(),
                                             nullptr, 10); }
        catch(...) { r.contentLength = -1; }
    }
}

int Http3::h3_recv_data(nghttp3_conn *h3, int64_t stream_id,
                        const uint8_t *data, size_t datalen,
                        void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    auto it = self->streams.find(stream_id);
    if(it != self->streams.end())
    {
        ResponseState &r = it->second;
        if(datalen > 0 && !r.firstBodyByteSeen)
            r.firstBodyByteSeen = true;
        r.body.insert(r.body.end(), data, data + datalen);
    }
    // Extend QUIC flow-control credit for the consumed body bytes.
    // nghttp3_conn_read_stream's return value (credited in
    // cb_recv_stream_data) covers control + QPACK overhead but NOT DATA
    // frame payload — that's what we got here. Without this extension the
    // peer hits initial_max_stream_data_bidi_local after the first window.
    if(datalen > 0 && self->conn != nullptr)
    {
        ngtcp2_conn_extend_max_stream_offset(self->conn, stream_id, datalen);
        ngtcp2_conn_extend_max_offset(self->conn, datalen);
    }
    return 0;
}

int Http3::h3_deferred_consume(nghttp3_conn *h3, int64_t stream_id,
                               size_t consumed, void *conn_user_data,
                               void *stream_user_data)
{
    (void)h3; (void)stream_id; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    if(self->conn != nullptr)
        ngtcp2_conn_extend_max_offset(self->conn,
                                      static_cast<uint64_t>(consumed));
    return 0;
}

int Http3::h3_begin_headers(nghttp3_conn *h3, int64_t stream_id,
                            void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_id; (void)conn_user_data; (void)stream_user_data;
    return 0;
}

int Http3::h3_recv_header(nghttp3_conn *h3, int64_t stream_id,
                          int32_t token, nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value, uint8_t flags,
                          void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)token; (void)flags; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
    self->recordHeader(stream_id, n.base, n.len, v.base, v.len);
    return 0;
}

int Http3::h3_end_headers(nghttp3_conn *h3, int64_t stream_id, int fin,
                          void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)fin; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    auto it = self->streams.find(stream_id);
    if(it != self->streams.end())
        it->second.headersDone = true;
    return 0;
}

int Http3::h3_end_stream(nghttp3_conn *h3, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    auto it = self->streams.find(stream_id);
    if(it != self->streams.end())
        it->second.streamDone = true;
    return 0;
}

int Http3::h3_stream_close(nghttp3_conn *h3, int64_t stream_id,
                           uint64_t app_error_code, void *conn_user_data,
                           void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    auto it = self->streams.find(stream_id);
    if(it != self->streams.end())
    {
        it->second.appErrorCode = app_error_code;
        it->second.streamDone   = true;
    }
    return 0;
}

int Http3::h3_stop_sending(nghttp3_conn *h3, int64_t stream_id,
                           uint64_t app_error_code, void *conn_user_data,
                           void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    if(self->conn != nullptr)
        ngtcp2_conn_shutdown_stream_read(self->conn, 0, stream_id,
                                         app_error_code);
    return 0;
}

int Http3::h3_reset_stream(nghttp3_conn *h3, int64_t stream_id,
                           uint64_t app_error_code, void *conn_user_data,
                           void *stream_user_data)
{
    (void)h3; (void)stream_user_data;
    Http3 *self = static_cast<Http3 *>(conn_user_data);
    if(self->conn != nullptr)
        ngtcp2_conn_shutdown_stream_write(self->conn, 0, stream_id,
                                          app_error_code);
    return 0;
}

// ===== Session cache =====

const std::vector<uint8_t> *Http3::lookupSession(const std::string &key)
{
    auto it = sessionCache.find(key);
    if(it == sessionCache.end()) return nullptr;
    // Touch: move this key to the MRU end of the LRU list.
    lruOrder.splice(lruOrder.begin(), lruOrder, it->second.lruIt);
    it->second.lruIt = lruOrder.begin();
    return &it->second.blob;
}

void Http3::storeSession(const std::string &key, std::vector<uint8_t> blob)
{
    auto it = sessionCache.find(key);
    if(it != sessionCache.end())
    {
        it->second.blob = std::move(blob);
        // Touch on store too — the peer just issued us a fresh ticket
        // for this origin, so it's by definition most-recently-used.
        lruOrder.splice(lruOrder.begin(), lruOrder, it->second.lruIt);
        it->second.lruIt = lruOrder.begin();
        return;
    }
    while(sessionCache.size() >= kSessionCacheMax)
    {
        // Evict from the LRU tail.
        const std::string victim = lruOrder.back();
        lruOrder.pop_back();
        sessionCache.erase(victim);
    }
    lruOrder.push_front(key);
    SessionEntry e;
    e.blob  = std::move(blob);
    e.lruIt = lruOrder.begin();
    sessionCache.emplace(key, std::move(e));
}

size_t Http3::sessionCacheSize()
{
    return sessionCache.size();
}

// ===== Origin-failure cache =====

namespace {
uint64_t monotonic_seconds()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec);
}
} // namespace

std::string Http3::failureKey(const sockaddr_in6 &target)
{
    // 18 raw bytes: 16-byte IPv6 + 2-byte port (network order, matches
    // what's already on the wire). Keep it raw — no inet_ntop cost on
    // the hot path.
    std::string k;
    k.resize(18);
    std::memcpy(&k[0],  &target.sin6_addr, 16);
    std::memcpy(&k[16], &target.sin6_port, 2);
    return k;
}

void Http3::lru_insert(std::unordered_map<std::string, FailureEntry> &cache,
                       std::list<std::string> &order,
                       std::string key, uint64_t whenSec, size_t cap)
{
    while(cache.size() >= cap)
    {
        const std::string victim = order.back();
        order.pop_back();
        cache.erase(victim);
    }
    order.push_front(key);
    FailureEntry e;
    e.whenSec = whenSec;
    e.lruIt   = order.begin();
    cache.emplace(std::move(key), std::move(e));
}

void Http3::lru_erase(std::unordered_map<std::string, FailureEntry> &cache,
                      std::list<std::string> &order,
                      std::unordered_map<std::string, FailureEntry>::iterator it)
{
    order.erase(it->second.lruIt);
    cache.erase(it);
}

void Http3::markOriginFailed(const sockaddr_in6 &target)
{
    std::string key = failureKey(target);
    uint64_t now = monotonic_seconds();

    // Already confirmed-failed. Leave the original whenSec in place so
    // the 72 h TTL is measured from the FIRST confirmation, not from
    // every subsequent retry — otherwise a slow-but-trying origin would
    // be locked out indefinitely.
    auto itC = failureCache.find(key);
    if(itC != failureCache.end())
    {
        failLruOrder.splice(failLruOrder.begin(), failLruOrder,
                            itC->second.lruIt);
        itC->second.lruIt = failLruOrder.begin();
        return;
    }

    // Probation: 72 h TTL already expired and a retry just failed. One
    // post-expiry failure is enough to re-promote.
    auto itProb = probationCache.find(key);
    if(itProb != probationCache.end())
    {
        lru_erase(probationCache, probationLruOrder, itProb);
        lru_insert(failureCache, failLruOrder, std::move(key), now,
                   kOriginFailureCacheMax);
        return;
    }

    // Pending: a previous failure exists. Promote to confirmed iff the
    // gap is at least the confirmation interval — otherwise leave the
    // pending entry in place so its first-failure timestamp stays the
    // anchor.
    auto itPend = pendingFailureCache.find(key);
    if(itPend != pendingFailureCache.end())
    {
        if(now < itPend->second.whenSec ||
           now - itPend->second.whenSec >= kOriginFailureConfirmIntervalSeconds)
        {
            lru_erase(pendingFailureCache, pendingFailLruOrder, itPend);
            lru_insert(failureCache, failLruOrder, std::move(key), now,
                       kOriginFailureCacheMax);
        }
        else
        {
            // Still within the 15-min window — just refresh LRU position.
            pendingFailLruOrder.splice(pendingFailLruOrder.begin(),
                                       pendingFailLruOrder,
                                       itPend->second.lruIt);
            itPend->second.lruIt = pendingFailLruOrder.begin();
        }
        return;
    }

    // First failure for this target — record in pending.
    lru_insert(pendingFailureCache, pendingFailLruOrder, std::move(key), now,
               kOriginFailureCacheMax);
}

void Http3::markOriginSuccess(const sockaddr_in6 &target)
{
    std::string key = failureKey(target);
    auto itC = failureCache.find(key);
    if(itC != failureCache.end())
        lru_erase(failureCache, failLruOrder, itC);
    auto itProb = probationCache.find(key);
    if(itProb != probationCache.end())
        lru_erase(probationCache, probationLruOrder, itProb);
    auto itPend = pendingFailureCache.find(key);
    if(itPend != pendingFailureCache.end())
        lru_erase(pendingFailureCache, pendingFailLruOrder, itPend);
}

bool Http3::isOriginRecentlyFailed(const sockaddr_in6 &target)
{
    std::string key = failureKey(target);
    auto it = failureCache.find(key);
    if(it == failureCache.end()) return false;
    uint64_t now = monotonic_seconds();
    if(now < it->second.whenSec) return true; // clock skew safety
    if(now - it->second.whenSec >= kOriginFailureTtlSeconds)
    {
        // 72 h elapsed. Move into probation so the very next failure
        // re-promotes without waiting through the confirmation window
        // again — past behaviour proved this origin is broken for H3.
        lru_erase(failureCache, failLruOrder, it);
        lru_insert(probationCache, probationLruOrder, std::move(key), now,
                   kOriginFailureCacheMax);
        return false;
    }
    // Touch on lookup so frequently-checked failing origins stay hot.
    failLruOrder.splice(failLruOrder.begin(), failLruOrder, it->second.lruIt);
    it->second.lruIt = failLruOrder.begin();
    return true;
}

size_t Http3::failureCacheSize()
{
    return failureCache.size();
}

size_t Http3::pendingFailureCacheSize()
{
    return pendingFailureCache.size();
}

// ===== Multi-stream accessors =====

const Http3::ResponseState *Http3::getResponse(int64_t streamId) const
{
    auto it = streams.find(streamId);
    if(it == streams.cend()) return nullptr;
    return &it->second;
}

size_t Http3::streamsCompleted() const
{
    size_t n = 0;
    for(const auto &kv : streams)
        if(kv.second.streamDone) ++n;
    return n;
}

bool Http3::allStreamsDone() const
{
    if(!pendingRequests.empty()) return false;
    if(streams.empty()) return false;
    for(const auto &kv : streams)
        if(!kv.second.streamDone) return false;
    return true;
}

const Http3::ResponseState &Http3::response() const
{
    static const ResponseState empty;
    auto it = streams.find(lastRequestStreamId);
    if(it == streams.cend()) return empty;
    return it->second;
}

bool Http3::isHealthy() const
{
    if(connFailed) return false;
    if(conn == nullptr) return false;
    return true;
}
