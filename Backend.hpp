#ifndef CURL
#ifndef BACKEND_H
#define BACKEND_H

#include "EpollObject.hpp"
#include <netinet/in.h>
#include <unordered_map>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#ifdef DEBUGFASTCGI
#include <unordered_set>
#endif

class Http;

class Backend : public EpollObject
{
public:
    static uint32_t maxBackend;
    struct BackendList
    {
        std::vector<Backend *> busy;
        std::vector<Backend *> idle;
        std::vector<Http *> pending;//only when no idle and max busy reached
        sockaddr_in6 s;
    };
    enum NonHttpError : uint8_t
    {
        NonHttpError_AlreadySend,
        NonHttpError_Timeout,
        NonHttpError_DnsError,
        NonHttpError_DnsWrong,
        NonHttpError_DnsOverloaded
    };
public:
    Backend(BackendList * backendList);
    void close();
    void closeSSL();
    virtual ~Backend();
    void remoteSocketClosed();
    static Backend * tryConnectInternalList(const sockaddr_in6 &s, Http *http, std::unordered_map<std::string, BackendList *> &addressToList, bool &connectInternal, BackendList **backendList);
    static Backend * tryConnectHttp(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList);
    static Backend * tryConnectHttps(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList);
    void startHttps();
    void downloadFinished();
    void parseEvent(const epoll_event &event) override;
    bool tryConnectInternal(const sockaddr_in6 &s);
    static std::unordered_map<std::string/*128Bits/16Bytes IPv6 encoded*/,BackendList *> addressToHttp;
    static std::unordered_map<std::string/*128Bits/16Bytes IPv6 encoded*/,BackendList *> addressToHttps;
    static uint64_t msFrom1970();//ms from 1970
    bool detectTimeout();
    std::string getQuery() const;
    void startNextPending();

    void readyToWrite();
    ssize_t socketRead(void *buffer, size_t size);
    bool socketWrite(const void *buffer, size_t size);
    #ifdef DEBUGHTTPS
    static void dump_cert_info(SSL *ssl, bool server);
    #endif
    #ifdef DEBUGFASTCGI
    static std::unordered_set<Backend *> toDebug;
    #endif
public:
    static uint16_t https_portBE;
    Http *http;
    bool https;
    bool wasTCPConnected;
    const static SSL_METHOD *meth;
private:
    uint64_t lastActivitymsTimestamps;
    std::string bufferSocket;

public:
    BackendList * backendList;//public to debug
private:

    SSL_CTX* ctx;
    SSL* ssl;
};

#endif // BACKEND_H
#endif
