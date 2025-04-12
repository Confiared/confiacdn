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
    #ifdef DEBUGFASTCGI
    static std::unordered_set<Backend *> backendToDebug;
    #endif
    static bool forceHttpClose;
    static uint32_t maxBackend;
    static std::unordered_map<std::string/*128Bits/16Bytes IPv6 encoded*/,BackendList *> addressToHttp;
    static std::unordered_map<std::string/*128Bits/16Bytes IPv6 encoded*/,BackendList *> addressToHttps;
public:
    Backend(BackendList * backendList);
    virtual ~Backend();
    #ifdef DEBUGFASTCGI
    static void checkBackend();
    #endif
    void remoteSocketClosed();
    bool detectTimeout();
    static Backend * tryConnectHttp(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList);
    static Backend * tryConnectHttps(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList);
    void parseEvent(const epoll_event &event) override;
    ssize_t socketRead(void *buffer, size_t size);
    bool socketWrite(const void *buffer, size_t size);
    std::string getQuery() const;
    void downloadFinished();//after this, the backend should not point to http previous http at least, http should be nullptr
    unsigned int get_downloadFinishedCount() const;
    void close();//call externally from Http::detectTimeout()
private:
    void closeSSL();
    void remoteSocketClosedInternal();
    static Backend * tryConnectInternalList(const sockaddr_in6 &s, Http *http, std::unordered_map<std::string, BackendList *> &addressToList, bool &connectInternal, BackendList **backendList);
    void startHttps();
    void downloadFinishedInternal();
    bool tryConnectInternal(const sockaddr_in6 &s);
    void startNextPending();
    void startNextPendingInternal();

    void readyToWrite();
    #ifdef DEBUGHTTPS
    static void dump_cert_info(SSL *ssl, bool server);
    #endif
public:
    static uint16_t https_portBE;
    Http *http;
    bool https;
    bool wasTCPConnected;
    const static SSL_METHOD *meth;
    unsigned int downloadFinishedCount;
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
