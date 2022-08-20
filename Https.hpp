#ifndef HTTPS_H
#define HTTPS_H

#include "Http.hpp"
#include <openssl/ssl.h>
#ifdef DEBUGFASTCGI
#include <unordered_set>
#endif

class Https : public Http
{
public:
    Https(const int &cachefd,//0 if no old cache file found
          const std::string &cachePath, Client *client);
    virtual ~Https();
    bool tryConnectInternal(const sockaddr_in6 &s) override;
    std::unordered_map<std::string,Http *> &pathToHttpList() override;
    //std::unordered_map<std::string,Backend::BackendList *> &addressToHttpsList();
    #ifdef DEBUGHTTPS
    static void dump_cert_info(SSL *ssl, bool server);
    #endif
    void init_ssl_opts(SSL_CTX* ctx);
    std::string getUrl() const override;
    #ifdef DEBUGFASTCGI
    /// \warning The class 'Https' defines member variable with name 'toDebug' also defined in its parent class 'Http'.
    static std::unordered_set<Https *> toDebug;
    #endif
    bool isHttps() override;
public:
    //index can be: 29E7336BDEA3327B or XXXXXXXX/XXXXXXXXXXXXXXXXY
    static std::unordered_map<std::string,Http *> pathToHttps;
};

#endif // HTTPS_H
