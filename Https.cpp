#include "Https.hpp"
#include <iostream>
#ifdef DEBUGFASTCGI
#include <arpa/inet.h>
#endif

std::unordered_map<std::string,Http *> Https::pathToHttps;
#ifdef DEBUGFASTCGI
std::unordered_set<Https *> Https::toDebug;
#endif

Https::Https(const int &cachefd, const std::string &cachePath, Client *client) :
    Http(cachefd,cachePath,client)
{
    #ifdef DEBUGFASTCGI
    toDebug.insert(this);
    #endif
}

Https::~Https()
{
    #ifdef DEBUGFASTCGI
    if(toDebug.find(this)!=toDebug.cend())
        toDebug.erase(this);
    else
    {
        std::cerr << "Https Entry not found into global list, abort()" << std::endl;
        abort();
    }
    #endif
}

bool Https::tryConnectInternal(const sockaddr_in6 &s)
{
    bool connectInternal=false;
    backend=Backend::tryConnectHttps(s,this,connectInternal,&backendList);
    #ifdef DEBUGFASTCGI
    if(backend==nullptr)
        std::cerr << this << ": unable to get backend for " << getUrl() << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << this << ": http->backend=" << backend << " && connectInternal=" << connectInternal << std::endl;
    #endif
    return connectInternal && backend!=nullptr;
}

std::unordered_map<std::string,Http *> &Https::pathToHttpList()
{
    return pathToHttps;
}

/*std::unordered_map<std::string, Backend::BackendList *> &Https::addressToHttpsList()
{
    return Backend::addressToHttps;
}*/

std::string Https::getUrl() const
{
    if(host.empty() && uri.empty())
        return "no url";
    else
        return "https://"+host+uri;
}
