#include "Https.hpp"
#include "Common.hpp"
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
    if(backend!=nullptr)
    {
        disconnectBackend();
        #ifdef DEBUGFASTCGI
            //if this can be located into another backend, then error
        for( const auto& n : Backend::addressToHttp )
        {
            const Backend::BackendList * list=n.second;
            for(const Backend * b : list->busy)
                if(b->http==this)
                {
                    std::cerr << this << ": backend->http==this, http backend: " << backend << " " << getUrl() << " (abort)" << std::endl;
                    abort();
                }
        }
        for( const auto& n : Backend::addressToHttps )
        {
            const Backend::BackendList * list=n.second;
            for(const Backend * b : list->busy)
                if(b->http==this)
                {
                    std::cerr << this << ": backend->http==this, https backend: " << backend << " " << getUrl() << " (abort)" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
        }
        #endif
    }
    backend=Backend::tryConnectHttps(s,this,connectInternal,&backendList);
    #ifdef DEBUGFASTCGI
    if(backend==nullptr)
        std::cerr << Common::msFrom1970() << " " << this << ": unable to get backend for " << host << uri << " then put in pending" << " " << __FILE__ << ":" << __LINE__ << std::endl;
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

bool Https::isHttps()
{
    return true;
}
