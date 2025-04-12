#ifndef CURL
#include "Backend.hpp"
#include "Http.hpp"
#include "Cache.hpp"
#include "Common.hpp"
#include <iostream>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <chrono>

#ifdef DEBUGFASTCGI
#include <sys/time.h>
#endif

//curl -v -H "Accept-Encoding: gzip" -o style.css.gz 'http://cdn.bolivia-online.com/ultracopier-static.first-world.info/css/style.css'

std::unordered_map<std::string,Backend::BackendList *> Backend::addressToHttp;
std::unordered_map<std::string,Backend::BackendList *> Backend::addressToHttps;
uint32_t Backend::maxBackend=64;
bool Backend::forceHttpClose=false;

#ifdef DEBUGFASTCGI
std::unordered_set<Backend *> Backend::backendToDebug;
#endif

uint16_t Backend::https_portBE=0;
const SSL_METHOD *Backend::meth=nullptr;

Backend::Backend(BackendList * backendList) :
    http(nullptr),
    https(false),
    wasTCPConnected(false),
    downloadFinishedCount(0),
    lastActivitymsTimestamps(0),
    backendList(backendList),
    ctx(nullptr),
    ssl(nullptr)
{
    #ifdef DEBUGFASTCGI
    backendToDebug.insert(this);
    #endif
    lastActivitymsTimestamps=Common::msFrom1970();
    this->kind=EpollObject::Kind::Kind_Backend;
}

Backend::~Backend()
{
    //to be safe, delete when all is stable
    if(backendList!=nullptr)
    {
        unsigned int index=0;
        while(index<backendList->busy.size())
        {
            if(backendList->busy.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                backendList->busy.erase(backendList->busy.cbegin()+index);
                abort();
            }
            else
                index++;
        }
    }
    for( const auto &n : Backend::addressToHttp )
    {
        unsigned int index=0;
        while(index<n.second->busy.size())
        {
            if(n.second->busy.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                n.second->busy.erase(n.second->busy.cbegin()+index);
                abort();
            }
            else
                index++;
        }
        index=0;
        while(index<n.second->idle.size())
        {
            if(n.second->idle.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                n.second->idle.erase(n.second->idle.cbegin()+index);
                abort();
            }
            else
                index++;
        }
    }
    for( const auto &n : Backend::addressToHttps )
    {
        unsigned int index=0;
        while(index<n.second->busy.size())
        {
            if(n.second->busy.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                n.second->busy.erase(n.second->busy.cbegin()+index);
                abort();
            }
            else
                index++;
        }
        index=0;
        while(index<n.second->idle.size())
        {
            if(n.second->idle.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                n.second->idle.erase(n.second->idle.cbegin()+index);
                abort();
            }
            else
                index++;
        }
    }
    #ifdef DEBUGFASTCGI
    if(backendToDebug.find(this)!=backendToDebug.cend())
        backendToDebug.erase(this);
    else
    {
        std::cerr << "Backend Entry not found into global list, abort()" << std::endl;
        abort();
    }
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    if(fd!=-1)
    {
        std::cerr << "EPOLL_CTL_DEL Http: " << fd << std::endl;
        Cache::unregisterCacheFD(fd);
        if(epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL)==-1)
            std::cerr << "EPOLL_CTL_DEL Http: " << fd << ", errno: " << errno << std::endl;
    }
    if(http!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << ": http->backend=nullptr; (destructor), http: " << http << std::endl;
        #endif
        Http *http=this->http;
        this->http=nullptr;
        http->backend=nullptr;
        http->backendList=nullptr;
        /* when domain not exists: https://cdn.confiared.com/unknown.domain.com/index.css 
         * When The remote server have close the connexion */
        http->backendErrorAndDisconnect("Backend destructor called when remain http connected");
        http->disconnectFrontend(false);
    }
    if(backendList!=nullptr)
    {
        size_t index=0;
        while(index<backendList->busy.size())
        {
            if(backendList->busy.at(index)==this)
            {
                backendList->busy.erase(backendList->busy.cbegin()+index);
                break;
            }
            index++;
        }
        index=0;
        while(index<backendList->idle.size())
        {
            if(backendList->idle.at(index)==this)
            {
                backendList->idle.erase(backendList->idle.cbegin()+index);
                break;
            }
            index++;
        }
    }
    closeSSL();
}

void Backend::close()//call externally from Http::detectTimeout()
{
    #ifdef DEBUGFASTCGI
    std::cerr << "Backend::close() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif

    //abort(); -> do this test

    if(fd!=-1)
    {
        Cache::unregisterCacheFD(fd);
        epoll_ctl(epollfd,EPOLL_CTL_DEL, fd, NULL);
        #ifdef DEBUGFASTCGI
        std::cerr << "Backend::close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        ::close(fd);
        //prevent multiple loop call
        fd=-1;

        if(backendList!=nullptr)
        {
            if(!backendList->pending.empty())
                std::cerr << "Backend::close() AND !backendList->pending.empty() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        }

/* not fix like this, generate http remain attached
 *         if(backendList!=nullptr)
        {
            size_t index=0;
            while(index<backendList->busy.size())
            {
                if(backendList->busy.at(index)==this)
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << "Backend::close() " << this << " " << __FILE__ << ":" << __LINE__ << " ERROR should not pass here" << std::endl;
                    #endif
                    backendList->busy.erase(backendList->busy.cbegin()+index);
                    break;
                }
                index++;
            }
            index=0;
            while(index<backendList->idle.size())
            {
                if(backendList->idle.at(index)==this)
                {
                    backendList->idle.erase(backendList->idle.cbegin()+index);
                    break;
                }
                index++;
            }
        }*/
    }
    closeSSL();
}

void Backend::closeSSL()
{
    if(ssl!=nullptr)
    {
        SSL_free(ssl);
        ssl=nullptr;
    }
    if(ctx!=NULL)
    {
        SSL_CTX_free(ctx);
        ctx=nullptr;
    }
}

void Backend::remoteSocketClosed()
{
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    remoteSocketClosedInternal();
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
}

void Backend::remoteSocketClosedInternal()
{
    #ifdef DEBUGFASTCGI
    std::cerr << "Backend::remoteSocketClosed() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    #ifdef DEBUGFILEOPEN
    std::cerr << "Backend::remoteSocketClosed(), fd: " << fd << std::endl;
    #endif
    if(fd!=-1)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "EPOLL_CTL_DEL remoteSocketClosed Http: " << fd << std::endl;
        #endif
        Cache::unregisterCacheFD(fd);
        if(epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL)==-1)
            std::cerr << "EPOLL_CTL_DEL remoteSocketClosed Http: " << fd << ", errno: " << errno << std::endl;
        #ifdef DEBUGFASTCGI
        std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        ::close(fd);
        fd=-1;
    }
    closeSSL();
    if(http!=nullptr)
        http->resetRequestSended();
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    if(backendList!=nullptr)
    {
        if(!wasTCPConnected)
        {
            size_t index=0;
            while(index<backendList->busy.size())
            {
                if(backendList->busy.at(index)==this)
                {
                    backendList->busy.erase(backendList->busy.cbegin()+index);
                    break;
                }
                index++;
            }
            if(!backendList->pending.empty() && backendList->busy.empty())
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "Tcp connect problem, abort asll pending fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                const std::string error("Tcp connect problem");
                /*forget the pedding will retry after or timeout
                why not quit if TCP connect? can be timeout on specific connexion but the TCP is well accessible
                size_t index=0;
                while(index<backendList->pending.size())
                {
                    Http *http=backendList->pending.at(index);
                    http->backendError(error);//drop from list, then delete http
                    http->disconnectFrontend(true);
                    http->disconnectBackend();
                    index++;
                }*/
            }
            Http *httpTempToPassCheckBackend=http;
            http=nullptr;
            if(httpTempToPassCheckBackend!=nullptr)
            {
                httpTempToPassCheckBackend->backend=nullptr;
                httpTempToPassCheckBackend->backendList=nullptr;
            }
            #ifdef DEBUGFASTCGI
            std::cerr << "remoteSocketClosed and was NOT TCP connected " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            #ifdef DEBUGFASTCGI
            checkBackend();
            #endif
            return;
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " was TCP connected, backendList: " << (void *)backendList << ", backendList->busy.size(): " << std::to_string(backendList->busy.size()) << std::endl;
            #endif
            size_t index=0;
            while(index<backendList->busy.size())
            {
                if(backendList->busy.at(index)==this)
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << __FILE__ << ":" << __LINE__ << " located into busy to destroy: " << this << std::endl;
                    #endif
                    backendList->busy.erase(backendList->busy.cbegin()+index);
                    if(http!=nullptr)
                    {
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " backend destroy but had http client connected, try reasign" << std::endl;
                        #endif
                        /*if(http->requestSended)
                        {
                            std::cerr << "reassign but request already send" << std::endl;
                            http->parseNonHttpError(Backend::NonHttpError_AlreadySend);
                            return;
                        }*/
                        #ifdef DEBUGFASTCGI
                        if(http->requestSended)
                            std::cerr << "reassign but request already send" << std::endl;
                        #endif
                        Http *httpTempToPassCheckBackend=http;
                        http=nullptr;
                        httpTempToPassCheckBackend->requestSended=false;
                        #ifdef DEBUGFASTCGI
                        checkBackend();
                        #endif
                        //reassign to idle backend
                        if(!backendList->idle.empty())
                        {
                            //assign to idle backend and become busy
                            Backend *backend=backendList->idle.back();
                            backendList->idle.pop_back();
                            backendList->busy.push_back(backend);
                            backend->http=httpTempToPassCheckBackend;
                            #ifdef DEBUGFASTCGI
                            std::cerr << "reassign to idle backend, backend: " << this << " http: " << httpTempToPassCheckBackend << ": http->backend=" << backend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << backend->isValid() << std::endl;
                            #endif
                            httpTempToPassCheckBackend->backend=backend;
                            httpTempToPassCheckBackend->backendList=backendList;
                            httpTempToPassCheckBackend->readyToWrite();
                            #ifdef DEBUGFASTCGI
                            httpTempToPassCheckBackend->checkBackend();
                            checkBackend();
                            #endif
                        }
                        //reassign to new backend
                        else
                        {
                            Backend *newBackend=new Backend(backendList);
                            if(!newBackend->tryConnectInternal(backendList->s))
                            {
                                //todo abort client
                                #ifdef DEBUGFASTCGI
                                checkBackend();
                                #endif
                                return;
                            }
                            newBackend->http=httpTempToPassCheckBackend;
                            #ifdef DEBUGFASTCGI
                            std::cerr << "reassign to new backend, backend: " << this << " http: " << httpTempToPassCheckBackend << ": http->backend=" << newBackend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << newBackend->isValid() << std::endl;
                            #endif
                            httpTempToPassCheckBackend->backend=newBackend;
                            httpTempToPassCheckBackend->backendList=backendList;

                            backendList->busy.push_back(newBackend);
                            #ifdef DEBUGFASTCGI
                            httpTempToPassCheckBackend->checkBackend();
                            checkBackend();
                            #endif
                        }
                        return;
                    }
                    if(backendList->busy.empty() && backendList->idle.empty() && backendList->pending.empty())
                    {
                        #ifdef DEBUGFASTCGI
                        std::string host="Unknown IPv6";
                        char str[INET6_ADDRSTRLEN];
                        if (inet_ntop(AF_INET6, &backendList->s.sin6_addr, str, INET6_ADDRSTRLEN) != NULL)
                            host=str;
                        std::cerr << __FILE__ << ":" << __LINE__ << " addressToHttp.erase(): " << host << std::endl;
                        #endif
                        std::string addr((char *)&backendList->s.sin6_addr,16);
                        if(backendList->s.sin6_port == htobe16(80))
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " addressToHttp.erase(): " << host << ":" << be16toh(backendList->s.sin6_port) << std::endl;
                            if(addressToHttp.at(addr)!=backendList)
                            {
                                std::cerr << "intented erase backend list is not same than current (abort)" << std::endl;
                                abort();
                            }
                            if(!addressToHttp.at(addr)->busy.empty() || !addressToHttp.at(addr)->idle.empty() || !addressToHttp.at(addr)->pending.empty())
                            {
                                std::cerr << "intented erase backend list have pending request (abort)" << std::endl;
                                abort();
                            }
                            #endif
                            addressToHttp.erase(addr);
                        }
                        else
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " addressToHttp.erase(): " << host << ":" << be16toh(backendList->s.sin6_port) << std::endl;
                            if(addressToHttps.at(addr)!=backendList)
                            {
                                std::cerr << "intented erase backend list is not same than current (abort)" << std::endl;
                                abort();
                            }
                            if(!addressToHttps.at(addr)->busy.empty() || !addressToHttps.at(addr)->idle.empty() || !addressToHttps.at(addr)->pending.empty())
                            {
                                std::cerr << "intented erase backend list have pending request (abort)" << std::endl;
                                abort();
                            }
                            if(be16toh(backendList->s.sin6_port)!=443)
                            {
                                std::cerr << "intented erase backend list have wrong port (abort)" << std::endl;
                                abort();
                            }
                            #endif
                            addressToHttps.erase(addr);
                        }
                    }
                    backendList=nullptr;
                    #ifdef DEBUGFASTCGI
                    std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    break;
                }
                index++;
            }
            #ifdef DEBUGFASTCGI
            if(index<backendList->busy.size())
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " found into busy" << std::endl;
            else
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " NOT found into busy" << std::endl;
            #endif
            index=0;
            if(backendList!=nullptr)
            {
                while(index<backendList->idle.size())
                {
                    if(backendList->idle.at(index)==this)
                    {
                        backendList->idle.erase(backendList->idle.cbegin()+index);
                        break;
                    }
                    index++;
                }
                #ifdef DEBUGFASTCGI
                if(index<backendList->idle.size())
                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " found into idle" << std::endl;
                else
                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " NOT found into idle" << std::endl;
                #endif
            }
        }
    }
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
}

//after this, the backend should not point to http previous http at least, http should be nullptr
void Backend::downloadFinished()
{
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    //after this, the backend should not point to http previous http at least
    Http *oldhttp=http;
    downloadFinishedInternal();
    #ifdef DEBUGFASTCGI
    if(http==oldhttp)
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " http: " << http << " backend: " << this << " http==oldhttp after downloadFinishedInternal(); (abort)" << std::endl;
        abort();
    }
    /* WRONG: this backend can now have another http to do
     * if(http!=nullptr)
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " http: " << http << " backend: " << this << " http!=nullptr after downloadFinishedInternal(); (abort)" << std::endl;
        abort();
    }*/
    std::cerr << __FILE__ << ":" << __LINE__ << " http: " << http  << " backend: " << this<< " after downloadFinishedInternal()" << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
}

void Backend::downloadFinishedInternal()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " http " << http << " is finished, should be destruct Backend::downloadFinished() " << this << std::endl;
    if(http==nullptr)
        std::cerr << __FILE__ << ":" << __LINE__ << "Backend::downloadFinished() http==nullptr bug suspected WARNING " << this << std::endl;
    #endif
    if(backendList==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " http " << http << " backendList==nullptr return" << std::endl;
        #endif
        http=nullptr;
        return;
    }
    if(wasTCPConnected)
        downloadFinishedCount++;
    if(!wasTCPConnected || Backend::forceHttpClose)
    {
        const std::string error("Tcp connect problem");

        size_t index=0;
        while(index<backendList->busy.size())
        {
            if(backendList->busy.at(index)==this)
            {
                backendList->busy.erase(backendList->busy.cbegin()+index);
                break;
            }
            index++;
        }

/* firstly the current need retry
        if(!backendList->pending.empty() && backendList->busy.empty())
        {
            size_t index=0;
            while(index<backendList->pending.size())
            {
                Http *http=backendList->pending.at(index);
                http->backendError(error);
                http->disconnectFrontend(false);
                //http->disconnectBackend();-> no backend because pending
                //delete http;
                index++;
            }
        }*/
        if(http!=nullptr)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " Backend::downloadFinished() NOT TRY AGAIN, http was: " << http << std::endl;
            #endif
            #ifdef DEBUGFASTCGI
            http->checkBackend();
            #endif
            Http *httpTempToPassCheckBackend=http;
            http=nullptr;
            httpTempToPassCheckBackend->backend=nullptr;
            httpTempToPassCheckBackend->backendList=nullptr;
            httpTempToPassCheckBackend->backendErrorAndDisconnect(error);//disconnect client like http->disconnectFrontend();
            //http->disconnectBackend();
            //delete http;
            #ifdef DEBUGFASTCGI
            httpTempToPassCheckBackend->checkBackend();
            #endif
        }
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " Backend::downloadFinished() call close() http: " << http << " fd: " << fd << std::endl;
        #endif
        close();
        /* corruption loop:
         * ==1400295==    by 0x14F693: Http::checkBackend() (Http.cpp:3122)
==1400295==    by 0x11AD93: Backend::downloadFinishedInternal() (Backend.cpp:551)
==1400295==    by 0x11A8EF: Backend::downloadFinished() (Backend.cpp:482)
==1400295==    by 0x148B27: Http::disconnectBackend(bool) (Http.cpp:2100)
==1400295==    by 0x119957: Backend::remoteSocketClosed() (Backend.cpp:306)
==1400295==    by 0x11AE63: Backend::downloadFinishedInternal() (Backend.cpp:568)
==1400295==    by 0x11A8EF: Backend::downloadFinished() (Backend.cpp:482)
==1400295==    by 0x148B27: Http::disconnectBackend(bool) (Http.cpp:2100)
        remoteSocketClosed();
        */
        /// \todo, check if need static to delete here
        return;
    }
    if(backendList->pending.empty())
    {
        size_t index=0;
        while(index<backendList->busy.size())
        {
            if(backendList->busy.at(index)==this)
            {
                backendList->busy.erase(backendList->busy.cbegin()+index);
                break;
            }
            index++;
        }
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " http: " << http << std::endl;
        #endif
        if(this->isValid())
            backendList->idle.push_back(this);
        #ifdef DEBUGFASTCGI
        std::cerr << this << " backend, " << http << ": http->backend=null + http=nullptr" << " " << __FILE__ << ":" << __LINE__ << " isValid: " << this->isValid() << std::endl;
        #endif
        /** \todo fix clean client disconnection from here
         *  void Http::disconnectBackend(const bool fromDestructor) if timeout before start download, have client list
         *  **/
        /*http->disconnectFrontend();
         * ==30297==    at 0x55EF820: std::basic_ostream<char, std::char_traits<char> >& std::operator<< <char, std::char_traits<char>, std::allocator<char> >(std::basic_ostream<char, std::char_traits<char> >&, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.22)
==30297==    by 0x12EE3B: Client::continueRead() (Client.cpp:1655)
==30297==    by 0x12F6F6: Client::readyToWrite() (Client.cpp:1751)
==30297==    by 0x123CE7: Client::parseEvent(epoll_event const&) (Client.cpp:100)
==30297==    by 0x10DEB4: main (main.cpp:202)
==30297==  Address 0x6624560 is 16 bytes inside a block of size 448 free'd
==30297==    at 0x4C2D2DB: operator delete(void*) (vg_replace_malloc.c:576)
==30297==    by 0x1357C1: Http::~Http() (Http.cpp:153)
==30297==    by 0x10DD15: main (main.cpp:179)
==30297==  Block was alloc'd at
==30297==    at 0x4C2C21F: operator new(unsigned long) (vg_replace_malloc.c:334)
==30297==    by 0x12C837: Client::dnsRight(sockaddr_in6 const&) (Client.cpp:1321)
==30297==    by 0x1490D5: Dns::parseEvent(epoll_event const&) (Dns.cpp:402)
==30297==    by 0x10DF90: main (main.cpp:224)
*/
        //http->backend=nullptr;

        //http->disconnectBackend();->generate cache corruption
        //delete http;

        //try 30/06/2021
        Http *httpTempToPassCheckBackend=http;
        http=nullptr;
        httpTempToPassCheckBackend->disconnectFrontend(false);
        //http->disconnectBackend();
        httpTempToPassCheckBackend->backend=nullptr;
        httpTempToPassCheckBackend->backendList=nullptr;
        #ifdef DEBUGFASTCGI
        httpTempToPassCheckBackend->checkBackend();
        #endif
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " http: " << http << ": http->backend=null and !backendList->pending.empty() cachePath " << http->cachePath << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        Http *httpTempToPassCheckBackend=http;
        httpTempToPassCheckBackend->backend=nullptr;
        httpTempToPassCheckBackend->backendList=nullptr;
        //http->disconnectBackend();->generate cache corruption
        //delete http;-> generate crash
        http=nullptr;
        startNextPending();
        #ifdef DEBUGFASTCGI
        httpTempToPassCheckBackend->checkBackend();
        #endif
    }

    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " end of Backend::downloadFinished() http: " << http << std::endl;
    if(http==nullptr)
    {
        for( const auto &n : Backend::addressToHttp )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                {
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                    n.second->busy.erase(n.second->busy.cbegin()+index);
                    abort();
                }
                else
                    index++;
            }
        }
        for( const auto &n : Backend::addressToHttps )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                {
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                    n.second->busy.erase(n.second->busy.cbegin()+index);
                    abort();
                }
                else
                    index++;
            }
        }
        bool foundIntoIdle=false;
        for( const auto &n : Backend::addressToHttp )
        {
            unsigned int index=0;
            while(index<n.second->idle.size())
            {
                if(n.second->idle.at(index)==this)
                    foundIntoIdle=true;
                index++;
            }
        }
        for( const auto &n : Backend::addressToHttps )
        {
            unsigned int index=0;
            while(index<n.second->idle.size())
            {
                if(n.second->idle.at(index)==this)
                    foundIntoIdle=true;
                index++;
            }
        }
        if(!foundIntoIdle)
        {
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " http==nullptr and not found in idle (abort)" << std::endl;
            abort();
        }
    }
    else
    {
        bool foundIntoBusy=false;
        for( const auto &n : Backend::addressToHttp )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                    foundIntoBusy=true;
                index++;
            }
        }
        for( const auto &n : Backend::addressToHttps )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                    foundIntoBusy=true;
                index++;
            }
        }
        if(!foundIntoBusy)
        {
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " http==nullptr and not found in idle (abort)" << std::endl;
            abort();
        }
    }
    #endif
}

void Backend::startNextPending()
{
    startNextPendingInternal();
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
}

void Backend::startNextPendingInternal()
{
    if(backendList==nullptr)
        return;
    if(backendList->pending.empty())
        return;

    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Backend::startNextPending()" << std::endl;
    #endif
    bool haveFoundPending=false;
    bool haveUrlAndFrontendConnected=false;
    do
    {
        Http * httpToGet=backendList->pending.front();
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
        httpToGet->checkBackend();
        #endif

        #ifdef DEBUGFASTCGI
        if(Http::httpToDebug.find(httpToGet)==Http::httpToDebug.cend())
        {
            std::cerr << __FILE__ << ":" << __LINE__ << ", try get from backend: " << this << " the http already deleted: " << httpToGet << " (abort)" << std::endl;
            abort();
        }
        #endif
        backendList->pending.erase(backendList->pending.cbegin());
        httpToGet->pending=true;
        haveUrlAndFrontendConnected=httpToGet->haveUrlAndFrontendConnected();
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
        #endif
        if(haveUrlAndFrontendConnected)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << ", link backend: " << this << " with http " << httpToGet << " old: " << http << std::endl;
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            #endif
            http=httpToGet;
            #ifdef DEBUGFASTCGI
            //http->checkBackend();
            #endif
            http->backend=this;
            http->backendList=backendList;
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            #endif
            #ifdef DEBUGFASTCGI
            http->checkBackend();
            #endif
            http->readyToWrite();
            #ifdef DEBUGFASTCGI
            http->checkBackend();
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            #endif
            haveFoundPending=true;
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            httpToGet->checkBackend();
            #endif
            httpToGet->backendErrorAndDisconnect("Internal error, !haveUrlAndFrontendConnected");
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            #endif
            httpToGet->disconnectFrontend(false);
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            #endif
            httpToGet->disconnectBackend();
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " http: " << httpToGet << ": cachePath " << httpToGet->cachePath << " backend " << this << std::endl;
            #endif
            //delete httpToGet;
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << ", http buggy or without client, skipped http: " << httpToGet << " backend " << this << std::endl;
            #endif
        }
    } while(haveUrlAndFrontendConnected==false && !backendList->pending.empty());
    if(!haveFoundPending)
    {
        size_t index=0;
        while(index<backendList->busy.size())
        {
            if(backendList->busy.at(index)==this)
            {
                backendList->busy.erase(backendList->busy.cbegin()+index);
                break;
            }
            index++;
        }
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " " << " isValid: " << this->isValid() << " change from busy to idle" << std::endl;
        #endif
        if(this->isValid())
            backendList->idle.push_back(this);

        #ifdef DEBUGFASTCGI
        for( const auto &n : Backend::addressToHttp )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                {
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                    n.second->busy.erase(n.second->busy.cbegin()+index);
                    abort();
                }
                else
                    index++;
            }
        }
        for( const auto &n : Backend::addressToHttps )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                {
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                    n.second->busy.erase(n.second->busy.cbegin()+index);
                    abort();
                }
                else
                    index++;
            }
        }
        #endif
    }
    #ifdef DEBUGFASTCGI
    if(haveFoundPending)
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", found pending to do" << std::endl;
    else
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", NO pending to do" << std::endl;
    #endif
}

Backend * Backend::tryConnectInternalList(const sockaddr_in6 &s,Http *http,std::unordered_map<std::string,BackendList *> &addressToList,bool &connectInternal,Backend::BackendList ** backendList)
{
    #ifdef DEBUGFASTCGI
    std::cerr << "Backend::tryConnectInternalList " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    connectInternal=true;
    std::string addr((char *)&s.sin6_addr,16);
    //if have already connected backend on this ip
    if(addressToList.find(addr)!=addressToList.cend())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Backend::tryConnectInternalList " << __FILE__ << ":" << __LINE__ << " IP to connect is found into connected IP" << std::endl;
        #endif
        BackendList *list=addressToList[addr];
        *backendList=list;
        if(!list->idle.empty())
        {
            //assign to idle backend and become busy
            Backend *backend=list->idle.back();
            list->idle.pop_back();
            list->busy.push_back(backend);
            backend->http=http;
            #ifdef DEBUGFASTCGI
            std::cerr << http << ": http->backend=" << backend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << backend->isValid() << std::endl;
            #endif
            http->backend=backend;
            http->backendList=list;
            http->readyToWrite();
            #ifdef DEBUGFASTCGI
            http->checkBackend();
            if(http->backendList==nullptr)
            {
                std::cerr << "Backend::tryConnectInternalList() can't return " << backend << " without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
            #endif
            return backend;
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "Backend::tryConnectInternalList  " << __FILE__ << ":" << __LINE__ << " no more idle worker" << std::endl;
            #endif
            if(list->busy.size()<Backend::maxBackend)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << http << ": http->backend=in progress " << __FILE__ << ":" << __LINE__ << " if " << std::to_string(list->busy.size()) << "<" << std::to_string(Backend::maxBackend) << " then try create new connection" << std::endl;
                #endif
                Backend *newBackend=new Backend(list);
                http->backendList=list;
                if(!newBackend->tryConnectInternal(s))
                {
                    connectInternal=false;
                    #ifdef DEBUGFASTCGI
                    std::cerr << http << ": return nullptr; " << __FILE__ << ":" << __LINE__ << " if " << std::to_string(list->busy.size()) << "<" << std::to_string(Backend::maxBackend) << " new connection failed" << std::endl;
                    if(http->backendList==nullptr)
                    {
                        std::cerr << "Backend::tryConnectInternalList() can't return nullptr without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                        abort();
                    }
                    #endif
                    return nullptr;
                }
                newBackend->http=http;
                #ifdef DEBUGFASTCGI
                std::cerr << http << ": http->backend=" << newBackend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << newBackend->isValid() << " if " << std::to_string(list->busy.size()) << "<" << std::to_string(Backend::maxBackend) << " new connection success" << std::endl;
                #endif
                http->backend=newBackend;

                list->busy.push_back(newBackend);
                #ifdef DEBUGFASTCGI
                http->checkBackend();
                if(http->backendList==nullptr)
                {
                    std::cerr << "Backend::tryConnectInternalList() can't return " << newBackend << " without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                    abort();
                }
                #endif
                return newBackend;
            }
            else
            {
                http->backendList=list;
                http->pending=true;
                list->pending.push_back(http);
                #ifdef DEBUGFASTCGI
                //list busy
                std::cerr << "backend busy on: ";
                int index=0;
                for(const Backend *b : list->busy)
                {
                    if(index>0)
                        std::cerr << ", ";
                    if(b==nullptr)
                        std::cerr << "no backend";
                    else if(b->http==nullptr)
                        std::cerr << "backend: " << (void *)b << " no http";
                    else
                        std::cerr << "backend: " << (void *)b << " http: " << (void *)http << " url: " << b->http->getUrl();
                    index++;
                }
                std::cerr << std::endl;
                if(http->backendList==nullptr)
                {
                    std::cerr << "Backend::tryConnectInternalList() can't return nullptr without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                    abort();
                }
                #endif
                return nullptr;
            }
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Backend::tryConnectInternalList  " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        BackendList *list=new BackendList();
        *backendList=list;
        memcpy(&list->s,&s,sizeof(sockaddr_in6));

        http->backendList=list;
        Backend *newBackend=new Backend(list);
        if(!newBackend->tryConnectInternal(s))
        {
            connectInternal=false;
            #ifdef DEBUGFASTCGI
            std::cerr << http << ": return nullptr; " << __FILE__ << ":" << __LINE__ << " list->busy.size(): " << std::to_string(list->busy.size()) << " Backend::maxBackend: " << std::to_string(Backend::maxBackend) << std::endl;
            if(http->backendList==nullptr)
            {
                std::cerr << "Backend::tryConnectInternalList() can't return nullptr without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
            #endif
            return nullptr;
        }
        newBackend->http=http;
        #ifdef DEBUGFASTCGI
        {
            std::string host="Unknown IPv6";
            char str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &addr, str, INET6_ADDRSTRLEN) != NULL)
                host=str;
            std::cerr << http << ": http->backend=" << newBackend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << newBackend->isValid() << " " << host << std::endl;
        }
        #endif
        http->backend=newBackend;
        http->backendList=list;

        list->busy.push_back(newBackend);
        addressToList[addr]=list;
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        if(http->backendList==nullptr)
        {
            std::cerr << "Backend::tryConnectInternalList() can't return " << newBackend << " without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
            abort();
        }
        #endif
        return newBackend;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << http << ": http->backend out of condition" << std::endl;
    if(http->backendList==nullptr)
    {
        std::cerr << "Backend::tryConnectInternalList() can't return nullptr without set backendList " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
        abort();
    }
    #endif
    return nullptr;
}

Backend * Backend::tryConnectHttp(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList)
{
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    Backend * t=tryConnectInternalList(s,http,addressToHttp,connectInternal,backendList);
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    return t;
}

void Backend::startHttps()
{
    if(ssl!=nullptr)
    {
        std::cerr << "[" << Common::msFrom1970() << "] " << "Backend::startHttps(): ssl!=nullptr at start, http: " << http << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << "[" << Common::msFrom1970() << "] " << "Backend::startHttps(): " << this << " isValid: " << isValid() << " http: " << http << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif

    /* ------------------------------------- */
    ctx = SSL_CTX_new(meth);
    if (ctx==nullptr)
    {
        std::cerr << "ctx = SSL_CTX_new(meth); return NULL" << std::endl;
        //work around, infinity loop, if https and ssl==nullptr -> call again startHttps()
        https=false;
        return;
    }

    /* ---------------------------------------------------------------- */
    /* Cipher AES128-GCM-SHA256 and AES256-GCM-SHA384 - good performance with AES-NI support. */
    if (!SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256")) {
        printf("Could not set cipher list");
        return;
    }
    /* ------------------------------- */
    /* Configure certificates and keys */
    if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
        printf("Could not disable compression");
        return;
    }
/*    if (SSL_CTX_load_verify_locations(ctx, CERTF, 0) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        printf("Could not load cert file: ");
        ERR_print_errors_fp(stderr);
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        printf("Could not load key file");
        ERR_print_errors_fp(stderr);
        return;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,
                "Private key does not match public key in certificate.\n");
        return;
    }*/
    /* Enable client certificate verification. Enable before accepting connections. */
    /*SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
    SSL_VERIFY_CLIENT_ONCE, 0);*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    /* Start SSL negotiation, connection available. */
    ssl = SSL_new(ctx);
    if (ssl==nullptr)
    {
        std::cerr << "SSL_new(ctx); return NULL" << std::endl;
        return;
    }

    if(!SSL_set_fd(ssl, fd))
    {
        std::cerr << "SSL_set_fd failed" << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        closeSSL();
        #if defined(DEBUGFILEOPEN)
        std::cerr << "Backend::startHttps(), fd: " << fd << ", err == SSL_ERROR_ZERO_RETURN" << std::endl;
        #endif
        Cache::unregisterCacheFD(fd);
        #ifdef DEBUGFASTCGI
        std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        if(fd!=-1)
            ::close(fd);
        fd=-1;
        return;
    }
    SSL_set_connect_state(ssl);

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    //for(int i=0;i<99999;i++) -> then generate bug
    for(;;)
    {
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(end - begin).count()>10)
        {
            std::cerr << "SSL_connect backend: timeout" << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            closeSSL();
            #if defined(DEBUGFILEOPEN)
            std::cerr << "Backend::startHttps(), fd: " << fd << ", err == SSL_ERROR_ZERO_RETURN" << std::endl;
            #endif
            Cache::unregisterCacheFD(fd);
            #ifdef DEBUGFASTCGI
            std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            if(fd!=-1)
                ::close(fd);
            fd=-1;
            return;
        }
        int success = SSL_connect(ssl);

        if(success < 0) // The TLS/SSL handshake was not successful, because a fatal error occurred either at the protocol level or a connection failure occurred. The shutdown was not clean. It can also occur of action is need to continue the operation for non-blocking BIOs. Call SSL_get_error() with the return value ret to find out the reason.
        {
            int err = SSL_get_error(ssl, success);

            /* Non-blocking operation did not complete. Try again later. */
            /// \todo do it in async way via event loop
            if (err == SSL_ERROR_WANT_READ)
                continue;
            else if (err == SSL_ERROR_WANT_WRITE)
                continue;
            else if (err == SSL_ERROR_WANT_X509_LOOKUP)
                continue;
            else if(err == SSL_ERROR_ZERO_RETURN)
            {
                std::cerr << "SSL_connect: close notify received from peer" << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                closeSSL();
                #if defined(DEBUGFILEOPEN)
                std::cerr << "Backend::startHttps(), fd: " << fd << ", err == SSL_ERROR_ZERO_RETURN" << std::endl;
                #endif
                Cache::unregisterCacheFD(fd);
                #ifdef DEBUGFASTCGI
                std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(fd!=-1)
                    ::close(fd);
                fd=-1;
                return;
            }
            else
            {
                std::cerr << "Backend::startHttps() Error SSL_connect: " << err << ", errno: " << errno;
                if(http!=nullptr)
                    std::cerr << " url: " << http->getUrl();
                std::cerr << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                closeSSL();
                #if defined(DEBUGFILEOPEN)
                std::cerr << "Backend::startHttps(), fd: " << fd << std::endl;
                #endif
                if(fd!=-1)
                {
                    Cache::unregisterCacheFD(fd);
                    ::close(fd);
                }
                fd=-1;
                return;
            }
        }
        else if(success == 0) // The TLS/SSL handshake was not successful but was shut down controlled and by the specifications of the TLS/SSL protocol. Call SSL_get_error() with the return value ret to find out the reason.
        {
            #ifdef DEBUGHTTPS
            dump_cert_info(ssl, false);
            #else
                #ifdef DEBUGFASTCGI
                int ret=0;
                int ret2=SSL_get_error(ssl,ret);
                std::cerr << "problem with certificate " << ret << " " << ret2 << std::endl;
                #endif
            #endif
            break;
        }
        else // The TLS/SSL handshake was successfully completed, a TLS/SSL connection has been established.
            break;
    }
}

Backend * Backend::tryConnectHttps(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList)
{
    return tryConnectInternalList(s,http,addressToHttps,connectInternal,backendList);
}

#ifdef DEBUGHTTPS
void Backend::dump_cert_info(SSL *ssl, bool server)
{
    if(server) {
        printf("Ssl server version: %s", SSL_get_version(ssl));
    }
    else {
        printf("Client Version: %s", SSL_get_version(ssl));
    }

    /* The cipher negotiated and being used */
    printf("Using cipher %s", SSL_get_cipher(ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        if(server) {
        printf("Client certificate:\n");
        }
        else {
            printf("Server certificate:\n");
        }
        char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        if(str == NULL) {
            printf("warn X509 subject name is null");
        }
        printf("\t Subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        if(str == NULL) {
            printf("warn X509 issuer name is null");
        }
        printf("\t Issuer: %s\n", str);
        OPENSSL_free(str);

        /* Deallocate certificate, free memory */
        X509_free(client_cert);
    } else {
        printf("Client does not have certificate.\n");
    }
}
#endif

bool Backend::tryConnectInternal(const sockaddr_in6 &s)
{
    /* --------------------------------------------- */
    /* Create a normal socket and connect to server. */

    lastActivitymsTimestamps=Common::msFrom1970();
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if(fd==-1)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << http << ": socket(AF_INET6, SOCK_STREAM, 0)==-1 " << __FILE__ << ":" << __LINE__ << " Unable to create socket: errno: " << errno << std::endl;
        #endif
        std::cerr << "Unable to create socket, errno: " << errno << std::endl;
        return false;
    }
    Cache::newFD(fd,this,EpollObject::Kind::Kind_Backend);

    char astring[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(s.sin6_addr), astring, INET6_ADDRSTRLEN);
    #ifdef DEBUGFASTCGI
    if(std::string(astring)=="::")
    {
        #ifdef DEBUGFASTCGI
        std::cerr << http << ": try connect on :: " << __FILE__ << ":" << __LINE__ << " Unable to create socket: errno: " << errno << std::endl;
        #endif
        std::cerr << "Internal error, try connect on ::, errno: " << errno << std::endl;
        return false;
    }
    /*printf("Try connect on %s %i\n", astring, be16toh(s.sin6_port));
    std::cerr << std::endl;
    std::cout << std::endl;*/
    #endif
    https=(s.sin6_port==https_portBE);

    // non-blocking client socket
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            std::cerr << "fcntl(fd, F_GETFL, 0); return < 0" << std::endl;
            //return false;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    // no delay
    {
        int flag = 1;
        setsockopt(fd,            /* socket affected */
        IPPROTO_TCP,     /* set option at TCP level */
        TCP_NODELAY,     /* name of option */
        (char *) &flag,  /* the cast is historical
        cruft */
        sizeof(int));
    }

    // ---------------------

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLERR | EPOLLHUP | EPOLLRDHUP;// | EPOLLONESHOT: broke
    #ifdef DEBUGFASTCGI
    std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    int t = epoll_ctl(EpollObject::epollfd, EPOLL_CTL_ADD, fd, &event);
    if (t == -1) {
        std::cerr << "epoll_ctl(EpollObject::epollfd, EPOLL_CTL_ADD, fd, &event); return -1" << std::endl;
        #ifdef DEBUGFASTCGI
        std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        if(fd!=-1)
        {
            Cache::unregisterCacheFD(fd);
            ::close(fd);
        }
        fd=-1;
        #ifdef DEBUGFASTCGI
        std::cerr << http << ": epoll_ctl()==-1 " << __FILE__ << ":" << __LINE__ << " Unable to create socket: errno: " << errno << std::endl;
        #endif
        return false;
    }

    /*sockaddr_in6 targetDnsIPv6;
    targetDnsIPv6.sin6_port = htobe16(53);
    const char * const hostC=host.c_str();
    int convertResult=inet_pton(AF_INET6,hostC,&targetDnsIPv6.sin6_addr);*/
    int err = connect(fd, (struct sockaddr*) &s, sizeof(s));
    if (err < 0 && errno != EINPROGRESS)
    {
        std::cerr << "connect != EINPROGRESS" << std::endl;
        #ifdef DEBUGFASTCGI
        std::cerr << http << ": connect != EINPROGRESS " << __FILE__ << ":" << __LINE__ << " Unable to create socket: errno: " << errno << std::endl;
        #endif
        return false;
    }
    return true;
}

void Backend::parseEvent(const epoll_event &event)
{
    //std::cout << "Backend Epoll: " << event.events << std::endl;
    #ifdef DEBUGFASTCGI
    if(event.events & ~EPOLLOUT & ~EPOLLIN)
        std::cout << this << " Backend::parseEvent event.events: " << event.events << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    Http *oldhttp=this->http;
    #endif

    //workaround just in case have more read to do
    if(http!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        if(http->backend!=this)
        {
            std::cerr << this << " http: " << http << " " << __FILE__ << ":" << __LINE__ << " http and backend not match (abort)" << std::endl;
            abort();
        }
        if(http->backendList!=backendList)
        {
            std::cerr << this << " http: " << http << " " << __FILE__ << ":" << __LINE__ << " http and backend not match (abort)" << std::endl;
            abort();
        }
        #endif
        #ifdef DEBUGFASTCGI
        std::cerr << this << " Backend just try read: " << http << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        http->readyToRead();
        #ifdef DEBUGFASTCGI
        std::cerr << this << " Backend end try read: " << http << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    }

    if(event.events & EPOLLIN)
    {
        #ifdef DEBUGFASTCGI
        std::cout << this << " Backend EPOLLIN" << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        if(http!=nullptr)
            http->readyToRead();
        else
        {
            char buffer[1024*1024];
            int size=Backend::socketRead(buffer,sizeof(buffer));
            while(size>0)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << this << " ERROR Received data while not connected to http backend, fd: " << fd << " " << __FILE__ << ":" << __LINE__ << " data: " << Common::binarytoHexa(buffer,size) << std::endl;
                #endif
                size=Backend::socketRead(buffer,sizeof(buffer));
            }
            //prevent reuse this backend, because http seam don't have consumed all the input
            /// \todo fix it better, the http need always consume ALL the data!
            close();
        }
    }
    if(event.events & EPOLLOUT)
    {
        #ifdef DEBUGFASTCGI
        std::cout << this << " Backend EPOLLOUT" << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        if(ssl==nullptr && https && isValid())
            startHttps();
        if(http!=nullptr)
            http->readyToWrite();
    }

    if(event.events & EPOLLHUP)
    {
        #ifdef DEBUGFASTCGI
        std::cout << "Backend EPOLLHUP" << std::endl;
        #endif
        remoteSocketClosed();
        //do client reject
    }
    if(event.events & EPOLLRDHUP)
    {
        #ifdef DEBUGFASTCGI
        std::cout << "Backend EPOLLRDHUP" << std::endl;
        #endif
        remoteSocketClosed();
    }
    if(event.events & EPOLLET)
    {
        #ifdef DEBUGFASTCGI
        std::cout << "Backend EPOLLET" << std::endl;
        #endif
        remoteSocketClosed();
    }
    if(event.events & EPOLLERR)
    {
        #ifdef DEBUGFASTCGI
        std::cout << "Backend EPOLLERR" << std::endl;
        #endif
        remoteSocketClosed();
    }

    #ifdef DEBUGFASTCGI
    if(oldhttp!=nullptr && oldhttp!=http)
    {
        if(oldhttp->backend==this)
        {
            std::cerr << this << " http: " << http << " " << __FILE__ << ":" << __LINE__ << " http and backend match after change (abort)" << std::endl;
            abort();
        }
        if(oldhttp->backendList!=nullptr && oldhttp->backend==this)
        {
            unsigned int index=0;
            while(index<oldhttp->backendList->pending.size())
            {
                if(oldhttp->backendList->pending.at(index)==oldhttp)
                    break;
                index++;
            }
            if(index>=oldhttp->backendList->pending.size())
            {
                std::cerr << this << " http: " << http << " " << __FILE__ << ":" << __LINE__ << " backendList!=nullptr but not found into pendding (abort)" << std::endl;
                abort();
            }
        }
    }
    #endif
}

void Backend::readyToWrite()
{
    if(bufferSocket.empty())
        return;
    if(fd==-1)
        return;
    const ssize_t &sizeW=::write(fd,bufferSocket.data(),bufferSocket.size());
    if(sizeW>=0)
    {
        if((size_t)sizeW<bufferSocket.size())
            this->bufferSocket.erase(0,bufferSocket.size()-sizeW);
        else
            this->bufferSocket.clear();
    }
}

ssize_t Backend::socketRead(void *buffer, size_t size)
{
    #ifdef DEBUGFASTCGI
    //std::cout << "Socket try read" << std::endl;
    if(http==nullptr)
    {
        for( const auto &n : Backend::addressToHttp )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                {
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                    abort();
                }
                else
                    index++;
            }
            index=0;
        }
        for( const auto &n : Backend::addressToHttps )
        {
            unsigned int index=0;
            while(index<n.second->busy.size())
            {
                if(n.second->busy.at(index)==this)
                {
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred (abort)" << std::endl;
                    abort();
                }
                else
                    index++;
            }
        }
        std::cerr << this << " " << "socketRead() when no http set" << " " << __FILE__ << ":" << __LINE__ << std::endl;
        errno=0;
        return -1;
    }
    #endif
    if(fd<0)
    {
        errno=0;
        return -1;
    }
    if(ssl!=nullptr)
    {
        int readen = SSL_read(ssl, buffer, size);
        if (readen<0)
        {
            if(errno!=11)
                std::cerr << this << " " << "SSL_read return -1 with errno " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return -1;
        }
        /*#ifdef DEBUGFASTCGI
        std::cout << "Socket byte read: " << readen << std::endl;
        std::cerr << "Client Received " << readen << " chars - '" << std::string((char *)buffer,readen) << "'" << std::endl;
        #endif*/

        if (readen <= 0) {
            if(readen == SSL_ERROR_WANT_READ ||
                readen == SSL_ERROR_WANT_WRITE ||
                readen == SSL_ERROR_WANT_X509_LOOKUP) {
                std::cerr << this << " " << "Read could not complete. Will be invoked later." << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return -1;
            }
            else if(readen == SSL_ERROR_ZERO_RETURN) {
                std::cerr << this << " " << "SSL_read: close notify received from peer" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return -1;
            }
            else {
                #ifdef DEBUGFASTCGI
                std::cerr << this << " " << "Error during SSL_read" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                return -1;
            }
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << "Error during SSL_read bis" << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            return -1;
        }
        else
        {
            lastActivitymsTimestamps=Common::msFrom1970();
            return readen;
        }
    }
    else
    {
        const ssize_t &s=::read(fd,buffer,size);
        /*#ifdef DEBUGFASTCGI
        std::cout << "Socket byte read: " << s << std::endl;
        #endif*/
        if(s>0)
            lastActivitymsTimestamps=Common::msFrom1970();
        return s;
    }
}

bool Backend::socketWrite(const void *buffer, size_t size)
{
    lastActivitymsTimestamps=Common::msFrom1970();
    #ifdef DEBUGFASTCGI
    std::cout << this << " " << "Try socket write: " << size << " " << __FILE__ << ":" << __LINE__ << std::endl;
    if(http==nullptr)
    {
        std::cerr << this << " " << "socketRead() when no http set" << " " << __FILE__ << ":" << __LINE__ << std::endl;
        errno=0;
        return false;
    }
    #endif
    if(fd<0)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << "Backend::socketWrite() fd<0" << std::endl;
        #endif
        return false;
    }
    if(!this->bufferSocket.empty())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << "Backend::socketWrite() !this->bufferSocket.empty()" << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        this->bufferSocket+=std::string((char *)buffer,size);
        return true;
    }
    ssize_t sizeW=-1;
    if(ssl!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cout << this << " " << "Try SSL socket write: " << size << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        #ifdef DEBUGFASTCGI
        //std::cerr << "Client Send " << size << " chars - '" << std::string((char *)buffer,size) << "'" << std::endl;
        #endif
        int writenSize = SSL_write(ssl, buffer,size);
        if (writenSize <= 0) {
            if(writenSize == SSL_ERROR_WANT_READ ||
                writenSize == SSL_ERROR_WANT_WRITE ||
                writenSize == SSL_ERROR_WANT_X509_LOOKUP) {
                std::cerr << this << " SSL_write(ssl, buffer,size); return -1 Write could not complete. Will be invoked later., errno " << errno << " fd: " << getFD() << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return false;
            }
            else if(writenSize == SSL_ERROR_ZERO_RETURN) {
                std::cerr << this << " SSL_write(ssl, buffer,size); return -1 close notify received from peer, errno " << errno << " fd: " << getFD() << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return false;
            }
            else {
                std::cerr << this << " SSL_write(ssl, buffer,size); return -1, errno " << errno << " fd: " << getFD() << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return false;
            }
        }
        else
            sizeW=writenSize;
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cout << this << " " << "Try socket write: " << size << std::endl;
        #endif
        if(fd!=-1)
            sizeW=::write(fd,buffer,size);
        else
            sizeW=0;
    }
    #ifdef DEBUGFASTCGI
    std::cout << "Socket Writed bytes: " << size << std::endl;
    #endif
    if(sizeW>=0)
    {
        if((size_t)sizeW<size)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << "sizeW only: " << sizeW << std::endl;
            #endif
            this->bufferSocket+=std::string((char *)buffer+sizeW,size-sizeW);
        }
        return true;
    }
    else
    {
        if(errno!=32)//if not broken pipe
            std::cerr << this << " " << "Http socket errno:" << errno << std::endl;
        return false;
    }
}

bool Backend::detectTimeout()
{
    //if no http then idle, no data, skip detect timeout
    if(http==nullptr)
        return false;
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " backend: " << this << " http: " << http << std::endl;//too many time
        #endif
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif
    }
    if(http->get_status()==Http::Status_WaitDns)
        return false;
    const uint64_t var_msFrom1970=Common::msFrom1970();
    if(lastActivitymsTimestamps>(var_msFrom1970-5*1000))
    {
        //prevent time drift
        if(lastActivitymsTimestamps>var_msFrom1970)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << "lastReceivedBytesmsTimestamps>var_msFrom1970: " << lastActivitymsTimestamps << ">" << var_msFrom1970 << " time drift fixed WARNING" << std::endl;
            #endif
            lastActivitymsTimestamps=var_msFrom1970;
        }
        return false;
    }
    //if no byte received into 5s
    #ifdef DEBUGFASTCGI
    struct timeval tv;
    gettimeofday(&tv,NULL);
    std::cerr << "[" << tv.tv_sec << "] ";
    #endif
    std::cerr << "Backend::detectTimeout() timeout while downloading " << http->getUrl() << " from " << http << " (backend " << this << "): " << var_msFrom1970 << "<" << (var_msFrom1970-5*1000) << " (" << var_msFrom1970 << "-5*1000)"
              << " http->get_status(): " << (int)http->get_status() << " http->get_requestSended(): " << http->get_requestSended() << std::endl;
    close();//before http to prevent re-use as retry backend
    /* seam duplicate with remoteSocketClosed() if(http!=nullptr)
    {
        http->backendError("Timeout");
        http->disconnectFrontend(true);
        http->disconnectBackend();
    }*/
    remoteSocketClosed();//else backend is into busy and bug all
    //abort();
    return true;
}

std::string Backend::getQuery() const
{
    std::string ret;
    char buffer[32];
    std::snprintf(buffer,sizeof(buffer),"%p",(void *)this);
    ret+=std::string(buffer)+" ";
    if(http==nullptr)
        ret+="not alive";
    else
        ret+="alive on "+http->getUrl()+" "+std::to_string((uint64_t)http);
    ret+=" last byte "+std::to_string(lastActivitymsTimestamps);
    ret+=" downloadFinishedCount "+std::to_string(downloadFinishedCount);
    if(wasTCPConnected)
        ret+=" wasTCPConnected";
    else
        ret+=" !wasTCPConnected";
    return ret;
}
#endif

unsigned int Backend::get_downloadFinishedCount() const
{
    return downloadFinishedCount;
}

#ifdef DEBUGFASTCGI
void Backend::checkBackend()
{
    for( const auto &n : Backend::addressToHttp )
    {
        for( Backend * p : n.second->busy )
        {
            if(p->http==nullptr)
            {
                std::cerr << p << " backend is in busy but http is null, if downloadFinished() then should return to idle, else destroy " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
        }
        for( Backend * p : n.second->idle )
        {
            if(p->http!=nullptr)
            {
                std::cerr << p << " backend is in idle but http is not null http: " << p->http << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
        }
        if(!n.second->pending.empty())
        {
            if(!n.second->idle.empty())
            {
                std::cerr << " !n.second->pending.empty() && !n.second->idle.empty() " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
            if(n.second->busy.size()<Backend::maxBackend)
            {
                std::cerr << " !n.second->pending.empty() && n.second->busy.size()<Backend::maxBackend " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
        }
    }
    for( const auto &n : Backend::addressToHttps )
    {
        for( Backend * p : n.second->busy )
        {
            if(p->http==nullptr)
            {
                std::cerr << p << " backend is in busy but http is null, if downloadFinished() then should return to idle, else destroy " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
        }
        for( Backend * p : n.second->idle )
        {
            if(p->http!=nullptr)
            {
                std::cerr << p << " backend is in idle but http is not null http: " << p->http << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
        }
        if(!n.second->pending.empty())
        {
            if(!n.second->idle.empty())
            {
                std::cerr << " !n.second->pending.empty() && !n.second->idle.empty() " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
            if(n.second->busy.size()<Backend::maxBackend)
            {
                std::cerr << " !n.second->pending.empty() && n.second->busy.size()<Backend::maxBackend " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
        }
    }
}
#endif
