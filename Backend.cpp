#ifndef CURL
#include "Backend.hpp"
#include "Http.hpp"
#include "Cache.hpp"
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

#ifdef DEBUGFASTCGI
std::unordered_set<Backend *> Backend::toDebug;
#endif

uint16_t Backend::https_portBE=0;
const SSL_METHOD *Backend::meth=nullptr;

Backend::Backend(BackendList * backendList) :
    http(nullptr),
    https(false),
    wasTCPConnected(false),
    lastReceivedBytesTimestamps(0),
    backendList(backendList),
    ctx(nullptr),
    ssl(nullptr)
{
    #ifdef DEBUGFASTCGI
    toDebug.insert(this);
    #endif
    lastReceivedBytesTimestamps=Backend::currentTime();
    this->kind=EpollObject::Kind::Kind_Backend;
}

Backend::~Backend()
{
    #ifdef DEBUGFASTCGI
    if(toDebug.find(this)!=toDebug.cend())
        toDebug.erase(this);
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
        Cache::closeFD(fd);
        if(epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL)==-1)
            std::cerr << "EPOLL_CTL_DEL Http: " << fd << ", errno: " << errno << std::endl;
    }
    if(http!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << ": http->backend=nullptr; (destructor), http: " << http << std::endl;
        #endif
        http->backend=nullptr;
        http->backendList=nullptr;
        /*should abort here, just skip the error for now
         * When The remote server have close the connexion */
        http->backendError("Backend descrutor called when remain http connected (abort)");
        http->disconnectFrontend(false);
        http=nullptr;
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

void Backend::close()
{
    #ifdef DEBUGFASTCGI
    std::cerr << "Backend::close() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    if(fd!=-1)
    {
        Cache::closeFD(fd);
        epoll_ctl(epollfd,EPOLL_CTL_DEL, fd, NULL);
        #ifdef DEBUGFASTCGI
        std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        ::close(fd);
        //prevent multiple loop call
        fd=-1;
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
        Cache::closeFD(fd);
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
                const std::string error("Tcp connect problem");
                size_t index=0;
                while(index<backendList->pending.size())
                {
                    Http *http=backendList->pending.at(index);
                    http->backendError(error);//drop from list, then delete http
                    http->disconnectFrontend(true);
                    http->disconnectBackend();
                    index++;
                }
            }
            if(http!=nullptr)
            {
                http->backend=nullptr;
                http->backendList=nullptr;
            }
            #ifdef DEBUGFASTCGI
            std::cerr << "remoteSocketClosed and was NOT TCP connected " << __FILE__ << ":" << __LINE__ << std::endl;
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
                        http->requestSended=false;
                        //reassign to idle backend
                        if(!backendList->idle.empty())
                        {
                            //assign to idle backend and become busy
                            Backend *backend=backendList->idle.back();
                            backendList->idle.pop_back();
                            backendList->busy.push_back(backend);
                            backend->http=http;
                            #ifdef DEBUGFASTCGI
                            std::cerr << http << ": http->backend=" << backend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << backend->isValid() << std::endl;
                            #endif
                            http->backend=backend;
                            http->backendList=backendList;
                            http->readyToWrite();
                            #ifdef DEBUGFASTCGI
                            http->checkBackend();
                            #endif
                        }
                        //reassign to new backend
                        else
                        {
                            Backend *newBackend=new Backend(backendList);
                            if(!newBackend->tryConnectInternal(backendList->s))
                                //todo abort client
                                return;
                            newBackend->http=http;
                            #ifdef DEBUGFASTCGI
                            std::cerr << http << ": http->backend=" << newBackend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << newBackend->isValid() << std::endl;
                            #endif
                            http->backend=newBackend;
                            http->backendList=backendList;

                            backendList->busy.push_back(newBackend);
                            #ifdef DEBUGFASTCGI
                            http->checkBackend();
                            #endif
                        }
                        http=nullptr;
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
}

void Backend::downloadFinished()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " http " << http << " is finished, should be destruct" << std::endl;
    if(http==nullptr)
        std::cerr << __FILE__ << ":" << __LINE__ << "Backend::downloadFinished() http==nullptr bug suspected" << std::endl;
    #endif
    if(backendList==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " http " << http << " backendList==nullptr return" << std::endl;
        #endif
        http=nullptr;
        return;
    }
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
        const std::string error("Tcp connect problem");
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
        }
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << "Backend::downloadFinished() NOT TRY AGAIN" << std::endl;
        #endif
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif
        http->backend=nullptr;
        http->backendList=nullptr;
        http->backendError(error);//disconnect client like http->disconnectFrontend();
        //http->disconnectBackend();
        //delete http;
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif
        http=nullptr;
        close();
        remoteSocketClosed();
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

        //try 30/06/2021
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif
        http->disconnectFrontend(false);
        //http->disconnectBackend();
        http->backend=nullptr;
        http->backendList=nullptr;
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif

        //http->disconnectBackend();->generate cache corruption
        //delete http;
        http=nullptr;
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
        std::cerr << http << ": http->backend=null and !backendList->pending.empty() cachePath " << http->cachePath << std::endl;
        #endif
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif
        http->backend=nullptr;
        http->backendList=nullptr;
        //http->disconnectBackend();->generate cache corruption
        //delete http;-> generate crash
        http=nullptr;
        bool haveFound=false;
        bool haveUrlAndFrontendConnected=false;
        do
        {
            Http * httpToGet=backendList->pending.front();
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
            #endif

            #ifdef DEBUGFASTCGI
            if(Http::toDebug.find(httpToGet)==Http::toDebug.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << ", try get from backend: " << this << " the http already deleted: " << httpToGet << " (abort)" << std::endl;
                abort();
            }
            #endif
            backendList->pending.erase(backendList->pending.cbegin());
            httpToGet->pending=true;
            haveUrlAndFrontendConnected=httpToGet->haveUrlAndFrontendConnected();
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
            #endif
            if(haveUrlAndFrontendConnected)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << ", link backend: " << this << " with http " << httpToGet << " old: " << http << std::endl;
                #endif
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                http=httpToGet;
                #ifdef DEBUGFASTCGI
                //http->checkBackend();
                #endif
                http->backend=this;
                http->backendList=backendList;
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                #ifdef DEBUGFASTCGI
                http->checkBackend();
                #endif
                http->readyToWrite();
                #ifdef DEBUGFASTCGI
                http->checkBackend();
                #endif
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                haveFound=true;
            }
            else
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                httpToGet->backendError("Internal error, !haveUrlAndFrontendConnected");
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                httpToGet->disconnectFrontend(false);
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                httpToGet->disconnectBackend();
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << httpToGet << ": cachePath " << httpToGet->cachePath << std::endl;
                #endif
                //delete httpToGet;
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << ", http buggy or without client, skipped: " << httpToGet << std::endl;
                #endif
            }
        } while(haveUrlAndFrontendConnected==false && !backendList->pending.empty());
        if(!haveFound)
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
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " " << " isValid: " << this->isValid() << std::endl;
            #endif
            if(this->isValid())
                backendList->idle.push_back(this);
        }
        #ifdef DEBUGFASTCGI
        if(haveFound)
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", found pending to do" << std::endl;
        else
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", NO pending to do" << std::endl;
        #endif

    }
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
}

Backend * Backend::tryConnectInternalList(const sockaddr_in6 &s,Http *http,std::unordered_map<std::string,BackendList *> &addressToList,bool &connectInternal,Backend::BackendList ** backendList)
{
    connectInternal=true;
    std::string addr((char *)&s.sin6_addr,16);
    //if have already connected backend on this ip
    if(addressToList.find(addr)!=addressToList.cend())
    {
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
            #endif
            return backend;
        }
        else
        {
            if(list->busy.size()<Backend::maxBackend)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << http << ": http->backend=in progress " << __FILE__ << ":" << __LINE__ << " if " << std::to_string(list->busy.size()) << "<" << std::to_string(Backend::maxBackend) << std::endl;
                #endif
                Backend *newBackend=new Backend(list);
                if(!newBackend->tryConnectInternal(s))
                {
                    connectInternal=false;
                    return nullptr;
                }
                newBackend->http=http;
                #ifdef DEBUGFASTCGI
                std::cerr << http << ": http->backend=" << newBackend << " " << __FILE__ << ":" << __LINE__ << " isValid: " << newBackend->isValid() << " if " << std::to_string(list->busy.size()) << "<" << std::to_string(Backend::maxBackend) << std::endl;
                #endif
                http->backend=newBackend;
                http->backendList=list;

                list->busy.push_back(newBackend);
                #ifdef DEBUGFASTCGI
                http->checkBackend();
                #endif
                return newBackend;
            }
            else
            {
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
                        std::cerr << "no http";
                    else
                        std::cerr << (void *)b << " " << (void *)http << " url: " << b->http->getUrl();
                    index++;
                }
                std::cerr << std::endl;
                #endif
                return nullptr;
            }
        }
    }
    else
    {
        BackendList *list=new BackendList();
        *backendList=list;
        memcpy(&list->s,&s,sizeof(sockaddr_in6));

        Backend *newBackend=new Backend(list);
        if(!newBackend->tryConnectInternal(s))
        {
            connectInternal=false;
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
        #endif
        return newBackend;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << http << ": http->backend out of condition" << std::endl;
    #endif
    return nullptr;
}

Backend * Backend::tryConnectHttp(const sockaddr_in6 &s,Http *http, bool &connectInternal,Backend::BackendList ** backendList)
{
    return tryConnectInternalList(s,http,addressToHttp,connectInternal,backendList);
}

void Backend::startHttps()
{
    if(ssl!=nullptr)
    {
        std::cerr << "Backend::startHttps(): ssl!=nullptr at start" << std::endl;
        return;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << "Backend::startHttps(): " << this << std::endl;
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
        printf("SSL_set_fd failed");
        closeSSL();
        #if defined(DEBUGFILEOPEN)
        std::cerr << "Backend::startHttps(), fd: " << fd << ", err == SSL_ERROR_ZERO_RETURN" << std::endl;
        #endif
        Cache::closeFD(fd);
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
            printf("SSL_connect backend: timeout");
            closeSSL();
            #if defined(DEBUGFILEOPEN)
            std::cerr << "Backend::startHttps(), fd: " << fd << ", err == SSL_ERROR_ZERO_RETURN" << std::endl;
            #endif
            Cache::closeFD(fd);
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
                printf("SSL_connect: close notify received from peer");
                closeSSL();
                #if defined(DEBUGFILEOPEN)
                std::cerr << "Backend::startHttps(), fd: " << fd << ", err == SSL_ERROR_ZERO_RETURN" << std::endl;
                #endif
                Cache::closeFD(fd);
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
                printf("Error SSL_connect: %d", err);
                perror("perror: ");
                closeSSL();
                #if defined(DEBUGFILEOPEN)
                std::cerr << "Backend::startHttps(), fd: " << fd << std::endl;
                #endif
                if(fd!=-1)
                {
                    Cache::closeFD(fd);
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

    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if(fd==-1)
    {
        std::cerr << "Unable to create socket" << std::endl;
        return false;
    }
    Cache::newFD(fd,this,EpollObject::Kind::Kind_Backend);

    char astring[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(s.sin6_addr), astring, INET6_ADDRSTRLEN);
    #ifdef DEBUGFASTCGI
    if(std::string(astring)=="::")
    {
        std::cerr << "Internal error, try connect on ::" << std::endl;
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
            Cache::closeFD(fd);
            ::close(fd);
        }
        fd=-1;
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
    if(event.events & EPOLLIN)
    {
        #ifdef DEBUGFASTCGI
        //std::cout << "Backend EPOLLIN" << std::endl;
        #endif
        if(http!=nullptr)
            http->readyToRead();
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " Received data while not connected to http backend, fd: " << fd << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            char buffer[1024*1024];
            while(Backend::socketRead(buffer,sizeof(buffer))>0)
            {}
        }
    }
    if(event.events & EPOLLOUT)
    {
        #ifdef DEBUGFASTCGI
        //std::cout << "Backend EPOLLOUT" << std::endl;
        #endif
        if(ssl==nullptr && https)
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
            lastReceivedBytesTimestamps=Backend::currentTime();
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
            lastReceivedBytesTimestamps=Backend::currentTime();
        return s;
    }
}

bool Backend::socketWrite(const void *buffer, size_t size)
{
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

uint64_t Backend::currentTime() //ms from 1970
{
    struct timeval te;
    gettimeofday(&te, NULL);
    return te.tv_sec*1000LL + te.tv_usec/1000;
}

bool Backend::detectTimeout()
{
    //if no http then idle, no data, skip detect timeout
    if(http==nullptr)
        return false;
    else
    {
        #ifdef DEBUGFASTCGI
        http->checkBackend();
        #endif
    }
    const uint64_t msFrom1970=Backend::currentTime();
    if(lastReceivedBytesTimestamps>(msFrom1970-5*1000))
    {
        //prevent time drift
        if(lastReceivedBytesTimestamps>msFrom1970)
            lastReceivedBytesTimestamps=msFrom1970;
        return false;
    }
    //if no byte received into 5s
    #ifdef DEBUGFASTCGI
    struct timeval tv;
    gettimeofday(&tv,NULL);
    std::cerr << "[" << tv.tv_sec << "] ";
    #endif
    std::cerr << "Backend::detectTimeout() timeout while downloading " << http->getUrl() << " from " << http << " (backend " << this << "): " << msFrom1970 << "<" << (msFrom1970-5*1000) << " (" << msFrom1970 << "-5*1000)" << std::endl;
    if(http!=nullptr)
    {
        http->backendError("Timeout");
        http->disconnectFrontend(true);
        http->disconnectBackend();
    }
    close();
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
    ret+=" last byte "+std::to_string(lastReceivedBytesTimestamps);
    if(wasTCPConnected)
        ret+=" wasTCPConnected";
    else
        ret+=" !wasTCPConnected";
    return ret;
}
#endif
