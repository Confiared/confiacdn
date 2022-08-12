#include "Client.hpp"
#include "Cache.hpp"
#include "Dns.hpp"
#include "Http.hpp"
#include "Https.hpp"
#include "Common.hpp"
#include <unistd.h>
#include <iostream>
#include <string.h>
//#include <xxhash.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "xxHash/xxh3.h"
#include <chrono>
#include <arpa/inet.h>
#include <sstream>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

//ETag -> If-None-Match
//debug.m3MM7UcOEr3qP3ZK

//can't be static, reused later
//char Client::pathVar[]="XXXXXXXXXXXXXXXX";
//std::string pathForIndex;
#ifdef HOSTSUBFOLDER
char Client::folderVar[]="";
#endif
#ifdef DEBUGFASTCGI
#include <arpa/inet.h>
#endif

std::unordered_set<Client *> Client::clients;
std::unordered_set<Client *> Client::toDelete;
#ifdef DEBUGFASTCGI
std::unordered_set<Client *> Client::toDebug;
#endif
char Client::bigStaticReadBuffer[65536];

Client::Client(int cfd) :
    EpollObject(cfd,EpollObject::Kind::Kind_Client),
    fastcgiid(-1),
    readCache(nullptr),
    http(nullptr),
    fullyParsed(false),
    endTriggered(false),
    status(Status_Idle),
    https(false),
    gzip(false),
    partial(false),
    partialEndOfFileTrigged(false),
    outputWrited(false),
    creationTime(0),
    bodyAndHeaderFileBytesSended(0)
{
    memset(Client::pathVar,0,sizeof(Client::pathVar));
    #ifdef HOSTSUBFOLDER
    {
        strncpy(Client::pathVar,"XXXXXXXX/XXXXXXXXXXXXXXXXY",sizeof(Client::pathVar));
        memset(Client::folderVar,0,sizeof(Client::folderVar));
        strncpy(Client::folderVar,"XXXXXXXX",sizeof(Client::folderVar));
    }
    #else
        strncpy(Client::pathVar,"XXXXXXXXXXXXXXXXY",sizeof(Client::pathVar));
    #endif
    #ifdef DEBUGFASTCGI
    bytesSended=0;
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << "create client " << this << std::endl;
    #endif
    Cache::newFD(cfd,this,EpollObject::Kind::Kind_Client);
    this->kind=EpollObject::Kind::Kind_Client;
    this->fd=cfd;
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Client::Client() " << this << " fd: " << fd << " this->fd: " << this->fd << " constructor" << std::endl;
    #endif
    clients.insert(this);
    creationTime=Backend::msFrom1970();
    #ifdef DEBUGFASTCGI
    toDebug.insert(this);
    #endif
}

Client::~Client()
{
    #ifdef DEBUGFASTCGI
    toDebug.insert(this);
    #endif
    if(clients.find(this)!=clients.cend())
        clients.erase(this);
    else
    {
        std::cerr << "Client Entry not found into global list, abort()" << std::endl;
        abort();
    }
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " destructor " << this << std::endl;
    #endif
    #ifdef DEBUGFILEOPEN
    std::cerr << "Client::~Client(), readCache close: " << readCache << std::endl;
    #endif
    if(readCache!=nullptr)
    {
        readCache->close();
        delete readCache;
        readCache=nullptr;
    }
    if(http!=nullptr)
    {
        if(!http->removeClient(this))
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " not into client list of " << http << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
    }
    if(fd!=-1)
        Cache::closeFD(fd);
}

void Client::parseEvent(const epoll_event &event)
{
    #ifdef DEBUGFASTCGI
    std::cout << this << " Client event.events: " << event.events << std::endl;
    #endif
    if(event.events & EPOLLIN)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << "EPOLLIN " << this << std::endl;
        #endif
        readyToRead();
    }
    if(event.events & EPOLLOUT)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << "EPOLLOUT " << this << std::endl;
        #endif
        readyToWrite();
    }
    if(event.events & EPOLLHUP)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << "EPOLLHUP " << this << std::endl;
        #endif
        disconnect();
    }
    if(event.events & EPOLLRDHUP)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << "EPOLLRDHUP " << this << std::endl;
        #endif
        disconnect();
        #ifdef DEBUGFASTCGI
        if(fd!=-1)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << "EPOLLRDHUP (abort) " << this << std::endl;
            abort();
        }
        #endif
    }
    if(event.events & EPOLLERR)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << "EPOLLERR " << this << std::endl;
        #endif
        disconnect();
    }
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << "event.events: " << event.events << " " << this << std::endl;
    #endif
}

void Client::disconnect()
{
    if(fd==-1)
        return;
    #ifdef DEBUGFASTCGI
    {
        struct stat sb;
        sb.st_size=0;
        if(fstat(fd,&sb)!=0)
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " size: " << sb.st_size << std::endl;
        else
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
    }
    #endif
    #ifdef DEBUGFILEOPEN
    std::cerr << __FILE__ << ":" << __LINE__ << " " << "Client::disconnect(), readCache close: " << fd << " " << this << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << "Client::disconnect(), bytesSended: " << bytesSended << " " << this << std::endl;
    #endif
    if(fd!=-1)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " fd: " << fd << " disconnect() close()" << std::endl;
        #endif
        Cache::closeFD(fd);
        epoll_ctl(epollfd,EPOLL_CTL_DEL, fd, NULL);
        if(::close(fd)!=0)
            std::cerr << this << " " << fd << " disconnect() failed: " << errno << std::endl;
        fd=-1;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << "Client::disconnect(), bytesSended: " << bytesSended << " " << this << std::endl;
    #endif
    disconnectFromHttp();
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << "Client::disconnect(), bytesSended: " << bytesSended << " " << this << std::endl;
    #endif
    dataToWrite.clear();
    fastcgiid=-1;
    #ifdef DEBUGFASTCGI
    std::cerr << "disconnectFrontend client " << this << ": " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
}

void Client::disconnectFromHttp()
{
    if(http!=nullptr)
    {
        if(!http->removeClient(this))
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " not into client list of " << http << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
    }
}

void Client::readyToRead()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " fd: " << fd << " this->fd: " << this->fd << " fullyParsed: " << fullyParsed << std::endl;
    #endif
    if(fullyParsed)
        return;
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
    #endif

    /// \todo for now re-read all request, possible bug? performance problema
    if(!requestRawData.empty())
        memcpy(Client::bigStaticReadBuffer,requestRawData.data(),requestRawData.size());
    const int size=read(fd,Client::bigStaticReadBuffer+requestRawData.size(),sizeof(Client::bigStaticReadBuffer)-requestRawData.size())+requestRawData.size();
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " additional data: " << Common::binarytoHexa(Client::bigStaticReadBuffer+requestRawData.size(),size-requestRawData.size()) << " size: " << size-requestRawData.size() << std::endl;
    #endif
    requestRawData.clear();

    /*std::string buggyData=Common::hexaToBinary("");
    if(buggyData.size()>=sizeof(Client::bigStaticReadBuffer))
        abort();
    memcpy(Client::bigStaticReadBuffer,buggyData.data(),buggyData.size());
    const int size=buggyData.size();*/

    if(size<=0)
        return;
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " read data: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
    #endif

    std::string ifNoneMatch;
    https=false;
    uri.clear();
    host.clear();
    //all is big endian
    int pos=0;
    uint8_t var8=0;
    uint16_t var16=0;

    /*{
        std::cerr << fd << ") " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << std::endl;
    }*/

    do
    {
        if(!read8Bits(var8,Client::bigStaticReadBuffer,size,pos))
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
            requestRawData=std::string(Client::bigStaticReadBuffer,size);
            return;
        }
        if(var8!=1)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " wrong fastcgi version: " << std::to_string(var8) << std::endl;
            #endif
            disconnect();
            return;
        }
        if(!read8Bits(var8,Client::bigStaticReadBuffer,size,pos))
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
            requestRawData=std::string(Client::bigStaticReadBuffer,size);
            return;
        }
        if(fastcgiid==-1)
        {
            if(var8!=1)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
                #endif
                disconnect();
                return;
            }
            if(!read16Bits(var16,Client::bigStaticReadBuffer,size,pos))
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                requestRawData=std::string(Client::bigStaticReadBuffer,size);
                return;
            }
            fastcgiid=var16;
            #ifndef ONFLYENCODEFASTCGI
            if(fastcgiid!=1)
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error, only request with id 1 is supported, use nginx + fastcgi_keep_conn off" << std::endl;
                disconnect();
            }
            #endif
        }
        else
        {
            /*
             * 1 = FCGI_BEGIN_REQUEST
             * 4 = FCGI_PARAMS
             * 5 = FCGI_STDIN
            */
            if(var8!=1 && var8!=4 && var8!=5)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " at 2nd number read, pos: "  << std::to_string(pos) << " var8: " << std::to_string(var8) << " fastcgiid: " << std::to_string(fastcgiid) << std::endl;
                #endif
                disconnect();
                return;
            }
            if(!read16Bits(var16,Client::bigStaticReadBuffer,size,pos))
            {
                requestRawData=std::string(Client::bigStaticReadBuffer,size);
                return;
            }
            if(fastcgiid!=var16)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
                #endif
                disconnect();
                return;
            }
        }
        uint16_t contentLenght=0;
        uint8_t paddingLength=0;
        if(!read16Bits(contentLenght,Client::bigStaticReadBuffer,size,pos))
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
            requestRawData=std::string(Client::bigStaticReadBuffer,size);
            return;
        }
        if(!read8Bits(paddingLength,Client::bigStaticReadBuffer,size,pos))
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
            requestRawData=std::string(Client::bigStaticReadBuffer,size);
            return;
        }
        if(!canAddToPos(1,size,pos))
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
            requestRawData=std::string(Client::bigStaticReadBuffer,size);
            return;
        }
        switch (var8) {
        //FCGI_BEGIN_REQUEST
        case 1:
            //skip the content length + padding length
            if(!canAddToPos(contentLenght+paddingLength,size,pos))
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                requestRawData=std::string(Client::bigStaticReadBuffer,size);
                return;
            }
        break;
        //FCGI_PARAMS
        case 4:
        {
            int contentLenghtAbs=contentLenght+pos;
            while(pos<contentLenghtAbs)
            {
                uint32_t varSize=0;
                uint8_t varSize8=0;
                if(!read8Bits(varSize8,Client::bigStaticReadBuffer,size,pos))
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                    requestRawData=std::string(Client::bigStaticReadBuffer,size);
                    return;
                }
                if(varSize8>127)
                {
                    if(!read24Bits(varSize,Client::bigStaticReadBuffer,size,pos))
                    {
                        std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                        requestRawData=std::string(Client::bigStaticReadBuffer,size);
                        return;
                    }
                }
                else
                    varSize=varSize8;

                uint32_t valSize=0;
                uint8_t valSize8=0;
                if(!read8Bits(valSize8,Client::bigStaticReadBuffer,size,pos))
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                    requestRawData=std::string(Client::bigStaticReadBuffer,size);
                    return;
                }
                if(valSize8>127)
                {
                    if(!read24Bits(valSize,Client::bigStaticReadBuffer,size,pos))
                    {
                        std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                        requestRawData=std::string(Client::bigStaticReadBuffer,size);
                        return;
                    }
                }
                else
                    valSize=valSize8;

                switch(varSize)
                {
                    case 9:
                    if(memcmp(Client::bigStaticReadBuffer+pos,"HTTP_HOST",varSize)==0)
                        host=std::string(Client::bigStaticReadBuffer+pos+varSize,valSize);
                    else
                    {
                        #ifdef DEBUGFASTCGI
                        //std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " other header (1): " << std::string(buff+pos,9) << std::endl;
                        #endif
                    }
                    break;
                    case 10:
                    #ifdef DEBUGFASTCGI
                    if(memcmp(Client::bigStaticReadBuffer+pos,"HTTP_DEBUG",varSize)==0)
                        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " HTTP_DEBUG: " << std::string(Client::bigStaticReadBuffer+pos+varSize,valSize) << std::endl;
                    #endif
                    break;
                    case 11:
                    if(memcmp(Client::bigStaticReadBuffer+pos,"REQUEST_URI",varSize)==0)
                        uri=std::string(Client::bigStaticReadBuffer+pos+varSize,valSize);
                    #ifdef DEBUGFASTCGI
                    else if(memcmp(Client::bigStaticReadBuffer+pos,"REMOTE_ADDR",varSize)==0)
                    {
                        std::cout << "request from IP: " << std::string(Client::bigStaticReadBuffer+pos+varSize,valSize) << std::endl;
                    /* black list: self ip, block ip continuously downloading same thing
                        ifNoneMatch=std::string(buff+pos+varSize,8);
                        */
                    }
                    /*else if(memcmp(buff+pos,"SERVER_PORT",11)==0 && valSize==3)
                        if(memcmp(buff+pos+varSize,"443",3)==0)
                            https=true;*/
                    #endif
                    else
                    {
                        #ifdef DEBUGFASTCGI
                        //std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " other header (2): " << std::string(buff+pos,9) << std::endl;
                        #endif
                    }
                    break;
                    case 13:
                    if(memcmp(Client::bigStaticReadBuffer+pos,"HTTP_EPNOERFT",varSize)==0)
                        if(memcmp(Client::bigStaticReadBuffer+pos+varSize,"ysff43Uy",8)==0)
                        {
                            char text[]="X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nAnti loop protection";
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << "Anti loop protection" << std::endl;
                            #endif
                            writeOutput(text,sizeof(text)-1);
                            internalWriteEnd();
                            disconnect();
                            return;
                        }
                    break;
                    case 14:
                    if(memcmp(Client::bigStaticReadBuffer+pos,"REQUEST_SCHEME",varSize)==0 && valSize==5)
                        if(memcmp(Client::bigStaticReadBuffer+pos+varSize,"https",5)==0)
                            https=true;
                    break;
                    case 18:
                    if(memcmp(Client::bigStaticReadBuffer+pos,"HTTP_IF_NONE_MATCH",varSize)==0 && valSize==8)
                        ifNoneMatch=std::string(Client::bigStaticReadBuffer+pos+varSize,8);
                    break;
                    case 20:
                    if(Http::useCompression)
                        if(memcmp(Client::bigStaticReadBuffer+pos,"HTTP_ACCEPT_ENCODING",varSize)==0 && valSize>=4)
                            gzip=std::string(Client::bigStaticReadBuffer+pos+varSize,varSize).find("gzip")!=std::string::npos;
                    break;
                    default:
                    break;
                }
                #ifdef DEBUGFASTCGI
                //std::cout << std::string(buff+pos,varSize) << ": " << std::string(buff+pos+varSize,valSize) << std::endl;
                #endif
                if(!canAddToPos(varSize+valSize,size,pos))
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                    requestRawData=std::string(Client::bigStaticReadBuffer,size);
                    return;
                }
            }
            if(!canAddToPos(paddingLength,size,pos))
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                requestRawData=std::string(Client::bigStaticReadBuffer,size);
                return;
            }
        }
        break;
        //FCGI_STDIN
        case 5:
            //skip the content length + padding length
            if(!canAddToPos(contentLenght+paddingLength,size,pos))
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " FastCGI protocol error: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                requestRawData=std::string(Client::bigStaticReadBuffer,size);
                return;
            }
            if(host.empty() || uri.empty())
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " host.empty() || uri.empty() and try fullyParsed=true: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << " size: " << size << std::endl;
                #endif
            }
            fullyParsed=true;
        break;
        default:
            break;
        }
    } while(pos<size);

    if(!fullyParsed)
        return;
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
    #endif

    //resolv the host or from subdomain or from uri
    {
        //resolv final url (hex, https, ...)
        const size_t &pos=host.rfind(".confiared.com");
        const size_t &mark=(host.size()-14);
        #ifdef DEBUGDNS
        const size_t &posdebug=host.rfind(".bolivia-online.com");
        const size_t &markdebug=(host.size()-19);
        if(pos==mark || posdebug==markdebug)
        {
            std::string hostb;
            if(pos==mark)
                hostb=host.substr(0,mark);
            else
                hostb=host.substr(0,markdebug);
        #else
        if(pos==mark)
        {
            std::string hostb=host.substr(0,mark);
        #endif

            size_t posb=hostb.rfind("cdn");
            size_t markb=(hostb.size()-3);
            if(posb==markb)
            {
                if(markb>1)
                    host=Common::hexaToBinary(hostb.substr(0,markb-1));
                else if(markb==0)
                {
                    const size_t poss=uri.find("/",1);
                    if(poss!=std::string::npos)
                    {
                        if(poss>2)
                        {
                            host=uri.substr(1,poss-1);
                            uri=uri.substr(poss);
                        }
                    }
                    else
                    {
                        //std::cerr << "uri '/' not found " << uri << ", host: " << host << std::endl;
                        char text[]="X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nCDN bad usage (1): contact@confiared.com";
                        writeOutput(text,sizeof(text)-1);
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " bad CDN usage, data: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << std::endl;
                        #endif
                        internalWriteEnd();
                        disconnect();
                        return;
                    }
                }
            }
            else
            {
                markb=(hostb.size()-4);
                posb=hostb.rfind("cdn1");
                if(posb!=markb)
                    posb=hostb.rfind("cdn2");
                if(posb!=markb)
                    posb=hostb.rfind("cdn3");
                if(posb==markb)
                {
                    if(markb>1)
                        host=Common::hexaToBinary(hostb.substr(0,markb-1));
                    else if(markb==0)
                    {
                        const size_t poss=uri.find("/",1);
                        if(poss!=std::string::npos)
                        {
                            if(poss>2)
                            {
                                host=uri.substr(1,poss-1);
                                uri=uri.substr(poss);
                            }
                        }
                        else
                        {
                            //std::cerr << "uri '/' not found " << uri << ", host: " << host << std::endl;
                            char text[]="X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nCDN bad usage (2): contact@confiared.com";
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " bad CDN usage 2, data: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << std::endl;
                            #endif
                            writeOutput(text,sizeof(text)-1);
                            internalWriteEnd();
                            disconnect();
                            return;
                        }
                    }
                }
            }
        }
        else
        {
            const size_t poss=uri.find("/",1);
            if(poss!=std::string::npos)
            {
                if(poss>2)
                {
                    host=uri.substr(1,poss-1);
                    uri=uri.substr(poss);
                }
            }
            else
            {
                std::cerr << "uri '/' not found " << uri << ", host: " << host << ", pos: " << pos << ", mark: " << mark
                            #ifdef DEBUGDNS
                          << ", posdebug: " << posdebug << ", markdebug: " << markdebug
                            #endif
                          << std::endl;
                char buffer[2048];
                sprintf(buffer,"%p",this);
                std::string text("X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nCDN bad usage (3): contact@confiared.com for uri: "+uri+" host: "+host+" client: "+buffer);
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " bad CDN usage 3, data: " << Common::binarytoHexa(Client::bigStaticReadBuffer,size) << std::endl;
                #endif
                writeOutput(text.c_str(),text.size());
                internalWriteEnd();
                disconnect();
                return;
            }
        }
        #ifdef DEBUGDNS
        /*if(posdebug==markdebug)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " posdebug==markdebug " << std::endl;
            //https=true;-> generate a bug to test http url
        }*/
        #endif
    }

    //check if robots.txt
    if(uri=="/robots.txt")
    {
        char text[]="X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nUser-agent: *\r\nDisallow: /";
        writeOutput(text,sizeof(text)-1);
        internalWriteEnd();
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " bad CDN usage /" << std::endl;
        #endif
        disconnect();
        return;
    }
    //check if robots.txt
    if(uri=="/favicon.ico")
    {
        char text[]="X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nDropped for now";
        writeOutput(text,sizeof(text)-1);
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " bad CDN usage favico" << std::endl;
        #endif
        internalWriteEnd();
        disconnect();
        return;
    }

    /*generate problem
     * Curl error on https://cdn3.confiared.com/files.first-world.info/ultracopier/2.2.4.12/ultracopier-windows-x86_64-2.2.4.12-setup.exe, curl_errno($ch): 18, curl_getinfo($ch, CURLINFO_HTTP_CODE): 200 SCZ transfer closed with 15537536 bytes remaining to read */
    //drop buffer in memory, replace by seek from cache file to reduce memory
    #ifdef FASTCGIASYNC
    int flags, s;
    flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1)
        std::cerr << "fcntl get flags error" << std::endl;
    else
    {
        flags |= O_NONBLOCK;
        s = fcntl(fd, F_SETFL, flags);
        if(s == -1)
            std::cerr << "fcntl set flags error" << std::endl;
        #ifdef DEBUGFASTCGI
        else
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " async set" << std::endl;
        #endif
    }
    #endif

    Client::loadUrl(host,uri,ifNoneMatch);
}

void Client::loadUrl(const std::string &host, const std::string &uri, const std::string &ifNoneMatch)
{
    //if have request
    #ifdef DEBUGFASTCGI
    const auto p1 = std::chrono::system_clock::now();
    if(https)
        std::cout << std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count() << " downloading: https://" << host << uri << std::endl;
    else
        std::cout << std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count() << " downloading: http://" << host << uri << std::endl;
    #endif

    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
    #endif

    if(host.empty())
    {
        char text[]="X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nCDN bad usage (4): contact@confiared.com";
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN bad usage host emtpy" << std::endl;
        #endif
        writeOutput(text,sizeof(text)-1);
        internalWriteEnd();
        disconnect();
        return;
    }
    else if(host=="debug.m3MM7UcOEr3qP3ZK") {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " debug.m3MM7UcOEr3qP3ZK: " << this->fd << " " << this << std::endl;
        #endif
        std::string reply("X-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\n");
        reply+="Current time: ";
        reply+=std::to_string(Backend::msFrom1970());
        reply+="\r\n";
        reply+="Dns ("+std::to_string(Dns::dns->get_httpInProgress())+"): ";
        reply+=Dns::dns->getQueryList();
        //reply+="\r\n";
        size_t isNotValideCount=0;
        for( const auto &n : Client::clients )
            if(!n->isValid())
                isNotValideCount++;
        reply+="Clients: ";
        reply+=std::to_string(Client::clients.size());
        if(isNotValideCount>0)
            reply+=", "+std::to_string(isNotValideCount)+" not valid";
        {
            std::stringstream strm;
            strm << this;
            reply+=" (this: "+strm.str()+")";
        }
        reply+="\r\n";
        #ifdef DEBUGFASTCGI
        for (const Client * c : Client::clients)
            reply+=c->getStatus()+"\r\n";
        reply+="Backend: "+std::to_string(Backend::toDebug.size())+"\r\n";
        #endif
        reply+="Http: ";
        #ifdef DEBUGFASTCGI
        reply+="(http "+std::to_string(Http::toDebug.size()-Https::toDebug.size())+" and https "+std::to_string(Https::toDebug.size())+" backend)";
        std::unordered_set<const Http *> notIntoTheList;
        notIntoTheList.insert(Http::toDebug.begin(),Http::toDebug.end());
        #endif
        reply+="\r\n";
        {
            std::string ret;
            for( const auto &n : Http::pathToHttp )
            {
                const Http * const client=n.second;
                if(client!=nullptr)
                {
                    ret+="http "+client->getQuery();

                    {
                        std::string ret;
                        char buffer[32];
                        std::snprintf(buffer,sizeof(buffer),"%p",(void *)client->backend);
                        ret+=" backend "+std::string(buffer);
                    }
                    {
                        std::string ret;
                        char buffer[32];
                        std::snprintf(buffer,sizeof(buffer),"%p",(void *)client->backendList);
                        ret+=" backendList "+std::string(buffer);
                    }

                    ret+="\r\n";
                }
                #ifdef DEBUGFASTCGI
                notIntoTheList.erase(client);
                #endif
            }
            for( const auto &n : Https::pathToHttps )
            {
                const Http * const client=n.second;
                if(client!=nullptr)
                    ret+="https "+client->getQuery()+"\r\n";
                #ifdef DEBUGFASTCGI
                notIntoTheList.erase(client);
                #endif
            }
            for( const auto &n : Backend::addressToHttp )
            {
                in6_addr sin6_addr;
                memcpy(&sin6_addr,n.first.data(),16);

                std::string host="Unknown IPv6";
                char str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, n.first.data(), str, INET6_ADDRSTRLEN) != NULL)
                    host=str;

                ret+="backend http \""+host+"\"\r\n";
                if(n.second!=nullptr)
                {
                    ret+="busy:\r\n";
                    {
                        const std::vector<Backend *> &backend=n.second->busy;
                        for( const auto &m : backend )
                            if(m!=nullptr)
                                ret+=m->getQuery()+"\r\n";
                    }
                    ret+="idle:\r\n";
                    {
                        const std::vector<Backend *> &backend=n.second->idle;
                        for( const auto &m : backend )
                            if(m!=nullptr)
                                ret+=m->getQuery()+"\r\n";
                    }
                    ret+="pending:\r\n";
                    {
                        const std::vector<Http *> &pending=n.second->pending;
                        for( const auto &m : pending )
                            if(m!=nullptr)
                                ret+=m->getQuery()+"\r\n";
                    }
                }
                else
                    ret+="no backend list\"\r\n";
            }
            for( const auto &n : Backend::addressToHttps )
            {
                in6_addr sin6_addr;
                memcpy(&sin6_addr,n.first.data(),16);

                std::string host="Unknown IPv6";
                char str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, n.first.data(), str, INET6_ADDRSTRLEN) != NULL)
                    host=str;

                ret+="backend https \""+host+"\"\r\n";
                if(n.second!=nullptr)
                {
                    ret+="busy:\r\n";
                    {
                        const std::vector<Backend *> &backend=n.second->busy;
                        for( const auto &m : backend )
                            if(m!=nullptr)
                                ret+=m->getQuery()+"\r\n";
                    }
                    ret+="idle:\r\n";
                    {
                        const std::vector<Backend *> &backend=n.second->idle;
                        for( const auto &m : backend )
                            if(m!=nullptr)
                                ret+=m->getQuery()+"\r\n";
                    }
                    ret+="pending:\r\n";
                    {
                        const std::vector<Http *> &pending=n.second->pending;
                        for( const auto &m : pending )
                            if(m!=nullptr)
                                ret+=m->getQuery()+"\r\n";
                    }
                }
                else
                    ret+="no backend list\"\r\n";
            }
            reply+=ret;
        }
        reply+="\r\n";
        #ifdef DEBUGFASTCGI
        for (const Http * const x: notIntoTheList)
            reply+="lost http(s) "+x->getQuery()+"\r\n";
        #endif
        writeOutput(reply.data(),reply.size());
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN end of stats" << std::endl;
    #endif
        internalWriteEnd();
        disconnect();
        return;
    }

    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
    #endif
    status=Status_WaitTheContent;
    partial=false;

    #ifdef HOSTSUBFOLDER
    {
        std::string hostwithprotocol=host;
        if(https)
            hostwithprotocol+="s";
        const uint32_t &hashhost=static_cast<uint32_t>(XXH3_64bits(hostwithprotocol.data(),hostwithprotocol.size()));
        const XXH64_hash_t &hashuri=XXH3_64bits(uri.data(),uri.size());

        //do the hash for host to define cache subfolder, hash for uri to file

        //Cache::hostsubfolder should not be changed at runtime
        Common::binarytoHexaC32Bits(reinterpret_cast<const char *>(&hashhost),folderVar);
        memcpy(pathVar,folderVar,4);

        Common::binarytoHexaC64Bits(reinterpret_cast<const char *>(&hashuri),pathVar+8+1);
        if(gzip)
            pathVar[8+1+16]='G';
        else
            pathVar[8+1+16]='R';
    }
    #else
    {
        //Cache::hostsubfolder should not be changed at runtime
        //then don't touch folderVar
        //folderVar[6]='\0';

        XXH3_state_t state;
        XXH3_64bits_reset(&state);
        if(https)
            XXH3_64bits_update(&state, "S",1);
        XXH3_64bits_update(&state, host.data(),host.size());
        XXH3_64bits_update(&state, uri.data(),uri.size());
        const XXH64_hash_t &hashuri=XXH3_64bits_digest(&state);

        Common::binarytoHexaC64Bits(reinterpret_cast<const char *>(&hashuri),pathVar);
        if(gzip)
            pathVar[16]='G';
        else
            pathVar[16]='R';
    }
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " pathVar: " << pathVar << std::endl;
    #endif
    #ifdef HOSTSUBFOLDER
    const std::string pathForIndex(pathVar,26);
    #else
    const std::string pathForIndex(pathVar,17);
    #endif
    bool httpBackendFound=false;
    if(http==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        if(!https)
        {
            if(Http::pathToHttp.find(pathForIndex)!=Http::pathToHttp.cend())
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
                #endif
                if(!Http::pathToHttp.at(pathForIndex)->isAlive())
                {
                    std::cerr << this << " http " << pathForIndex << " is not alive" << __FILE__ << ":" << __LINE__ << std::endl;
                    Http *http=Http::pathToHttp.at(pathForIndex);
                    Http::pathToHttp.erase(pathForIndex);
                    http->disconnectFrontend(true);
                    http->disconnectBackend();
                    //delete http;->do into http->disconnectBackend();
                }
                else
                {
                    httpBackendFound=true;
                    http=Http::pathToHttp.at(pathForIndex);
                    http->addClient(this);//into this call, start open cache and stream if partial have started
                }
            }
        }
        else
        {
            if(Https::pathToHttps.find(pathForIndex)!=Https::pathToHttps.cend())
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
                #endif
                if(!Https::pathToHttps.at(pathForIndex)->isAlive())
                {
                    std::cerr << this << " http " << pathForIndex << " is not alive" << __FILE__ << ":" << __LINE__ << std::endl;
                    Http *http=Https::pathToHttps.at(pathForIndex);
                    Https::pathToHttps.erase(pathForIndex);
                    http->disconnectFrontend(true);
                    http->disconnectBackend();
                    //delete http;->do into http->disconnectBackend();
                }
                else
                {
                    httpBackendFound=true;
                    http=Https::pathToHttps.at(pathForIndex);
                    http->addClient(this);//into this call, start open cache and stream if partial have started
                }
            }
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        httpBackendFound=true;
    }
    if(!httpBackendFound)
    //if(true)
    {
        struct stat sb;
        #if defined(DEBUGFASTCGI) || defined(DEBUGFILEOPEN)
        struct stat sb2;
        #endif
        std::string url;
        if(https)
            url="https://";
        else
            url="http://";
        url+=host;
        url+=uri;
        //try open cache
        #ifdef DEBUGFASTCGI
        const bool cacheWasExists=stat(pathVar,&sb)==0;
        if(cacheWasExists)
        {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " cache size: " << sb.st_size << std::endl;}
        #endif
        //std::cerr << "open(pathVar " << pathVar << std::endl;
        int cachefd = open(pathVar, O_RDWR | O_NOCTTY/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        #ifdef DEBUGFASTCGI
        const bool cacheWasExists3=stat(pathVar,&sb)==0;
        if(cacheWasExists3)
        {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " cache size: " << sb.st_size << std::endl;}
        #endif
        //if failed open cache
        if(cachefd==-1)
        {
            #ifdef DEBUGFASTCGI
            const bool cacheWasExists4=stat(pathVar,&sb)==0;
            if(cacheWasExists4)
            {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " cache size: " << sb.st_size << " exists, should not, errno: " << errno << std::endl;}
            #endif
            if(errno!=2)//if not file not found
                std::cerr << "can't open cache file " << pathForIndex << " for " << url << " due to errno: " << errno << std::endl;
            #ifdef HOSTSUBFOLDER
                ::mkdir(folderVar,S_IRWXU);
            #endif

            /*if(status==Status_WaitTheContent)
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " status==Status_WaitTheContent (abort)" << std::endl;
                abort();
            }*/
            createHttpBackend();
            return;
        }
        else
        {
            #ifdef DEBUGFASTCGI
            const bool cacheWasExists2=stat(pathVar,&sb)==0;
            fstat(cachefd,&sb2);
            if(!cacheWasExists)
            {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " cache created into wrong way" << std::endl;}
            if(!cacheWasExists && cacheWasExists2)
            {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " cache created into wrong way 2" << std::endl;}
            #endif
            #ifdef DEBUGFILEOPEN
            stat(pathVar,&sb);
            fstat(cachefd,&sb2);
            std::cerr << "Client::loadUrl() open: " << pathForIndex << ", fd: " << cachefd << ", size real:" << sb.st_size << ", " << url << ", size open: " << sb2.st_size << std::endl;
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
            #endif
            if(!ifNoneMatch.empty())
            {
                char bufferETag[6];
                if(::pread(cachefd,bufferETag,sizeof(bufferETag),2*sizeof(uint64_t)+sizeof(uint16_t))==sizeof(bufferETag))
                {
                    if(memcmp(ifNoneMatch.substr(1,6).data(),bufferETag,sizeof(bufferETag))==0)
                    {
                        //frontend 304
                        char text[]="Status: 304 Not Modified\r\n\r\n";
                        writeOutput(text,sizeof(text)-1);
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN 304" << std::endl;
                        #endif
                        internalWriteEnd();
                        disconnect();
                        #ifdef DEBUGFILEOPEN
                        std::cerr << "Client::loadUrl(), readCache close: " << cachefd << std::endl;
                        #endif
                        #ifdef DEBUGFASTCGI
                        std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        #endif
                        if(cachefd!=-1)
                            ::close(cachefd);
                        cachefd=-1;
                        return;
                    }
                }
            }

            fstat(cachefd,&sb);
            #ifdef DEBUGFASTCGI
            {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " cache size: " << sb.st_size << std::endl;}
            #endif
            if(sb.st_size<25)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(cachefd!=-1)
                    ::close(cachefd);
                cachefd=-1;
                std::cerr << "corruption detected, new file? for " << pathForIndex << " url: " << url << std::endl;

                createHttpBackend();
                return;
            }
            uint64_t lastModificationTimeCheck=0;
            if(::pread(cachefd,&lastModificationTimeCheck,sizeof(lastModificationTimeCheck),1*sizeof(uint64_t))!=sizeof(lastModificationTimeCheck))
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(cachefd!=-1)
                    ::close(cachefd);
                cachefd=-1;
                std::cerr << "corruption detected, bug? for " << pathForIndex << " url: " << url << std::endl;

                createHttpBackend();
                return;

                lastModificationTimeCheck=0;
            }
            uint16_t http_code=500;
            if(::pread(cachefd,&http_code,sizeof(http_code),2*sizeof(uint64_t))!=sizeof(http_code))
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(cachefd!=-1)
                    ::close(cachefd);
                cachefd=-1;
                std::cerr << "corruption detected, bug? for " << pathForIndex << " url: " << url << std::endl;

                createHttpBackend();
                return;

                http_code=500;
            }
            //last modification time check <24h or in future to prevent time drift
            const uint64_t &currentTime=time(NULL);
            if(lastModificationTimeCheck>currentTime)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " lastModificationTimeCheck>currentTime, time drift?" << std::endl;
                #endif
                lastModificationTimeCheck=currentTime;
            }
            if(lastModificationTimeCheck>(currentTime-Cache::timeToCache(http_code)))
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
                #endif
                if(readCache!=nullptr)
                {
                    delete readCache;
                    readCache=nullptr;
                }
                readCache=new Cache(cachefd,this);
                readCache->set_access_time(currentTime);
                #ifdef DEBUGFASTCGI
                std::cerr << "startRead() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(startRead())
                    return;
                else//corrupted, then recreate
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " corrupted, delete to recreate" << std::endl;
                    #ifdef DEBUGFASTCGI
                    std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    if(cachefd!=-1)
                        ::close(cachefd);
                    cachefd=-1;
                    #ifdef DEBUGFASTCGI
                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << pathVar << std::endl;
                    #endif
                    ::unlink(pathVar);
                }
            }
            else
            {
                #ifdef DEBUGFILEOPEN
                std::cerr << "Client::loadUrl(), readCache close: " << cachefd << ", " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                #ifdef DEBUGFASTCGI
                std::cerr << lastModificationTimeCheck << ">(" << currentTime << "-" << Cache::timeToCache(http_code) << ") " << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                //without the next line descriptor lost, generate: errno 24 (Too many open files)
                if(cachefd!=-1)
                    ::close(cachefd);
                cachefd=-1;
            }

            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
            #endif
            #ifdef HOSTSUBFOLDER
                ::mkdir(folderVar,S_IRWXU);
            #endif

            createHttpBackend();
            return;
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "startRead() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        /* this case is used when:
         * Http add client: this client fd: X isAlive: 1 getEndDetected(): 1 getFileMoved(): 1
         * when the file was downloaded fully, but uploading to another client */
        if(http->headerWriten || http->getEndDetected() || http->getFileMoved())
            startRead(pathVar,true);
    }
}

#ifdef DEBUGFASTCGI
std::string Client::getStatus() const
{
    std::string s;
    {
        std::stringstream strm;
        strm << this;
        s+=strm.str()+" ";
    }
    switch(status)
    {
    case Status_Idle:
        s+="Status_Idle";
        break;
    case Status_WaitTheContent:
        s+="Status_WaitTheContent";
        break;
    default:
        s+="Status_???";
        break;
    }
    s+=" "+std::to_string(fastcgiid);
    s+=" "+std::to_string(fd);
    if(fullyParsed)
        s+=" fullyParsed";
    else
        s+=" !fullyParsed";
    if(dataToWrite.empty())
        s+=" dataToWrite.empty()";
    else
        s+=" !dataToWrite.empty()";
    if(gzip)
        s+=" gzip";
    else
        s+=" !gzip";
    if(partial)
        s+=" partial";
    else
        s+=" !partial";
    if(partialEndOfFileTrigged)
        s+=" partialEndOfFileTrigged";
    else
        s+=" !partialEndOfFileTrigged";
    if(outputWrited)
        s+=" outputWrited";
    else
        s+=" !outputWrited";
    if(https)
        s+=" https://";
    else
        s+=" http://";
    s+=host;
    s+=uri;
    s+=" ";
    {
        std::stringstream strm;
        strm << http;
        s+=" "+strm.str();
    }
    return s;
}
#endif

bool Client::canAddToPos(const int &i, const int &size, int &pos)
{
    if((pos+i)>size)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        /*disconnect();-> request can be too big, then need buffer, don't disconnect!
         * cause: 2022/06/24 06:35:18 [error] 34889#34889: *1 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 2803:1920::2:10, server: cdn.confiared.com, request: "GET /ultracopier.first-world.info/css/style.min.css HTTP/2.0", upstream: "fastcgi://127.0.0.1:5556", host: "cdn.confiared.com", referrer: "https://ultracopier.first-world.info/" */
        return false;
    }
    pos+=i;
    return true;
}

bool Client::read8Bits(uint8_t &var, const char * const data, const int &size, int &pos)
{
    if((pos+(int)sizeof(var))>size)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        /*disconnect();-> request can be too big, then need buffer, don't disconnect!
         * cause: 2022/06/24 06:35:18 [error] 34889#34889: *1 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 2803:1920::2:10, server: cdn.confiared.com, request: "GET /ultracopier.first-world.info/css/style.min.css HTTP/2.0", upstream: "fastcgi://127.0.0.1:5556", host: "cdn.confiared.com", referrer: "https://ultracopier.first-world.info/" */
        return false;
    }
    var=data[pos];
    pos+=sizeof(var);
    return true;
}

bool Client::read16Bits(uint16_t &var, const char * const data, const int &size, int &pos)
{
    if((pos+(int)sizeof(var))>size)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        /*disconnect();-> request can be too big, then need buffer, don't disconnect!
         * cause: 2022/06/24 06:35:18 [error] 34889#34889: *1 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 2803:1920::2:10, server: cdn.confiared.com, request: "GET /ultracopier.first-world.info/css/style.min.css HTTP/2.0", upstream: "fastcgi://127.0.0.1:5556", host: "cdn.confiared.com", referrer: "https://ultracopier.first-world.info/" */
        return false;
    }
    uint16_t t;
    memcpy(&t,data+pos,sizeof(var));
    var=be16toh(t);
    pos+=sizeof(var);
    return true;
}

bool Client::read24Bits(uint32_t &var, const char * const data, const int &size, int &pos)
{
    if((pos+(int)sizeof(var)-1)>size)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        /*disconnect();-> request can be too big, then need buffer, don't disconnect!
         * cause: 2022/06/24 06:35:18 [error] 34889#34889: *1 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 2803:1920::2:10, server: cdn.confiared.com, request: "GET /ultracopier.first-world.info/css/style.min.css HTTP/2.0", upstream: "fastcgi://127.0.0.1:5556", host: "cdn.confiared.com", referrer: "https://ultracopier.first-world.info/" */
        return false;
    }
    uint32_t t=0;
    memcpy(reinterpret_cast<char *>(&t)+1,data+pos,sizeof(var)-1);
    var=be32toh(t);
    pos+=sizeof(var)-1;
    return true;
}

void Client::createHttpBackend()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " Client::createHttpBackend()" << std::endl;
    #endif

    #ifdef HOSTSUBFOLDER
    const std::string pathForIndex(pathVar,26);
    #else
    const std::string pathForIndex(pathVar,17);
    #endif

    //if was not found into loadurl but here mean need be loaded
    if(http==nullptr)
    {
        std::string url;
        if(https)
            url="https://";
        else
            url="http://";
        url+=host;
        url+=uri;
        #ifdef DEBUGFASTCGI
        struct stat sb;
        const bool cacheWasExists=stat(pathVar,&sb)==0;
        if(cacheWasExists)
        {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " cache size: " << sb.st_size << " pathVar: " << pathVar << std::endl;}
        #endif
        //try open cache
        //std::cerr << "open((path).c_str() " << path << std::endl;
        int cachefd = open(pathVar, O_RDWR | O_NOCTTY/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        //if failed open cache in write mode
        if(cachefd==-1)
        {
            cachefd=0;
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
            #endif
            if(errno!=2)//if not file not found
                std::cerr << "can't open cache file " << pathForIndex << " for " << url << " due to errno: " << errno << std::endl;
            #ifdef HOSTSUBFOLDER
                ::mkdir(folderVar,S_IRWXU);
            #endif

            createHttpBackendInternal(0);
        }
        else
        {
            #ifdef DEBUGFASTCGI
            const bool cacheWasExists2=stat(pathVar,&sb)==0;
            if(!cacheWasExists)
            {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " cache created into wrong way" << std::endl;}
            if(!cacheWasExists && cacheWasExists2)
            {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " cache created into wrong way 2" << std::endl;}
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
            #endif
            #ifdef DEBUGFILEOPEN
            std::cerr << "Client::dnsRight() open: " << pathForIndex << ", fd: " << cachefd << std::endl;
            #endif
            uint64_t lastModificationTimeCheck=0;
            if(::pread(cachefd,&lastModificationTimeCheck,sizeof(lastModificationTimeCheck),1*sizeof(uint64_t))!=sizeof(lastModificationTimeCheck))
                lastModificationTimeCheck=0;
            uint16_t http_code=500;
            if(::pread(cachefd,&http_code,sizeof(http_code),2*sizeof(uint64_t))!=sizeof(http_code))
                http_code=500;
            //last modification time check <24h or in future to prevent time drift
            const uint64_t &currentTime=time(NULL);
            if(lastModificationTimeCheck>(currentTime-Cache::timeToCache(http_code)))
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
                #endif
                if(readCache!=nullptr)
                {
                    delete readCache;
                    readCache=nullptr;
                }
                readCache=new Cache(cachefd,this);
                readCache->set_access_time(currentTime);
                #ifdef DEBUGFASTCGI
                std::cerr << "startRead() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(startRead())
                    return;
                else//corrupted, then recreate
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << pathForIndex << " corrupted, delete to recreate" << std::endl;
                    #ifdef DEBUGFASTCGI
                    std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    if(cachefd!=-1)
                        ::close(cachefd);
                    #ifdef DEBUGFASTCGI
                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << pathVar << std::endl;
                    #endif
                    ::unlink(pathVar);
                }
                return;
            }
            #ifdef HOSTSUBFOLDER
                ::mkdir(folderVar,S_IRWXU);
            #endif

            //get the ETag to compare with client
            std::string etag;
            {
                uint8_t etagBackendSize=0;
                if(::pread(cachefd,&etagBackendSize,sizeof(etagBackendSize),3*sizeof(uint64_t))==sizeof(etagBackendSize))
                {
                    char buffer[etagBackendSize];
                    if(::pread(cachefd,buffer,etagBackendSize,3*sizeof(uint64_t)+sizeof(uint8_t))==etagBackendSize)
                    {
                        etag=std::string(buffer,etagBackendSize);
                        #ifdef DEBUGFASTCGI
                        if(etag.find('\0')!=std::string::npos)
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << "close() fd: " << cachefd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                            #endif
                            if(cachefd!=-1)
                                ::close(cachefd);
                            cachefd=-1;
                            etag="etag contain \\0 abort";
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
                            #endif
                            status=Status_Idle;
                            char text[]="Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nInternal error etag 0";
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN internal error etag 0" << std::endl;
                            #endif
                            writeOutput(text,sizeof(text)-1);
                            internalWriteEnd();
                            disconnect();
                            return;
                        }
                        #endif
                    }
                }
            }
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
            #endif

            createHttpBackendInternal(cachefd,etag);
        }
    }
    else
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " Client::createHttpBackend() already http backend (abort)" << std::endl;
        abort();
    }
}

void Client::createHttpBackendInternal(int cachefd, std::string etag)
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " cachefd: " << cachefd << " " << this << " Client::createHttpBackendInternal()" << std::endl;
    #endif
    #ifdef HOSTSUBFOLDER
    const std::string pathForIndex(pathVar,26);
    #else
    const std::string pathForIndex(pathVar,17);
    #endif
    if(https)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " cachefd: " << cachefd << " " << this << std::endl;
        #endif
        Https *https=new Https(cachefd, //0 if no old cache file found
                              pathForIndex,this);
        if(https->tryConnect(host,uri,gzip,etag))
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
            #endif
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " Http::dnsError()" << std::endl;
            #endif
            //Http::dnsError()
            return;
        }
        if(http==nullptr || fastcgiid==-1 || fd==-1)//then tryConnect() have disconnected it, eg: cached Http::dnsError()
            return;
        if(Https::pathToHttps.find(pathForIndex)==Https::pathToHttps.cend())
        {
            #ifdef DEBUGFASTCGI
            if(http->cachePath.empty())
            {
                std::cerr << "Client::dnsRight(), http->cachePath.empty() can't be empty if add to Http::pathToHttp " << pathForIndex << " " << (void *)http << " " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << std::endl;
                abort();
            }
            #endif
            Https::pathToHttps[pathForIndex]=https;
        }
        else
        {
            std::cerr << "Https::pathToHttps.find(" << pathForIndex << ") already found, abort()" << std::endl;
            abort();
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " cachefd: " << cachefd << " " << this << std::endl;
        #endif
        if(http!=nullptr)
        {
            if(!http->removeClient(this))
            {
                #ifdef DEBUGFASTCGI
                std::cerr << this << " not into client list of " << http << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
            }
        }
        http=new Http(cachefd, //0 if no old cache file found
                              pathForIndex,this);
        if(http->tryConnect(host,uri,gzip,etag))
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << "http->tryConnect() ok" << std::endl;
            #endif
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " Http::dnsError()" << std::endl;
            #endif
            //Http::dnsError()
            return;
        }
        if(http==nullptr || fastcgiid==-1 || fd==-1)//then tryConnect() have disconnected it, eg: cached Http::dnsError()
            return;
        if(Http::pathToHttp.find(pathForIndex)==Http::pathToHttp.cend())
        {
            #ifdef DEBUGFASTCGI
            if(http->cachePath.empty())
            {
                std::cerr << "Client::dnsRight(), http->cachePath.empty() can't be empty if add to Http::pathToHttp " << pathForIndex << " " << (void *)http << " " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << std::endl;
                abort();
            }
            #endif
            Http::pathToHttp[pathForIndex]=http;
        }
        else
        {
            std::cerr << "Http::pathToHttp.find(" << pathForIndex << ") already found, abort()" << std::endl;
            abort();
        }
    }
}

bool Client::startRead()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " Client::startRead()" << std::endl;
    #endif
    if(!readCache->seekToContentPos())
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " Client::startRead(): !readCache->seekToContentPos(), cache corrupted?" << std::endl;
        status=Status_Idle;
        char text[]="Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nUnable to read cache (1)";
        writeOutput(text,sizeof(text)-1);
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN unable to read cache" << std::endl;
        #endif
        internalWriteEnd();
        disconnect();
        return false;
    }
    //readCache->setAsync();
    if(!readCache->seekToContentPos())
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " Client::startRead(): !readCache->seekToContentPos(), cache corrupted bis?" << std::endl;
        return false;
    }
    continueRead();
    return true;
}

bool Client::startRead(const std::string &path, const bool &partial)
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " partial: " << partial << std::endl;
    #endif

    //to drop dual event
    if(readCache!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " drop dual event" << std::endl;
        #endif
        return true;
    }

    this->partial=partial;
    //O_WRONLY -> failed, need Read too call Cache::seekToContentPos(), read used to get pos
    #ifdef DEBUGFASTCGI
    struct stat sb;
    const bool cacheWasExists=stat(path.c_str(),&sb)==0;
    if(cacheWasExists)
    {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " " << path.c_str() << " cache size: " << sb.st_size << std::endl;}
    #endif
    errno=0;
    int cachefd = ::open(path.c_str(), O_RDWR | O_NOCTTY/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    const int temperrno=errno;
    //if failed open cache
    if(cachefd==-1)
    {
        //workaround internal bug cache PATH
        const std::string temppath=path+".tmp";
        int cachefd = ::open(temppath.c_str(), O_RDWR | O_NOCTTY/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        const int temperrno2=errno;
        //if failed open cache
        if(cachefd==-1)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN unable to read cache 2 " << path << ", errno: " << temperrno << ", errno2: " << temperrno2 << ", partial: " << partial << std::endl;
            struct dirent *dp;
            DIR *dfd = opendir(".");
            if(dfd != NULL) {
                while((dp = readdir(dfd)) != NULL)
                    printf("%s ", dp->d_name);
                closedir(dfd);
            }
            printf("\n");
            #endif
            status=Status_Idle;
            char text[]="Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nUnable to read cache (2)";
            writeOutput(text,sizeof(text)-1);
            internalWriteEnd();
            disconnect();
            return false;
        }
    }

    #ifdef DEBUGFASTCGI
    const bool cacheWasExists2=stat(path.c_str(),&sb)==0;
    if(!cacheWasExists)
    {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " cache created into wrong way" << std::endl;}
    if(!cacheWasExists && cacheWasExists2)
    {std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " cache created into wrong way 2" << std::endl;}
    #endif
    #ifdef DEBUGFILEOPEN
    std::cerr << "Client::startRead() open: " << path << ", fd: " << cachefd << std::endl;
    #endif

    const off_t &s=lseek(cachefd,1*sizeof(uint64_t),SEEK_SET);
    if(s==-1)
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " unable to seek" << std::endl;
        status=Status_Idle;
        char text[]="Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nUnable to seek";
        writeOutput(text,sizeof(text)-1);
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN unable to seek" << std::endl;
        #endif
        internalWriteEnd();
        disconnect();
        return false;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
    #endif
    const uint64_t &currentTime=time(NULL);
    if(readCache!=nullptr)
    {
        delete readCache;
        readCache=nullptr;
    }
    readCache=new Cache(cachefd,this);
    readCache->set_access_time(currentTime);
    if(!readCache->seekToContentPos())
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " unable to seek to content" << std::endl;
        status=Status_Idle;
        char text[]="Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nUnable to seek to content";
        writeOutput(text,sizeof(text)-1);
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN unable to seek to content" << std::endl;
        #endif
        internalWriteEnd();
        disconnect();
        return false;
    }
    return startRead();
}

void Client::tryResumeReadAfterEndOfFile()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " Client::tryResumeReadAfterEndOfFile(): " << bodyAndHeaderFileBytesSended << std::endl;
    #endif
    if(partialEndOfFileTrigged)
        continueRead();
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " Client::tryResumeReadAfterEndOfFile() workaround: " << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        //continueRead() include into readyToWrite() -> continueRead();//workaround
        readyToWrite();
    }
}

void Client::writeOutputDropDataIfNeeded(const char * const data,const size_t &size)
{
    //send in progress, drop data because the client can't receive more
    if(!dataToWrite.empty())
        return;
    //ignore if can't push, just drop data because is streaming
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " pushWithoutWriting(), write not buffer : " << Common::binarytoHexa(data,size) << std::endl;
    #endif
    errno=0;
    if(fd!=-1)
        writeOutput(data,size);
}

void Client::continueRead()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " " << this << " Client::continueRead() start" << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
    if(readCache==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " " << this << " Client::continueRead() readCache==nullptr" << std::endl;
        #endif
        return;
    }
    if(!dataToWrite.empty())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " " << this << " Client::continueRead() !dataToWrite.empty()" << std::endl;
        #endif
        return;
    }
    #ifdef DEBUGFASTCGI
    if(http)
        std::cerr << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() << " " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " http " << http << " http->cachePath: " << http->cachePath << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
    else
        std::cerr << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() <<  " " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
    #endif
    char buffer[65535-1000];//fastcgi is limited to 65535-1000 size
    do {
        const ssize_t &s=readCache->read(buffer,sizeof(buffer));
        #ifdef DEBUGFASTCGI
        //std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " continueRead(): " << s << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        if(s<1)
        {
            if(!partial)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " internalWriteEnd();disconnect(); and !partial" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                #endif
                internalWriteEnd();
                disconnect();
            }
            else
            {
                if(http!=nullptr)
                {
                    if(http->getEndDetected())
                    {
                        partialEndOfFileTrigged=false;
                        partial=false;
                        if(dataToWrite.empty())
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " internalWriteEnd();disconnect(); and dataToWrite.empty()" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                            #endif
                            internalWriteEnd();
                            disconnect();
                        }
                    }
                    else
                    {
                        partialEndOfFileTrigged=true;
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " End of file, wait more" << std::endl;
                        #endif
                    }
                }
                else
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " http!=nullptr" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                    #endif
                    if(bodyAndHeaderFileBytesSended<=0)
                    {
                        partialEndOfFileTrigged=true;
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " End of file, wait more, bug???" << std::endl;
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " internalWriteEnd();disconnect();" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                        #endif
                        partial=false;//prevent internalWriteEnd() call this method and do infinity loop
                        partialEndOfFileTrigged=false;
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " internalWriteEnd();disconnect();" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                        #endif
                        internalWriteEnd();
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " internalWriteEnd();disconnect();" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                        #endif
                        disconnect();
                    }
                }
            }
            return;
        }
        partialEndOfFileTrigged=false;
        #ifdef DEBUGFASTCGI
        //std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " continueRead(): " << s << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        if(bodyAndHeaderFileBytesSended==0)
        {
            if(s<1)
                std::cerr << "Strange, file cache is lower than acceptable size to compute bodyAndHeaderFileBytesSended, ERROR" << std::endl;//this should never happen
            else
                bodyAndHeaderFileBytesSended+=(s-1);
        }
        else
            bodyAndHeaderFileBytesSended+=s;
        #ifdef ONFLYENCODEFASTCGI
        writeOutput(buffer,s);
        #else
        write(buffer,s);
        #endif
        #ifdef DEBUGFASTCGI
        //std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " continueRead(): " << s << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        //if can't write all
        if(!dataToWrite.empty())
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " client TCP buffer statured, return to wait buffer is empty" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << ", remain to write: " << dataToWrite.size() << std::endl;
            #endif
            return;
        }
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " end of read loop;" << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        //if can write all, try again
    } while(1);
}

void Client::cacheError()
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << std::endl;
    #endif
    status=Status_Idle;
    char text[]="Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nCache file error";
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN cache file error" << std::endl;
    #endif
    writeOutput(text,sizeof(text)-1);
    internalWriteEnd();
    disconnect();
}

void Client::readyToWrite()
{
    #ifdef DEBUGFASTCGI
    time_t t = time(NULL);
    std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << " t: " << t << std::endl;
    #endif
    if(!dataToWrite.empty())
    {
        while(!dataToWrite.empty())
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
            #endif
            errno=0;
            ssize_t writedSize=-1;
            if(fd!=-1)
                writedSize=::write(fd,dataToWrite.data(),dataToWrite.size());
            /*if(writedSize>0)
                std::cerr << this << " real write writedSize: " << writedSize << "/" << dataToWrite.size() << __FILE__ << ":" << __LINE__ <<  " : " << Common::binarytoHexa(dataToWrite.data(),writedSize)<< std::endl;*/
            #ifdef DEBUGFASTCGI
            bytesSended+=writedSize;
            #endif
            /* when nginx disconnect: errno==EPIPE
            Eg nginx log:
            upstream sent unsupported FastCGI protocol version: 0 while reading upstream, client: 2803:1920::2:10, server: cdn.confiared.com, request: "GET /ultracopier.first-world.info/files/2.2.6.1/ultracopier-windows-x86_64-2.2.6.1-setup.exe HTTP/2.0", upstream: "fastcgi://127.0.0.1:5556", host: "cdn.confiared.com" */
            if(errno!=0 && errno!=EAGAIN)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "fd: " << fd << " errno: " << errno << " writedSize: " << writedSize << " " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                #endif
                disconnect();
                return;
            }
            if(writedSize>0)
            {
                if((size_t)writedSize==dataToWrite.size())
                {
                    #ifdef DEBUGFASTCGI
                    //std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                    #endif
                    dataToWrite.clear();
                    continueRead();
                    //event to continue to read file
                    return;
                }
            }
            else
            {
                #ifdef DEBUGFASTCGI
                //std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                #endif
                return;//0 bytes writen, nothing to do
            }
            #ifdef DEBUGFASTCGI
            /*time_t t = time(NULL);
            std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << " t: " << t << " writedSize: " << writedSize << " dataToWrite.size(): " << dataToWrite.size() << std::endl;*/
            #endif
            dataToWrite.erase(0,writedSize);
            #ifdef DEBUGFASTCGI
            /*t = time(NULL);
            std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << " t: " << t << " writedSize: " << writedSize << " dataToWrite.size(): " << dataToWrite.size() << std::endl;*/
            //std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ <<  " dataToWrite: " << dataToWrite << std::endl;
            #endif

            /* wrong, just wait all the data is writted
             * if(endTriggered==true)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
                #endif
                endTriggered=false;

                #ifdef DEBUGFILEOPEN
                std::cerr << "Client::~Client(), readCache close: " << readCache << std::endl;
                #endif
                if(readCache!=nullptr)
                {
                    readCache->close();
                    delete readCache;
                    readCache=nullptr;
                }

                disconnect();
            }*/
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << "readyToWrite() " << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " fileBytesSended: " << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        continueRead();
    }
}

void Client::httpError(const std::string &errorString)
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this->fd << " " << this << " error: " << errorString << std::endl;
    #endif
    const std::string &fullContent=
            "Status: 500 Internal Server Error\r\nX-Robots-Tag: noindex, nofollow\r\nContent-type: text/plain\r\n\r\nError: "+
            errorString;
    writeOutput(fullContent.data(),fullContent.size());
    internalWriteEnd();
    disconnect();
}

int64_t Client::get_bodyAndHeaderFileBytesSended() const
{
    return bodyAndHeaderFileBytesSended;
}

bool Client::detectTimeout()
{
    #ifdef DEBUGFASTCGI
    if(http!=nullptr)
    {
        if(Http::toDebug.find(http)==Http::toDebug.cend())
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << "Client::detectTimeout(), Http::toDebug.find(http)==Http::toDebug.cend()" << std::endl;
            //abort();
        }
    }
    #endif
    if(fullyParsed)
        return false;
    const uint64_t msFrom1970=Backend::msFrom1970();
    if(creationTime>(msFrom1970-5000))
    {
        //prevent time drift
        if(creationTime>msFrom1970)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << "Client::detectTimeout(), time drift" << std::endl;
            creationTime=msFrom1970;
        }
        return false;
    }
    disconnect();
    return true;
}

bool Client::dataToWriteIsEmpty() const
{
    return dataToWrite.empty();
}

void Client::write(const char * const data,const int &size)
{
    if(size<1)
    {
        if(size<0)
        {
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", Client::write() invalid size, (abort)" << std::endl;
            abort();
        }
        return;
    }
    if(!isValid())
        return;
    if(fastcgiid==-1)
        if(fd!=-1)
            Cache::closeFD(fd);
    if(data==nullptr)
        return;
    if(!dataToWrite.empty())
    {
        dataToWrite+=std::string(data,size);
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", skip to store content: " << Common::binarytoHexa(data,size) << std::endl;
        #endif
        return;
    }
    #ifdef DEBUGFASTCGI
    //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", try real write (" << std::to_string(size) << "): " << Common::binarytoHexa(data,size) << std::endl;
    #endif

    errno=0;
    int writedSize=-1;
    if(fd!=-1)
        writedSize=::write(fd,data,size);
    #ifdef DEBUGFASTCGI
    if(writedSize>0)
    {
//        std::cerr << this << " real write writedSize: " << writedSize << " " << __FILE__ << ":" << __LINE__ <<  " : " << Common::binarytoHexa(data,writedSize) << std::endl;
    }
    #endif
    const int temperrno=errno;
    #ifdef DEBUGFASTCGI
    if(writedSize>0)
        bytesSended+=writedSize;
    #endif
    if(writedSize==size)
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", real write ok: " << Common::binarytoHexa(data,size) << std::endl;
        #endif
        return;
    }
    else
    {
        if(temperrno!=0 && temperrno!=EAGAIN)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
            #endif
            if(temperrno!=32)//if not BROKEN PIPE
            {
                switch(temperrno)
                {
                    case 104:
                        std::cerr << fd << ") error to write: " << temperrno << "ECONNRESET Connection reset by peer" << std::endl;
                    break;
                    default:
                    std::cerr << fd << ") error to write: " << temperrno << std::endl;
                    break;
                }
            }
            disconnect();
            return;
        }
    }
    if(temperrno==EAGAIN || temperrno==0)
    {
        if(temperrno==EAGAIN)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " temperrno==EAGAIN this " << this << " size " << size << " writedSize " << writedSize << std::endl;
            #endif
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " temperrno: " << temperrno << " this " << this << " size " << size << " writedSize " << writedSize << std::endl;
            #endif
        }
        if(writedSize>0)
            dataToWrite+=std::string(data+writedSize,size-writedSize);
        else
            dataToWrite+=std::string(data,size);
        return;
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " errno " << temperrno << " this " << this << " size " << size << " writedSize " << writedSize << std::endl;
        #endif
        disconnect();
        return;
    }
}

void Client::internalWriteEnd()
{
    writeEnd(get_bodyAndHeaderFileBytesSended());
}

void Client::writeEnd(const uint64_t &fileBytesSended)
{
    if(get_bodyAndHeaderFileBytesSended()!=(int64_t)fileBytesSended)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << " Client::writeEnd() get_fileBytesSended()!=(int64_t)fileBytesSended: " << bodyAndHeaderFileBytesSended << "!=" << bodyAndHeaderFileBytesSended << std::endl;
        #endif
        return;
    }
    if(!isValid())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << " Client::writeEnd() !isValid()" << std::endl;
        #endif
        return;
    }
    if(fastcgiid==-1)
        if(fd!=-1)
            Cache::closeFD(fd);
    #ifdef DEBUGFASTCGI
    const auto p1 = std::chrono::system_clock::now();
    std::cerr << std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count() << " Client::writeEnd(): " << bodyAndHeaderFileBytesSended << std::endl;
    if(http!=nullptr)
        std::cerr << http->getUrl() << " ";
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
    #endif
    disconnectFromHttp();
    if(!outputWrited)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " !outputWrited" << std::endl;
        #endif
        return;
    }
    if(partial && readCache!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " !outputWrited" << std::endl;
        #endif
        continueRead();
    }

    if(!dataToWrite.empty())
    {
        dataToWrite+=std::string(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));
        endTriggered=true;
        #ifdef DEBUGFILEOPEN
        std::cerr << "Client::writeEnd() pre, readCache close: " << readCache << std::endl;
        #endif
        if(readCache->size()>0)
            if(readCache->size()>(ssize_t)bodyAndHeaderFileBytesSended)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " fd: " << fd << " this->fd: " << this << " readCache->size()>=(ssize_t)bodyAndHeaderFileBytesSended " << " fileBytesSended: " << bodyAndHeaderFileBytesSended << " remain data to send (abort)" << std::endl;
                #endif
                // case Backend::detectTimeout() timeout while downloading, when partial already downloaded
                //abort();
            }
        return;
    }
    #ifdef DEBUGFILEOPEN
    std::cerr << "Client::writeEnd() post, readCache close: " << readCache << std::endl;
    #endif
    if(readCache!=nullptr)
    {
        readCache->close();
        delete readCache;
        readCache=nullptr;
    }

    write(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));

    fastcgiid=-1;
    if(dataToWrite.empty())
    {
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
        disconnect();
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        #endif
    }
    else
        endTriggered=true;
}

void Client::writeOutput(const char * const data, const int &size)
{
    if(size>65535-1000)
    {
        std::cerr << "writeOutput() size > 65535-1000, then greater than allowed by fastcgi, see Http::buffer and Client::continueRead() (abort)" << std::endl;
        abort();
    }
    if(!isValid())
        return;
    if(fastcgiid==-1)
        if(fd!=-1)
            Cache::closeFD(fd);
    #ifdef DEBUGFASTCGI
    //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", outputWrited: " << outputWrited << " content (size " << size << "): " << Common::binarytoHexa(data,size) << std::endl;
    #endif
    outputWrited=true;

    //FCGI_STDOUT
    #ifdef ONFLYENCODEFASTCGI
    uint16_t idbe=htobe16(fastcgiid);
    memcpy(Http::fastcgiheaderstdout+1+1,&idbe,2);
    #endif
    const uint16_t &sizebe=htobe16(size);
    memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
    write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout));
    #ifdef DEBUGFASTCGI
    //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ", Http::fastcgiheaderstdout (size " << sizeof(Http::fastcgiheaderstdout) << "): " << Common::binarytoHexa(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout)) << std::endl;
    #endif
    write(data,size);
}
