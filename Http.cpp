#include "Http.hpp"
#ifdef DEBUGFASTCGI
#include "Https.hpp"
#endif
#include "Client.hpp"
#include "Cache.hpp"
#include "Backend.hpp"
#include "Common.hpp"
#include "Dns.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sstream>
#include <algorithm>
#include <fcntl.h>
#include <chrono>

#ifdef DEBUGFASTCGI
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#ifdef DEBUGFASTCGI
std::unordered_set<Http *> Http::toDebug;
#endif
std::unordered_set<Http *> Http::toDelete;

//ETag -> If-None-Match
const char rChar[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const size_t &rCharSize=sizeof(rChar)-1;
//Todo: limit max file size 9GB
//reuse cache stale for file <20KB

std::unordered_map<std::string,Http *> Http::pathToHttp;
int Http::fdRandom=-1;
char Http::buffer[];
bool Http::useCompression=true;
bool Http::allowStreaming=false;
char Http::fastcgiheaderend[];
char Http::fastcgiheaderstdout[];

Http::Http(const int &cachefd, //0 if no old cache file found
           const std::string &cachePath, Client *client) :
    cachePath(cachePath),//to remove from Http::pathToHttp
    tempCache(nullptr),
    finalCache(nullptr),
    parsedHeader(false),
    lastReceivedBytesTimestamps(0),
    contentsize(-1),
    contentwritten(0),
    http_code(0),
    parsing(Parsing_None),
    gzip(false),
    pending(false),
    requestSended(false),
    headerWriten(false),
    backend(nullptr),
    backendList(nullptr),
    contentLengthPos(-1),
    chunkLength(-1)
{
    #ifdef DEBUGFASTCGI
    /* to fix:
     * Conditional jump or move depends on uninitialised value(s)
     * Http::checkBackend() (Http.cpp:2697) */
    memset(&m_socket,0,sizeof(m_socket));
    memset(&m_socket.sin6_addr,0,sizeof(m_socket.sin6_addr));
    #endif

    status=Status_Idle;
    #ifdef DEBUGFASTCGI
    toDebug.insert(this);
    #endif
    endDetected=false;
    fileMoved=false;
    streamingDetected=false;
    lastReceivedBytesTimestamps=Backend::msFrom1970();
    #ifdef DEBUGFASTCGI
    if(&pathToHttpList()==&Http::pathToHttp)
        std::cerr << "contructor http " << this << " uri: " << uri << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << ": " << __FILE__ << ":" << __LINE__ << std::endl;
    else
        std::cerr << "contructor https " << this << " uri: " << uri << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << ": " << __FILE__ << ":" << __LINE__ << std::endl;
    if(cachePath.empty())
    {
        std::cerr << "critical error cachePath.empty() " << this << " uri: " << uri << ": " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
    }
    #endif
    if(cachefd<=0)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::Http() cachefd==0 then tempCache(nullptr): " << this << std::endl;
        #endif
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::Http() cachefd!=0: " << this << std::endl;
        #endif
        finalCache=new Cache(cachefd,nullptr);
    }
    /*
    //while receive write to cache
    //when finish
        //unset Http to all future listener
        //Close all listener
    */

    /* simplified addClient()
     * this prevent:
     * Http::tryConnect() before addClient()
     * Http::dnsError()
     * Http::disconnectFrontend()
     * Http::checkIngrityHttpClient()
     * abort();
     * */
    clientsList.push_back(client);
    client->http=this;
}

/// \bug never call! memory leak
Http::~Http()
{
    #ifdef DEBUGFASTCGI
    if(toDebug.find(this)!=toDebug.cend())
        toDebug.erase(this);
    else
    {
        std::cerr << "Http Entry not found into global list, abort()" << std::endl;
        abort();
    }
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << "Http::~Http(): destructor " << this << " uri: " << uri << " " << status << " " << __FILE__ << ":" << __LINE__ << std::endl;
    Backend *b=backend;
    #endif

    if(status==Status_WaitDns)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "disconnectFrontend client " << this << ": " << __FILE__ << ":" << __LINE__ << " host: " << host << std::endl;
        #endif
        //Call to virtual method 'Http::isHttps' during destruction bypasses virtual dispatch [clang-analyzer-optin.cplusplus.VirtualCall]
        //Dns::dns->cancelClient(this,host,isHttps(),true);-> done over destructor
        #ifdef DEBUGFASTCGI
        std::cerr << "disconnectFrontend client " << this << ": " << __FILE__ << ":" << __LINE__ << " host: " << host << std::endl;
        #endif
        status=Status_Idle;
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        #endif
    }

    delete tempCache;
    tempCache=nullptr;
    disconnectFrontend(true);
    disconnectBackend(true);
    for(Client * client : clientsList)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " http destructor, client " << client << std::endl;
        #endif
        #ifdef ONFLYENCODEFASTCGI
        client->writeEnd(client->get_bodyAndHeaderFileBytesSended());
        #endif
        client->disconnect();
    }
    clientsList.clear();

    #ifdef DEBUGFASTCGI
    for(const Client * client : Client::clients)
    {
        if(client->http==this)
        {
            std::cerr << "Http::~Http(): destructor, remain client on this http " << __FILE__ << ":" << __LINE__ << " " << this << " client: " << client << " destructor (abort)" << std::endl;
            abort();
        }
    }
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Http::pathToHttp;
        for( const auto &n : pathToHttp )
            if(n.second==this)
            {
                std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Http::pathToHttp at " << n.first << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
    }
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Https::pathToHttps;
        for( const auto &n : pathToHttp )
            if(n.second==this)
            {
                std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Https::pathToHttps at " << n.first << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
    }
    if(Http::toDelete.find(this)!=Http::toDelete.cend())
    {
        std::cerr << "Http::~Http(): destructor post opt can't have this into Http::toDelete " << this << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
    }
    if(b!=nullptr)
    {
        if(b->http==this)
        {
            std::cerr << "Http::~Http(): destructor post backend " << (void *)b << " remain on this Http " << this << __FILE__ << ":" << __LINE__ << std::endl;
            abort();
        }
    }
    #endif
}

bool Http::tryConnect(const std::string &host, const std::string &uri, const bool &gzip, const std::string &etag)
{
    if(status!=Status_Idle)
    {
        std::cerr << "Http::tryConnect() status!=Status_Idle " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
    }
    #ifdef DEBUGFASTCGI
    const auto p1 = std::chrono::system_clock::now();
    std::cerr << std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count() << " try connect " << this << " uri: " << uri << ": " << __FILE__ << ":" << __LINE__ << std::endl;
    if(etag.find('\0')!=std::string::npos)
        std::cerr << "etag contain \\0 abort" << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    this->gzip=gzip;
    this->host=host;
    this->uri=uri;
    this->etagBackend=etag;

    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " status=Status_WaitDns" << std::endl;
    #endif
    status=Status_WaitDns;
    if(!Dns::dns->getAAAA(this,host,isHttps()))
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " CDN dns overloaded" << std::endl;
        #endif
        parseNonHttpError(Backend::NonHttpError_DnsOverloaded);
        disconnectFrontend(true);
        disconnectBackend();
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        #endif
        return false;
    }
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
    return true;
}

void Http::dnsError()
{
    if(status!=Status_WaitDns)
    {
        /*std::cerr << "Http::dnsError() status!=Status_WaitDns " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();*/
        //now it's just a warning
        std::cerr << "Http::dnsError() status!=Status_WaitDns: " << (int)status << " " << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        return;
    }
    status=Status_WaitTheContent;
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    parseNonHttpError(Backend::NonHttpError_DnsError);
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    disconnectFrontend(true);
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    disconnectBackend();
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
}

void Http::dnsWrong()
{
    if(status!=Status_WaitDns)
    {
        /*std::cerr << "Http::dnsWrong() status!=Status_WaitDns " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();*/
        //now it's just a warning
        std::cerr << "Http::dnsWrong() status!=Status_WaitDns: " << (int)status << " " << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        return;
    }
    status=Status_WaitTheContent;
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    parseNonHttpError(Backend::NonHttpError_DnsWrong);
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    disconnectFrontend(true);
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    disconnectBackend();
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
}

void Http::dnsRight(const sockaddr_in6 &sIPv6)
{
    if(status!=Status_WaitDns)
    {
        /*std::cerr << "Http::dnsRight() status!=Status_WaitDns " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();*/
        //now it's just a warning
        std::cerr << "Http::dnsRight() status!=Status_WaitDns: " << (int)status << " " << __FILE__ << ":" << __LINE__ << " " << this << std::endl;
        return;
    }
    status=Status_WaitTheContent;
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    lastReceivedBytesTimestamps=Backend::msFrom1970();
    #ifdef DEBUGFASTCGI
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &sIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
    #ifdef DEBUGDNS
    if(Dns::dns->hardcodedDns.find(host)!=Dns::dns->hardcodedDns.cend())
        if(std::string(str)!=Dns::dns->hardcodedDns.at(host))
        {
            std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
            abort();
        }
    #endif
    std::cerr << this << ": Http::dnsRight() " << host << ": " << str << " url: " << getUrl() << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    m_socket=sIPv6;
    #endif
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    tryConnectInternal(sIPv6);
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
}

bool Http::isHttps()
{
    return false;
}

bool Http::tryConnectInternal(const sockaddr_in6 &s)
{
    if(status!=Status_WaitTheContent)
    {
        std::cerr << "Http::tryConnectInternal() status!=Status_WaitTheContent " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
    }
    bool connectInternal=false;
    #ifdef DEBUGFASTCGI
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &s.sin6_addr, str, INET6_ADDRSTRLEN);
    std::cerr << this << ": Http::tryConnectInternal " << host << ": " << str << " url: " << getUrl() << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    backend=Backend::tryConnectHttp(s,this,connectInternal,&backendList);
    if(backend==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::string host2="Unknown IPv6";
        char str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &m_socket.sin6_addr, str, INET6_ADDRSTRLEN) != NULL)
            host2=str;
        #ifdef DEBUGFASTCGI
        const auto p1 = std::chrono::system_clock::now();
        std::cerr << std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count() << " " << this << ": unable to get backend for " << host << uri << " Backend::addressToHttp[" << host2 << "]" << std::endl;
        #endif

        //check here if not backend AND free backend or backend count < max
        std::string addr((char *)&m_socket.sin6_addr,16);
        //if have already connected backend on this ip
        if(Backend::addressToHttp.find(addr)!=Backend::addressToHttp.cend())
        {
            Backend::BackendList *list=Backend::addressToHttp[addr];
            if(!list->idle.empty())
            {
                std::cerr << this << " backend==nullptr and !list->idle.empty(), isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort)" << std::endl;
                abort();
            }
            if(list->busy.size()<Backend::maxBackend)
            {
                std::cerr << this << " backend==nullptr and list->busy.size()<Backend::maxBackend, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort)" << std::endl;
                abort();
            }
            unsigned int index=0;
            while(index<list->pending.size())
            {
                if(list->pending.at(index)==this)
                    break;
                index++;
            }
            if(index>=list->pending.size())
            {
                std::cerr << this << " backend==nullptr and this " << this << " not found into pending, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
        }
        else if(Backend::addressToHttps.find(addr)!=Backend::addressToHttps.cend())
        {
            Backend::BackendList *list=Backend::addressToHttps[addr];
            if(!list->idle.empty())
            {
                std::cerr << this << " backend==nullptr and !list->idle.empty(), isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            if(list->busy.size()<Backend::maxBackend)
            {
                std::cerr << this << " backend==nullptr and list->busy.size()<Backend::maxBackend, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            unsigned int index=0;
            while(index<list->pending.size())
            {
                if(list->pending.at(index)==this)
                    break;
                index++;
            }
            if(index>=list->pending.size())
            {
                std::cerr << this << " backend==nullptr and this " << this << " not found into pending, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
        }
        else
        {
            std::string host="Unknown IPv6";
            std::string host2="Unknown IPv6";
            char str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &m_socket.sin6_addr, str, INET6_ADDRSTRLEN) != NULL)
                host=str;
            if (inet_ntop(AF_INET6, &m_socket.sin6_addr, str, INET6_ADDRSTRLEN) != NULL)
                host2=str;
            std::cerr << this << " backend==nullptr into tryConnectInternal(), put in queue?, backendList: " << backendList << ", isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << host << " " << host2 << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
            abort();
        }
        #endif
    }
    #ifdef DEBUGFASTCGI
    std::cerr << this << ": http->backend=" << backend << std::endl;
    #endif
    return connectInternal && backend!=nullptr;
}

const std::string &Http::getCachePath() const
{
    return cachePath;
}

void Http::resetRequestSended()
{
    if(http_code!=0)
        return;
    parsedHeader=false;
    contentsize=-1;
    contentwritten=0;
    parsing=Parsing_None;
    requestSended=false;
    contentLengthPos=-1;
    chunkLength=-1;
}

bool Http::get_requestSended()
{
    return requestSended;
}

Http::Status Http::get_status() const
{
    return status;
}

void Http::sendRequest()
{
    if(status!=Status_WaitTheContent)
    {
        std::cerr << "Http::sendRequest() status!=Status_WaitTheContent " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
    }
    //reset lastReceivedBytesTimestamps when come from busy to pending
    lastReceivedBytesTimestamps=Backend::msFrom1970();

    #ifdef DEBUGFASTCGI
    struct timeval tv;
    gettimeofday(&tv,NULL);
    std::cerr << "[" << tv.tv_sec << "] ";
    std::cerr << "Http::sendRequest() " << this << " " << __FILE__ << ":" << __LINE__ << " uri: " << uri << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << std::endl;
    if(uri.empty())
    {
        std::cerr << "Http::readyToWrite(): but uri.empty()" << std::endl;
        flushRead();
        return;
    }
    #endif
    requestSended=true;
    if(etagBackend.empty())
    {
        std::string h(std::string("GET ")+uri+" HTTP/1.1\r\nHost: "+host+"\r\nEPNOERFT: ysff43Uy\r\n");
        if(Http::useCompression && gzip)
            h+="Accept-Encoding: gzip\r\n";
        h+="\r\n";
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        //std::cerr << h << std::endl;
        #endif
        if(!socketWrite(h.data(),h.size()))
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "ERROR to write: " << h << " errno: " << errno << std::endl;
            #endif
            startReadFromCacheAfter304();
        }
    }
    else
    {
        std::string h(std::string("GET ")+uri+" HTTP/1.1\r\nHost: "+host+"\r\nEPNOERFT: ysff43Uy\r\nIf-None-Match: "+etagBackend+"\r\n");
        if(Http::useCompression && gzip)
            h+="Accept-Encoding: gzip\r\n";
        h+="\r\n";
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        //std::cerr << h << std::endl;
        #endif
        if(!socketWrite(h.data(),h.size()))
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "ERROR to write: " << h << " errno: " << errno << std::endl;
            #endif
            startReadFromCacheAfter304();
        }
    }
    /*used for retry host.clear();
    uri.clear();*/
}

char Http::randomETagChar(uint8_t r)
{
    #ifdef DEBUGFASTCGI
    if(rCharSize!=65)
        std::cerr << __FILE__ << ":" << __LINE__ << " wrong rChar size abort" << std::endl;
    #endif
    return rChar[r%rCharSize];
}

void Http::readyToRead()
{
/*    if(var=="content-length")
    if(var=="content-type")*/
    //::read(Http::buffer

    //load into buffer the previous content

    if(backend!=nullptr && /*if file end send*/ endDetected)
    {
        int size=socketRead(Http::buffer,sizeof(Http::buffer));
        while(size>0)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " Received data while not connected to http " << __FILE__ << ":" << __LINE__ << " data: " << Common::binarytoHexa(buffer,size) << std::endl;
            #endif
            size=socketRead(Http::buffer,sizeof(Http::buffer));
        }
        return;
    }

    uint16_t offset=0;
    if(!headerBuff.empty())
    {
        offset=headerBuff.size();
        memcpy(buffer,headerBuff.data(),headerBuff.size());
    }

    #ifdef DEBUGFASTCGI
    //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    ssize_t readSize=0;
    do
    {
        errno=0;
        //disable to debug
        const ssize_t size=socketRead(buffer+offset,sizeof(buffer)-offset);
        readSize=size;
        #ifdef DEBUGFASTCGI
        //if(readSize!=-1 || offset!=0) {std::cout << __FILE__ << ":" << __LINE__ << " " << readSize << " offset: " << offset << std::endl;}
        #endif
        if(size>0)
        {
            if(status!=Status_WaitTheContent)
            {
                std::cerr << "Http::readyToRead() status!=Status_WaitTheContent " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            lastReceivedBytesTimestamps=Backend::msFrom1970();
            std::cout << "Stream block: " << Common::binarytoHexa(buffer,size) << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << " " << __FILE__ << ":" << __LINE__ << std::endl;
            if(parsing==Parsing_Content)
            {
                write(buffer,size);
                if(endDetected)
                    return;
            }
            else
            {
                uint16_t pos=0;
                if(http_code==0)
                {
                    //HTTP/1.1 200 OK
                    void *fh=nullptr;
                    while(pos<size && buffer[pos]!='\n')
                    {
                        char &c=buffer[pos];
                        if(http_code==0 && c==' ')
                        {
                            if(fh==nullptr)
                            {
                                pos++;
                                fh=buffer+pos;
                            }
                            else
                            {
                                c=0x00;
                                http_code=atoi((char *)fh);
                                #ifdef DEBUGFASTCGI
                                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " http code: " << http_code << " (" << fh << ") headerBuff.empty(): " << std::to_string(headerBuff.empty()) << " data: " << Common::binarytoHexa(buffer,size) << std::endl;
                                #endif
                                if(backend!=nullptr)
                                    backend->wasTCPConnected=true;
                                if(!HttpReturnCode(http_code))
                                {
                                    flushRead();
                                    #ifdef DEBUGFASTCGI
                                    std::cout << __FILE__ << ":" << __LINE__ << "readyToRead() !HttpReturnCode(http_code)" << std::endl;
                                    #endif
                                    return;
                                }
                                pos++;
                            }
                        }
                        else
                            pos++;
                    }
                }
                if(http_code!=200)
                {
                    flushRead();
                    #ifdef DEBUGFASTCGI
                    std::cout << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    return;
                }
                #ifdef DEBUGFASTCGI
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                pos++;

                parsing=Parsing_HeaderVar;
                uint16_t pos2=pos;
                //content-length: 5000
                if(http_code!=0)
                {
                    while(pos<size)
                    {
                        char &c=buffer[pos];
                        if(c==':' && parsing==Parsing_HeaderVar)
                        {
                            if((pos-pos2)==4)
                            {
                                std::string var(buffer+pos2,pos-pos2);
                                std::transform(var.begin(), var.end(), var.begin(),[](unsigned char c){return std::tolower(c);});
                                if(var=="etag")
                                {
                                    parsing=Parsing_ETag;
                                    pos++;
                                    #ifdef DEBUGFASTCGI
                                    std::cout << "get backend etag" << std::endl;
                                    #endif
                                }
                                else
                                {
                                    parsing=Parsing_HeaderVal;
                                    //std::cout << "1a) " << std::string(buffer+pos2,pos-pos2) << " (" << pos-pos2 << ")" << std::endl;
                                    pos++;
                                }
                            }
                            else if((pos-pos2)==16)
                            {
                                std::string var(buffer+pos2,pos-pos2);
                                std::transform(var.begin(), var.end(), var.begin(),[](unsigned char c){return std::tolower(c);});
                                if(Http::useCompression && gzip && var=="content-encoding")
                                {
                                    parsing=Parsing_ContentEncoding;
                                    pos++;
                                    #ifdef DEBUGFASTCGI
                                    //std::cout << "get backend content-encoding" << std::endl;
                                    #endif
                                }
                                else
                                {
                                    parsing=Parsing_HeaderVal;
                                    //std::cout << "1a) " << std::string(buffer+pos2,pos-pos2) << " (" << pos-pos2 << ")" << std::endl;
                                    pos++;
                                }
                            }
                            else if((pos-pos2)==14)
                            {
                                std::string var(buffer+pos2,pos-pos2);
                                std::transform(var.begin(), var.end(), var.begin(),[](unsigned char c){return std::tolower(c);});
                                if(var=="content-length")
                                {
                                    parsing=Parsing_ContentLength;
                                    pos++;
                                    #ifdef DEBUGFASTCGI
                                    //std::cout << "get backend content-length" << std::endl;
                                    #endif
                                }
                                else
                                {
                                    parsing=Parsing_HeaderVal;
                                    //std::cout << "1a) " << std::string(buffer+pos2,pos-pos2) << " (" << pos-pos2 << ")" << std::endl;
                                    pos++;
                                }
                            }
                            else if((pos-pos2)==12)
                            {
                                std::string var(buffer+pos2,pos-pos2);
                                std::transform(var.begin(), var.end(), var.begin(),[](unsigned char c){return std::tolower(c);});
                                if(var=="content-type")
                                {
                                    parsing=Parsing_ContentType;
                                    pos++;
                                    #ifdef DEBUGFASTCGI
                                    //std::cout << "get backend content-type" << std::endl;
                                    #endif
                                }
                                else
                                {
                                    parsing=Parsing_HeaderVal;
                                    //std::cout << "1a) " << std::string(buffer+pos2,pos-pos2) << " (" << pos-pos2 << ")" << std::endl;
                                    pos++;
                                }
                            }
                            else if((pos-pos2)==13)
                            {
                                std::string var(buffer+pos2,pos-pos2);
                                std::transform(var.begin(), var.end(), var.begin(),[](unsigned char c){return std::tolower(c);});
                                if(var=="cache-control")
                                {
                                    parsing=Parsing_CacheControl;
                                    pos++;
                                    #ifdef DEBUGFASTCGI
                                    //std::cout << "get backend cache-control" << std::endl;
                                    #endif
                                }
                                else if(Http::allowStreaming && var=="accept-ranges")
                                {
                                    parsing=Parsing_AcceptRanges;
                                    pos++;
                                    #ifdef DEBUGFASTCGI
                                    //std::cout << "get backend accept-ranges" << std::endl;
                                    #endif
                                }
                                else
                                {
                                    parsing=Parsing_HeaderVal;
                                    //std::cout << "1a) " << std::string(buffer+pos2,pos-pos2) << " (" << pos-pos2 << ")" << std::endl;
                                    pos++;
                                }
                            }
                            else
                            {
                                parsing=Parsing_HeaderVal;
                                //std::cout << "1a) " << std::string(buffer+pos2,pos-pos2) << " (" << pos-pos2 << ")" << std::endl;
                                pos++;
                            }
                            if(c=='\r')
                            {
                                pos++;
                                const char &c2=buffer[pos];
                                if(c2=='\n')
                                    pos++;
                            }
                            else
                                pos++;
                            pos2=pos;
                        }
                        else if(c=='\n' || c=='\r')
                        {
                            if(pos==pos2 && parsing==Parsing_HeaderVar)
                            {
                                //end of header
                                #ifdef DEBUGFASTCGI
                                std::cout << "end of header" << std::endl;
                                #endif
                                parsing=Parsing_Content;
                                if(c=='\r')
                                {
                                    pos++;
                                    const char &c2=buffer[pos];
                                    if(c2=='\n')
                                        pos++;
                                }
                                else
                                    pos++;

                                //long filetime=0;
                        /*        long http_code = 0;
                                Http_easy_getinfo (easy, HttpINFO_RESPONSE_CODE, &http_code);
                                if(http_code==304) //when have header 304 Not Modified
                                {
                                    //set_last_modification_time_check() call before
                                    for(Client * client : clientsList)
                                        client->startRead(cachePath,false);
                                    return size;
                                }

                                Httpcode res = Http_easy_getinfo(easy, HttpINFO_FILETIME, &filetime);
                                if((HttpE_OK != res))
                                    filetime=0;*/
                                if(tempCache!=nullptr)
                                {
                                    tempCache=nullptr;
                                    delete tempCache;
                                }
                                #ifdef DEBUGFASTCGI
                                std::cout << "open((cachePath+.tmp).c_str() " << (cachePath+".tmp") << std::endl;
                                #endif
                                ::unlink((cachePath+".tmp").c_str());
                                #ifdef DEBUGFASTCGI
                                std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                                #endif
                                int cachefd = open((cachePath+".tmp").c_str(), O_RDWR | O_CREAT | O_TRUNC/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                                if(cachefd==-1)
                                {
                                    if(errno==2)
                                    {
                                        #ifdef HOSTSUBFOLDER
                                        {
                                            const std::string::size_type &n=cachePath.rfind("/");
                                            const std::string basePath=cachePath.substr(0,n);
                                            mkdir(basePath.c_str(),S_IRWXU);
                                        }
                                        #endif
                                        ::unlink((cachePath+".tmp").c_str());
                                        #ifdef DEBUGFASTCGI
                                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                                        #endif
                                        cachefd = open((cachePath+".tmp").c_str(), O_RDWR | O_CREAT | O_TRUNC/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                                        if(cachefd==-1)
                                        {
                                            #ifdef DEBUGFASTCGI
                                            std::cout << "open((cachePath+.tmp).c_str() failed " << (cachePath+".tmp") << " errno " << errno << std::endl;
                                            #endif
                                            //return internal error
                                            backendError("Cache file FS access error");
                                            disconnectFrontend(true);
                                            #ifdef DEBUGFASTCGI
                                            std::cout << __FILE__ << ":" << __LINE__ << std::endl;
                                            #endif
                                            return;
                                        }
                                        else
                                        {
                                            Cache::newFD(cachefd,this,EpollObject::Kind::Kind_Cache);
                                            #ifdef DEBUGFILEOPEN
                                            std::cerr << "Http::readyToRead() open: " << cachePath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                            #endif
                                        }
                                    }
                                    else
                                    {
                                        #ifdef DEBUGFASTCGI
                                        std::cout << "open((cachePath+.tmp).c_str() failed " << (cachePath+".tmp") << " errno " << errno << std::endl;
                                        #endif
                                        //return internal error
                                        backendError("Cache file FS access error");
                                        disconnectFrontend(true);
                                        #ifdef DEBUGFASTCGI
                                        std::cout << __FILE__ << ":" << __LINE__ << std::endl;
                                        #endif
                                        return;
                                    }
                                }
                                else
                                {
                                    Cache::newFD(cachefd,this,EpollObject::Kind::Kind_Cache);
                                    #ifdef DEBUGFILEOPEN
                                    std::cerr << "Http::readyToRead() open: " << (cachePath+".tmp") << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                }

                                tempCache=new Cache(cachefd,nullptr);
                                std::string r;
                                char randomIndex[6];
                                read(Http::fdRandom,randomIndex,sizeof(randomIndex));
                                {
                                    size_t rIndex=0;
                                    while(rIndex<6)
                                    {
                                        const char &c=randomETagChar(randomIndex[rIndex]);
                                        if(c==0x00 || c=='\0')
                                            std::cerr << "etag will contain \\0 abort" << __FILE__ << ":" << __LINE__ << std::endl;
                                        r+=c;
                                        rIndex++;
                                    }
                                }

                                const int64_t &currentTime=time(NULL);
                                if(!tempCache->set_access_time(currentTime))
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_access_time(currentTime): " << (cachePath+".tmp") << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendError("Cache file FS access error");
                                    disconnectBackend();
                                    return;
                                }
                                if(!tempCache->set_last_modification_time_check(currentTime))
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_last_modification_time_check(currentTime): " << (cachePath+".tmp") << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendError("Cache file FS access error");
                                    disconnectBackend();
                                    std::cerr << this << " drop corrupted cache " << cachePath << ".tmp";
                                    {
                                        struct stat sb;
                                        const int rstat=fstat(cachefd,&sb);
                                        if(rstat==0 && sb.st_size>=0)
                                            std::cerr << " size: " << sb.st_size;
                                    }
                                    std::cerr << std::endl;
                                    ::unlink((cachePath+".tmp").c_str());//drop corrupted cache
                                    #ifdef DEBUGFASTCGI
                                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                                    #endif
                                    return;
                                }
                                if(!tempCache->set_http_code(http_code))
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_http_code(http_code): " << (cachePath+".tmp") << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendError("Cache file FS access error");
                                    disconnectBackend();
                                    return;
                                }
                                if(!tempCache->set_ETagFrontend(r))//string of 6 char
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_ETagFrontend(r): " << (cachePath+".tmp") << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendError("Cache file FS access error");
                                    disconnectBackend();
                                    return;
                                }
                                if(!tempCache->set_ETagBackend(etagBackend))//at end seek to content pos
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_ETagBackend(etagBackend): " << (cachePath+".tmp") << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendError("Cache file FS access error");
                                    disconnectBackend();
                                    return;
                                }

                                std::string header;

                                switch(http_code)
                                {
                                    case 200:
                                    break;
                                    case 404:
                                    header="Status: 404 NOT FOUND\n";
                                    break;
                                    default:
                                    header="Status: 500 Internal Server Error\n";
                                    break;
                                }
                                if(contentsize>=0)
                                    header+="Content-Length: "+std::to_string(contentsize)+"\n";
                                /*else not valid into http2
                                    header+="Transfer-Encoding: chunked\n";*/
                                if(Http::useCompression && gzip)
                                    if(!contentEncoding.empty())
                                    {
                                        header+="Content-Encoding: "+contentEncoding+"\n";
                                        contentEncoding.clear();
                                    }
                                if(!contenttype.empty())
                                    header+="Content-Type: "+contenttype+"\n";
                                else
                                    header+="Content-Type: text/html\n";
                                if(contentsize>=0)
                                    streamingDetected=false;
                                if(streamingDetected)
                                    header+="Cache-Control: no-cache,no-store,must-revalidate,max-age=0\n";
                                if(http_code==200)
                                {
                                    const std::string date=timestampsToHttpDate(currentTime);
                                    const std::string expire=timestampsToHttpDate(currentTime+Cache::timeToCache(http_code));
                                    header+="Date: "+date+"\n"
                                        "Expires: "+expire+"\n"
                                        "Cache-Control: public\n"
                                        "ETag: \""+r+"\"\n"
                                        ;//"Access-Control-Allow-Origin: *\n";
                                }
                                #ifdef DEBUGFASTCGI
                                //std::cout << "header: " << header << std::endl;
                                #endif
                                header+="\n";
                                tempCache->seekToContentPos();
                                if(headerWriten)
                                {
                                    std::cerr << "headerWriten already to true, critical error (abort)" << std::endl;
                                    abort();
                                }
                                else
                                {
                                    headerWriten=true;

                                    #ifndef ONFLYENCODEFASTCGI
                                    //fastcgi header
                                    uint16_t sizebe=htobe16(header.size());
                                    memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
                                    if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
                                    {
                                        std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                        tempCache->close();
                                        delete tempCache;
                                        tempCache=nullptr;
                                        backendError("Cache file FS access error");
                                        disconnectBackend();
                                    }
                                    else
                                    #endif
                                    if(tempCache->write(header.data(),header.size())!=(ssize_t)header.size())
                                    {
                                        std::cerr << "Header creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                        tempCache->close();
                                        delete tempCache;
                                        tempCache=nullptr;
                                        backendError("Cache file FS access error");
                                        disconnectBackend();
                                    }
                                    else
                                    {
/*                                        epoll_event event;
                                        memset(&event,0,sizeof(event));
                                        event.data.ptr = tempCache;
                                        event.events = EPOLLOUT | EPOLLRDHUP | EPOLLHUP | EPOLLRDHUP | EPOLLERR;
                                        //std::cerr << "EPOLL_CTL_ADD bis: " << cachefd << std::endl;

                                        #ifdef DEBUGFASTCGI
                                        std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                        #endif
                                        if((uint64_t)event.data.ptr<100)
                                        {
                                            std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                                            abort();
                                        }

                                        //tempCache->setAsync(); -> too hard for now*/

                                        if(getFileMoved())
                                        {
                                            for(Client * client : clientsList)
                                                client->startRead(cachePath,true);
                                        }
                                        else
                                        {
                                            for(Client * client : clientsList)
                                                client->startRead(cachePath+".tmp",true);
                                        }
                                    }
                                }
                                break;
                            }
                            else
                            {
                                switch(parsing)
                                {
                                    case Parsing_ContentLength:
                                    {
                                        uint64_t value64;
                                        std::istringstream iss(std::string(buffer+pos2,pos-pos2));
                                        iss >> value64;
                                        contentsize=value64;
                                        #ifdef DEBUGFASTCGI
                                        std::cout << "content-length: " << value64 << std::endl;
                                        #endif
                                    }
                                    break;
                                    case Parsing_ContentType:
                                        contenttype=std::string(buffer+pos2,pos-pos2);
                                    break;
                                    case Parsing_ETag:
                                        etagBackend=std::string(buffer+pos2,pos-pos2);
                                    break;
                                    case Parsing_ContentEncoding:
                                    if(Http::useCompression && gzip)
                                        contentEncoding=std::string(buffer+pos2,pos-pos2);
                                    break;
                                    case Parsing_CacheControl:
                                    //take care of no-cache to revalidate each time the ressources?
                                    //no-store = streaming, repeate the header, but copy content stream
                                    if(Http::allowStreaming)
                                    {
                                        //not split into list to improve performance
                                        if(std::string(buffer+pos2,pos-pos2).find("no-store")!=std::string::npos)
                                            streamingDetected=true;
                                    }
                                    break;
                                    case Parsing_AcceptRanges:
                                    //take care of no-cache to revalidate each time the ressources?
                                    //no-store = streaming, repeate the header, but copy content stream
                                    if(Http::allowStreaming && std::string(buffer+pos2,pos-pos2)=="none")
                                        streamingDetected=true;
                                    break;
                                    default:
                                    //std::cout << "1b) " << std::string(buffer+pos2,pos-pos2) << std::endl;
                                    break;
                                }
                                parsing=Parsing_HeaderVar;
                            }
                            if(c=='\r')
                            {
                                pos++;
                                const char &c2=buffer[pos];
                                if(c2=='\n')
                                    pos++;
                            }
                            else
                                pos++;
                            pos2=pos;

                        }
                        else
                        {
                            //std::cout << c << std::endl;
                            if(c=='\r')
                            {
                                pos++;
                                const char &c2=buffer[pos];
                                if(c2=='\n')
                                    pos++;
                            }
                            else
                                pos++;
                        }
                    }
                }
                #ifdef DEBUGFASTCGI
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                if(parsing==Parsing_Content)
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    //std::cerr << "content: " << std::string(buffer+pos,size-pos) << std::endl;
                    if(size<=pos)
                        return;
                    const size_t finalSize=size-pos;
                    const size_t rSize=write(buffer+pos,finalSize);
                    if(endDetected || rSize<=0 || rSize!=finalSize)
                        return;
                }
                else
                {
                    switch(parsing)
                    {
                        case Parsing_HeaderVar:
                        case Parsing_ContentType:
                        case Parsing_ContentLength:
                            if(headerBuff.empty() && pos2>0)
                                headerBuff=std::string(buffer+pos2,pos-pos2);
                            else
                            {
                                switch(parsing)
                                {
                                    case Parsing_ContentLength:
                                    case Parsing_ContentType:
                                        parsing=Parsing_HeaderVar;
                                        readyToRead();
                                    break;
                                    default:
                                    std::cerr << "parsing var before abort over size: " << (int)parsing << std::endl;
                                    break;
                                }
                            }
                        break;
                        default:
                        std::cerr << "parsing var before abort over size: " << (int)parsing << std::endl;
                        break;
                    }
                }
                #ifdef DEBUGFASTCGI
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
            }
            /*const char *ptr = strchr(buffer,':',size);
            if(ptr==nullptr)
            {}
            else
            {
                if(header.empty())
                {
                    if((ptr-buffer)==sizeof("content-length") && memcmp(buffer,"content-length",sizeof("content-length"))==0)
                    {}
                    //if(var=="content-type")
                }
            }*/
        }
        else
        {
            if(errno!=11 && errno!=0)
            {
                const auto p1 = std::chrono::system_clock::now();
                // errno = 111 when The remote server have close the connexion
                std::cout << this << " " << __FILE__ << ":" << __LINE__ << " " << std::chrono::duration_cast<std::chrono::seconds>(
                                p1.time_since_epoch()).count() << " socketRead(), errno " << errno << " for " << getUrl() << " parsing: " << (int)parsing << std::endl;
                /*if(errno==111 && parsing==Parsing_None)
                {
                    backendError("The remote server have close the connexion");//drop from list, then delete http
                    disconnectFrontend(true);
                    disconnectBackend();
                }*/
            }
            break;
        }
        #ifdef DEBUGFASTCGI
        //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    } while(readSize>0);
    #ifdef DEBUGFASTCGI
    //std::cout << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
}

void Http::readyToWrite()
{
    #ifdef DEBUGFASTCGI
    if(uri.empty())
    {
        std::cerr << "Http::readyToWrite(): but uri.empty() " << this << " uri: " << uri << ": " << __FILE__ << ":" << __LINE__ << std::endl;
        return;
    }
    #endif
    if(!requestSended)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Http::readyToWrite() uri: " << uri << std::endl;
        #endif
        sendRequest();
    }
}

ssize_t Http::socketRead(void *buffer, size_t size)
{
    if(backend==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << "Http::socketRead error backend==nullptr" << std::endl;
        #endif
        return -1;
    }
    if(!backend->isValid())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::socketRead error backend is not valid: " << backend << std::endl;
        #endif
        return -1;
    }
    return backend->socketRead(buffer,size);
}

bool Http::socketWrite(const void *buffer, size_t size)
{
    if(backend==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::socketWrite error backend==nullptr" << std::endl;
        #endif
        return false;
    }
    if(!backend->isValid())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::socketWrite error backend is not valid: " << backend << std::endl;
        #endif
        return false;
    }
    return backend->socketWrite(buffer,size);
}

std::unordered_map<std::string,Http *> &Http::pathToHttpList()
{
    return Http::pathToHttp;
}

std::string Http::get_host() const
{
    return host;
}

#ifdef DEBUGFASTCGI
void Http::checkIngrityHttpClient()
{
    for(const Client * client : Client::clients)
    {
        if(client!=nullptr)
        {
            if(client->http!=nullptr)
            {
                #ifdef DEBUGDNS
                if(client->http->get_status()==Status_WaitDns)
                {
                    if(!Dns::dns->queryHaveThisClient(client->http,client->http->host,client->http->isHttps()))
                    {
                        std::cerr << "Http::checkIngrityHttpClient() " << client->http << " getStatus(): Status_WaitDns but not query have this client " << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        abort();
                    }
                }
                #endif
                bool found=false;
                for(Client * search : client->http->clientsList)
                {
                    if(search==client)
                    {
                        found=true;
                        break;
                    }
                }
                if(found==false)
                {
                    std::cerr << "Http::checkIngrityHttpClient() corruption problem: for the client " << client << " http is: " << client->http << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
        }
    }
    Dns::dns->checkCorruption();
    for(const Http * http : Http::toDebug)
    {
        if(http!=nullptr)
        {
            for(Client * search : http->clientsList)
            {
                if(search==nullptr)
                {
                    std::cerr << "Http::checkIngrityHttpClient() search client nullptr " << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
                else
                {
                    if(search->http!=http)
                    {
                        std::cerr << "Http::checkIngrityHttpClient() search->http!=http " << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        abort();
                    }
                }
            }
        }
    }
}
#endif

//always call disconnectFrontend() before disconnectBackend()
void Http::disconnectFrontend(const bool &force)
{
    #ifdef DEBUGFASTCGI
    std::cerr << "disconnectFrontend " << this << " uri: " << uri << ": " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
    std::cerr << "contentsize: " << contentsize << ", contentwritten: " << contentwritten << " " << __FILE__ << ":" << __LINE__ << " force " <<  force << std::endl;
    //checkIngrityHttpClient();->can be into intermediate state: Client::createHttpBackend() -> Http::dnsError() -> Http::disconnectFrontend()
    std::cerr << __FILE__ << ":" << __LINE__ << " post Http::disconnectFrontend() checkIngrityHttpClient()" << std::endl;
    #endif
    std::vector<Client *> clientsList=this->clientsList;//clone list, can't work on list directly because will be removed item by
    if(force || !endDetected)
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << "disconnectFrontend force " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        for(Client * client : clientsList)
        {
            #ifdef ONFLYENCODEFASTCGI
            client->writeEnd(client->get_bodyAndHeaderFileBytesSended());//contain Client::disconnectFromHttp()
            #endif
            client->disconnect();
            #ifdef DEBUGFASTCGI
            std::cerr << "disconnectFrontend client: " << client << ": " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
        this->clientsList.clear();
        #ifdef DEBUGFASTCGI
        std::cerr << "disconnectFrontend force end " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    }
    else
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << "disconnectFrontend pre selective " << __FILE__ << ":" << __LINE__ << std::endl;
        if(!endDetected)
        {
            std::cerr << "endDetected is false, should not occur in selective " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
            abort();
        }
        #endif
        for(Client * client : clientsList)
        {
            /*if(client->endDetected() && client->dataToWriteIsEmpty())
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "Http::disconnectFrontend() " << __FILE__ << ":" << __LINE__ << " client->get_fileBytesSended()>=contentsize: " << client->get_bodyFileBytesSended() << ">=" << contentsize << std::endl;
                #endif
                client->writeEnd(client->get_bodyFileBytesSended());//contain Client::disconnectFromHttp()
                client->disconnect();
                #ifdef DEBUGFASTCGI
                std::cerr << "disconnectFrontend client: " << client << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
            }
            else*/
                client->continueRead();
        }
        //this->clientsList.clear();-> client slow remain connected
        #ifdef DEBUGFASTCGI
        //std::cerr << "disconnectFrontend post selective " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    }
    #ifdef DEBUGFASTCGI
    //std::cerr << "disconnectFrontend pre checkIngrityHttpClient() " << __FILE__ << ":" << __LINE__ << std::endl;
    checkIngrityHttpClient();
    //std::cerr << "disconnectFrontend post checkIngrityHttpClient() " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    //disconnectSocket();
    if(!this->clientsList.empty())
        return;

    #ifdef DEBUGFASTCGI
    for(const Client * client : Client::clients)
    {
        if(client->http==this)
        {
            std::cerr << "Http::disconnectFrontend(): remain client on this http " << __FILE__ << ":" << __LINE__ << " " << this << " client:" << client << " client->http->clientsList.size() " << client->http->clientsList.size() << " (abort)" << std::endl;
            abort();
        }
    }
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
    if(cachePath.empty())
        std::cerr << "Http::disconnectFrontend() cachePath.empty()" << std::endl;
    else
    {
        std::unordered_map<std::string,Http *> &pathToHttp=pathToHttpList();
        if(pathToHttp.find(cachePath)==pathToHttp.cend())
            std::cerr << "Http::pathToHttp.find(" << cachePath << ")==Http::pathToHttp.cend()" << std::endl;
    }
    #endif
    /* generate: ./Backend.cpp:344 http 0x68d2630 is finished, will be destruct
./Backend.cpp:421
0x68d2630: http->backend=null and !backendList->pending.empty()
Http::backendError(Internal error, !haveUrlAndFrontendConnected), but pathToHttp.find(13C1FCE29C43F20D) not found (abort) 0x68d3920
     *
     * if(!cachePath.empty())
    {
        std::unordered_map<std::string,Http *> &pathToHttp=pendingList();
        if(pathToHttp.find(cachePath)!=pathToHttp.cend())
        {
            std::cerr << "Http::disconnectFrontend(), erase pathToHttp.find(" << cachePath << ") " << this << std::endl;
            pathToHttp.erase(cachePath);
        }
        #ifdef DEBUGFASTCGI
        else
            std::cerr << this << " disconnectFrontend cachePath not found: " << cachePath << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    }
    #ifdef DEBUGFASTCGI
    else
        std::cerr << this << " disconnectFrontend cachePath not found: " << cachePath << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif*/
    /* can be in progress on backend {
        std::string cachePathTmp=cachePath+".tmp";
        if(!cachePathTmp.empty())
        {
            std::unordered_map<std::string,Http *> &pathToHttp=pendingList();
            if(pathToHttp.find(cachePathTmp)!=pathToHttp.cend())
                pathToHttp.erase(cachePathTmp);
            #ifdef DEBUGFASTCGI
            else
                std::cerr << this << " disconnectFrontend cachePath not found: " << cachePathTmp << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
        #ifdef DEBUGFASTCGI
        else
            std::cerr << this << " disconnectFrontend cachePath not found: " << cachePathTmp << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    }*/

    url.clear();
    headerBuff.clear();

    if(!contenttype.empty())
    {
        contenttype.clear();
        /*if(backend==nullptr && clientsList.empty() && !isAlive() && contenttype.empty())
            Http::toDelete.insert(this);*/
    }
}

bool Http::haveUrlAndFrontendConnected() const
{
    return !host.empty() && !uri.empty() && !clientsList.empty();
}

bool Http::isWithClient() const
{
    return !clientsList.empty();
}

bool Http::isAlive() const
{
    return !host.empty() && !uri.empty();
}

bool Http::startReadFromCacheAfter304()
{
    bool ok=false;
    if(finalCache!=nullptr)
    {
        if(!finalCache->set_last_modification_time_check(time(NULL)))
        {
            std::cerr << this << " drop corrupted cache " << cachePath << ".tmp";
            {
                struct stat sb;
                const int rstat=fstat(finalCache->getFD(),&sb);
                if(rstat==0 && sb.st_size>=0)
                    std::cerr << " size: " << sb.st_size;
            }
            std::cerr << std::endl;
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
            #endif
            ::unlink((cachePath+".tmp").c_str());//drop corrupted cache
        }
        else
            ok=true;
    }
    //send file to listener
    if(ok)
    {
        for(Client * client : clientsList)
        {
            #ifdef DEBUGFASTCGI
            std::cout << "send file to listener: " << client << std::endl;
            #endif
            client->startRead(cachePath,false);
        }
        return true;
    }
    else
        return false;
}

//return true if need continue
bool Http::HttpReturnCode(const int &errorCode)
{
    if(errorCode==200)
        return true;
    if(errorCode==304) //when have header 304 Not Modified
    {
        #ifdef DEBUGFASTCGI
        std::cout << "304 http code!, cache already good" << std::endl;
        #endif
        if(startReadFromCacheAfter304())
            return false;
    }
    const std::string errorString("Http "+std::to_string(errorCode));
    for(Client * client : clientsList)
        client->httpError(errorString);
    disconnectFrontend(true);
    return false;
    //disconnectSocket();
}

bool Http::backendError(const std::string &errorString)
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Http::backendError(" << errorString << "), erase pathToHttp.find(" << cachePath << ") " << this << std::endl;
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " client: ,clientsList size: " << clientsList.size();
    for(const Client * c : clientsList)
        std::cerr << " " << c;
    std::cerr << std::endl;
    #endif
    for(Client * client : clientsList)
        client->httpError(errorString);
    disconnectFrontend(true);
    if(!cachePath.empty())
    {
        std::unordered_map<std::string,Http *> &pathToHttp=pathToHttpList();
        #ifdef DEBUGFASTCGI
        if(tempCache!=nullptr)
        {
            if(pathToHttp.find(cachePath+".tmp")==pathToHttp.cend())
            {
                std::cerr << "Http::backendError(" << errorString << "), but pathToHttp.find(" << cachePath+".tmp" << ") not found (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort(); have low chance to pass here
            }
            else if(pathToHttp.at(cachePath+".tmp")!=this)
            {
                std::cerr << "Http::backendError(" << errorString << "), but pathToHttp.find(" << cachePath+".tmp" << ")!=this (abort) " << this << std::endl;
                //abort();
            }
            else
                std::cerr << "Http::backendError(" << errorString << "), erase pathToHttp.find(" << cachePath+".tmp" << ") " << this << std::endl;
        }
        if(finalCache!=nullptr)
        {
            if(pathToHttp.find(cachePath)==pathToHttp.cend())
            {
                std::cerr << "Http::backendError(" << errorString << "), but pathToHttp.find(" << cachePath << ") not found (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort();
            }
            else if(pathToHttp.at(cachePath)!=this)
            {
                std::cerr << "Http::backendError(" << errorString << "), but pathToHttp.find(" << cachePath << ")!=this (abort) " << this << std::endl;
                //abort();
            }
            else
                std::cerr << "Http::backendError(" << errorString << "), erase pathToHttp.find(" << cachePath << ") " << this << std::endl;
        }
        #endif
        //if(finalCache!=nullptr) -> file descriptor can be NOT open due to timeout while Http object is in pending queue
        {
            #ifdef DEBUGFASTCGI
            if(&pathToHttp==&Http::pathToHttp)
                std::cerr << "pathToHttp.erase(" << cachePath << ") " << this << std::endl;
            if(&pathToHttp==&Https::pathToHttps)
                std::cerr << "pathToHttps.erase(" << cachePath << ") " << this << std::endl;
            #endif
            pathToHttp.erase(cachePath);
        }
        //if(tempCache!=nullptr) -> file descriptor can be NOT open due to timeout while Http object is in pending queue
        {
            #ifdef DEBUGFASTCGI
            if(&pathToHttp==&Http::pathToHttp)
                std::cerr << "pathToHttp.erase(" << cachePath+".tmp" << ") " << this << std::endl;
            if(&pathToHttp==&Https::pathToHttps)
                std::cerr << "pathToHttps.erase(" << cachePath+".tmp" << ") " << this << std::endl;
            #endif
            pathToHttp.erase(cachePath+".tmp");
        }
        cachePath.clear();
    }
    #ifdef DEBUGFASTCGI
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Http::pathToHttp;
        for( const auto &n : pathToHttp )
            if(n.second==this)
            {
                std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Http::pathToHttp at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                abort();
            }
    }
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Https::pathToHttps;
        for( const auto &n : pathToHttp )
            if(n.second==this)
            {
                std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Https::pathToHttps at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                abort();
            }
    }
    #endif
    return false;
    //disconnectSocket();
}

std::string Http::getUrl() const
{
    if(host.empty() && uri.empty())
        return "no url";
    else
        return "http://"+host+uri;
}

void Http::flushRead()
{
    endDetected=true;
    disconnectFrontend(false);
    disconnectBackend();
    while(socketRead(Http::buffer,sizeof(Http::buffer))>0)
    {}
}

void Http::parseNonHttpError(const Backend::NonHttpError &error)
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " error: " << (int)error << std::endl;
    #endif
    switch(error)
    {
        case Backend::NonHttpError_AlreadySend:
        {
            const std::string &errorString("Tcp request already send (internal error)");
            for(Client * client : clientsList)
                client->httpError(errorString);
        }
        break;
        case Backend::NonHttpError_Timeout:
        {
            const std::string &errorString("Http timeout, too many time without data (internal error)");
            for(Client * client : clientsList)
                client->httpError(errorString);
        }
        break;
        case Backend::NonHttpError_DnsError:
        {
            const std::string &errorString("Dns error");
            for(Client * client : clientsList)
                client->httpError(errorString);
        }
        break;
        case Backend::NonHttpError_DnsWrong:
        {
            const std::string &errorString("This site DNS (AAAA entry) is not into Confiared IPv6 range");
            for(Client * client : clientsList)
                client->httpError(errorString);
        }
        break;
        case Backend::NonHttpError_DnsOverloaded:
        {
            const std::string &errorString("Overloaded CDN Dns");
            for(Client * client : clientsList)
                client->httpError(errorString);
        }
        break;
        default:
        {
            const std::string &errorString("Unknown non HTTP error");
            for(Client * client : clientsList)
                client->httpError(errorString);
        }
        break;
    }
}

//always call disconnectFrontend() before disconnectBackend()
void Http::disconnectBackend(const bool fromDestructor)
{
    #ifdef DEBUGFASTCGI
    std::cerr << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() << " Http::disconnectBackend() " << this << ", fromDestructor: " << fromDestructor <<  std::endl;
    #endif

    if(finalCache!=nullptr)
    {
        #ifdef DEBUGFILEOPEN
        std::cerr << "Http::disconnectBackend() post, finalCache close: " << finalCache << std::endl;
        #endif
        finalCache->close();
    }
    const char * const cstr=cachePath.c_str();
    //todo, optimise with renameat2(RENAME_EXCHANGE) if --flatcache + destination
    if(tempCache!=nullptr)
    {
        #ifdef DEBUGFILEOPEN
        std::cerr << "Http::disconnectBackend() post, tempCache close: " << tempCache << std::endl;
        #endif
        bool moveTempToFinal=true;
        const ssize_t &tempSize=tempCache->size();
        if(tempSize<25)
        {
            tempCache->close();
            std::cerr << this << " " << (cachePath+".tmp") << " corrupted temp file: " << tempCache->size() << " fd: " << tempCache->getFD() << " (abort)" << std::endl;
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
            #endif
            ::unlink(cstr);
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
            #endif
            ::unlink((cachePath+".tmp").c_str());
            moveTempToFinal=false;
            //abort();
        }
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::disconnectBackend() " << (cachePath+".tmp") << " temp file size: " << tempSize << " (close)" << std::endl;
        #endif

        tempCache->close();
        if(moveTempToFinal)
        {
            struct stat sb;
            const int rstat=stat((cachePath+".tmp").c_str(),&sb);
            if(rstat==0)
            {
                if(sb.st_size<100000000)
                {
                    if(sb.st_size>25)
                    {
                        #ifdef DEBUGFASTCGI
                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
                        #endif
                        ::unlink(cstr);
                        if(rename((cachePath+".tmp").c_str(),cstr)!=0)
                        {
                            if(errno==2)
                            {
                                #ifdef HOSTSUBFOLDER
                                {
                                    const std::string::size_type &n=cachePath.rfind("/");
                                    const std::string basePath=cachePath.substr(0,n);
                                    mkdir(basePath.c_str(),S_IRWXU);
                                }
                                #endif
                                if(rename((cachePath+".tmp").c_str(),cstr)!=0)
                                {
                                    std::cerr << "unable to move " << cachePath << ".tmp to " << cachePath << ", errno: " << errno << std::endl;
                                    #ifdef DEBUGFASTCGI
                                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                                    #endif
                                    ::unlink((cachePath+".tmp").c_str());
                                }
                            }
                            else
                            {
                                std::cerr << "unable to move " << cachePath << ".tmp to " << cachePath << ", errno: " << errno << std::endl;
                                #ifdef DEBUGFASTCGI
                                std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                                #endif
                                ::unlink((cachePath+".tmp").c_str());
                            }
                        }
                        else
                        {
                            #ifdef DEBUGFASTCGI
                            std::cout << __FILE__ << ":" << __LINE__ << " move: " << (cachePath+".tmp") << " to " << cstr << std::endl;
                            #endif
                            fileMoved=true;
                        }
                    }
                    else
                    {
                        std::cerr << "Too small to be saved (abort): " << cachePath+".tmp" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        #ifdef DEBUGFASTCGI
                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                        #endif
                        ::unlink(cstr);
                        ::unlink((cachePath+".tmp").c_str());
                    }
                }
                else
                {
                    std::cerr << "Too big to be saved (abort): " << cachePath+".tmp" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    #ifdef DEBUGFASTCGI
                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
                    #endif
                    ::unlink(cstr);
                    ::unlink((cachePath+".tmp").c_str());
                }
            }
        }
        else
        {
            std::cerr << "Not found: " << cachePath+".tmp" << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cachePath+".tmp") << std::endl;
            #endif
            ::unlink(cstr);
            ::unlink((cachePath+".tmp").c_str());
        }
        //disable to cache
        if(!Cache::enable)
        {
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
            #endif
            ::unlink(cstr);
        }

        //clean to don't try reuse it, else write else don't do it
        delete tempCache;
        tempCache=nullptr;
    }

    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " disconnect http " << this << " from backend " << backend << std::endl;
    #endif
    //remove from busy, should never be into idle
    if(backend!=nullptr)
        backend->downloadFinished();
    else
    {
        //remove from pending
        if(backendList!=nullptr)
        {
            unsigned int index=0;
            while(index<backendList->pending.size())
            {
                if(backendList->pending.at(index)==this)
                    break;
                index++;
            }
            if(index>=backendList->pending.size())
                std::cerr << this << " backend==nullptr and this " << this << " not found into pending, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
            else
                backendList->pending.erase(backendList->pending.cbegin()+index);
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " backendList==nullptr WARNING " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
    }
    #ifdef DEBUGFASTCGI
    if(backend!=nullptr && backend->http==this)
    {
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ": backend->http==this, backend: " << backend << " (abort)" << std::endl;
        abort();
    }
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ": backend=nullptr" << std::endl;

    //if this can be located into another backend, then error
    for( const auto& n : Backend::addressToHttp )
    {
        const Backend::BackendList * list=n.second;
        for(const Backend * b : list->busy)
            if(b->http==this)
            {
                std::cerr << this << ": backend->http==this, backend http: " << backend << " " << getUrl() << " (abort)" << std::endl;
                //abort();//why this is an error?
            }
    }
    for( const auto& n : Backend::addressToHttps )
    {
        const Backend::BackendList * list=n.second;
        for(const Backend * b : list->busy)
            if(b->http==this)
            {
                std::cerr << this << ": backend->http==this, backend https: " << backend << " " << getUrl() << " (abort)" << std::endl;
                //abort();//why this is an error?
            }
    }
    #endif
    backend=nullptr;
    backendList=nullptr;

    #ifdef DEBUGFASTCGI
    std::cerr << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() << " disconnectBackend " << this << " uri: " << uri << ": " << __FILE__ << ":" << __LINE__
        << " backend: " << (void *)backend
        << " clientsList size: " << std::to_string((int)clientsList.size())
        << " isAlive(): " << (int)isAlive()
        << " contenttype.size(): " << std::to_string((int)contenttype.size())
        << std::endl;
    #endif

    if(backend==nullptr && isAlive()
            /* contenttype.empty() -> empty if never try download due to timeout*/
            )
    {
        if(!clientsList.empty())
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "disconnectBackend " << this << " uri: " << uri << ": " << __FILE__ << ":" << __LINE__
                << " WARNING clientsList size: " << std::to_string((int)clientsList.size())
                << " can be: "
                << std::endl;
            std::cerr << " - in case of timeout before start to download" << std::endl;
            std::cerr << " - client TCP buffer statured, return to wait buffer is empty" << std::endl;
            #endif
            return;
        }
        if(!fromDestructor)
        {
            #ifdef DEBUGFASTCGI
            if(Http::toDebug.find(this)==Http::toDebug.cend())
            {
                std::cerr << this << " Http::toDelete.insert() failed because not into debug" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            else
                std::cerr << this << " Http::toDelete.insert() ok" << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            Http::toDelete.insert(this);
            #ifdef DEBUGFASTCGI
            for(const Client * client : Client::clients)
            {
                if(client->http==this)
                {
                    std::cerr << "Http::disconnectBackend(): remain client on this http " << __FILE__ << ":" << __LINE__ << " " << this << " client: " << client << " (abort)" << std::endl;
                    abort();
                }
            }
            for( const auto &n : Backend::addressToHttp )
            {
                for( const auto &m : n.second->busy )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << std::endl;
                        abort();
                    }
                }
                for( const auto &m : n.second->idle )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << std::endl;
                        abort();
                    }
                }
                for( const auto &m : n.second->pending )
                {
                    if(m==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << std::endl;
                        abort();
                    }
                }
            }
            for( const auto &n : Backend::addressToHttps )
            {
                for( const auto &m : n.second->busy )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << std::endl;
                        abort();
                    }
                }
                for( const auto &m : n.second->idle )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << std::endl;
                        abort();
                    }
                }
                for( const auto &m : n.second->pending )
                {
                    if(m==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << std::endl;
                        abort();
                    }
                }
            }
            #endif
        }
    }
    if(!cachePath.empty())
    {
        #ifdef DEBUGFASTCGI
        std::string pathToHttpVar="pathToHttp";
        if(&pathToHttpList()!=&Http::pathToHttp)
            pathToHttpVar="pathToHttps";
        #endif
        std::unordered_map<std::string,Http *> &pathToHttp=pathToHttpList();
        if(pathToHttp.find(cachePath)!=pathToHttp.cend())
        {
            #ifdef DEBUGFASTCGI
            if(pathToHttp.at(cachePath)!=this)
            {
                std::cerr << "Http::disconnectBackend(), but " << pathToHttpVar << ".find(" << cachePath << ") found but not this (abort) " << pathToHttp.at(cachePath) << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort();
            }
            else
            #endif
            //std::cerr << "Http::disconnectBackend(), erase " << pathToHttpVar << ".find(" << cachePath << ") " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            pathToHttp.erase(cachePath);
        }
        #ifdef DEBUGFASTCGI
        else
            std::cerr << this << " disconnectFrontend cachePath not found: " << cachePath << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        std::string cachePathTmp=cachePath+".tmp";
        if(pathToHttp.find(cachePathTmp)!=pathToHttp.cend())
        {
            #ifdef DEBUGFASTCGI
            if(pathToHttp.at(cachePathTmp)!=this)
            {
                std::cerr << "Http::disconnectBackend(), but " << pathToHttpVar << ".find(" << cachePathTmp << ") found but not this (abort) " << pathToHttp.at(cachePathTmp) << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort();
            }
            else
            #endif
            //std::cerr << "Http::disconnectBackend(), erase " << pathToHttpVar << ".find(" << cachePathTmp << ") " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            pathToHttp.erase(cachePathTmp);
        }
        #ifdef DEBUGFASTCGI
        else
            std::cerr << this << " disconnectFrontend cachePath not found: " << cachePathTmp << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
    }
    #ifdef DEBUGFASTCGI
    else
        std::cerr << this << " disconnectFrontend cachePath not found: " << cachePath << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Http::pathToHttp;
        for( const auto &n : pathToHttp )
            if(n.second==this)
            {
                std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Http::pathToHttp at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                abort();
            }
    }
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Https::pathToHttps;
        for( const auto &n : pathToHttp )
            if(n.second==this)
            {
                std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Https::pathToHttps at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                abort();
            }
    }
    #endif

    cachePath.clear();
    if(status==Status_WaitDns)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "disconnectFrontend client " << this << ": " << __FILE__ << ":" << __LINE__ << " host: " << host << std::endl;
        #endif
        Dns::dns->cancelClient(this,host,isHttps(),true);
        #ifdef DEBUGFASTCGI
        std::cerr << "disconnectFrontend client " << this << ": " << __FILE__ << ":" << __LINE__ << " host: " << host << std::endl;
        #endif
        status=Status_Idle;
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        #endif
    }
    host.clear();
    uri.clear();
    etagBackend.clear();
    //lastReceivedBytesTimestamps=0;
    #ifdef DEBUGFASTCGI
    std::cerr << "disconnectFrontend client " << this << ": " << __FILE__ << ":" << __LINE__ << " host: " << host << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << std::endl;
    #endif
    requestSended=false;
    endDetected=false;
    fileMoved=false;
}

void Http::addClient(Client * client)
{
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " add client: " << client << " clientsList.size(): " << std::to_string(clientsList.size()) << " client fd: " << client->getFD() << " isAlive: " << isAlive() << " getEndDetected(): " << getEndDetected() << " getFileMoved(): " << getFileMoved() << std::endl;
    if(cachePath.empty())
        std::cerr << "addClient() cachePath.empty()" << std::endl;
    else
    {
        std::unordered_map<std::string,Http *> &pathToHttp=pathToHttpList();
        if(pathToHttp.find(cachePath)==pathToHttp.cend())
            std::cerr << "Http::pathToHttp.find(" << cachePath << ")==Http::pathToHttp.cend()" << std::endl;
    }
    #endif
    #ifdef DEBUGFASTCGI
    if(cachePath.empty())
    {
        {
            std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Http::pathToHttp;
            for( const auto &n : pathToHttp )
                if(n.second==this)
                {
                    std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Http::pathToHttp at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                    abort();
                }
        }
        {
            std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Https::pathToHttps;
            for( const auto &n : pathToHttp )
                if(n.second==this)
                {
                    std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Https::pathToHttps at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                    abort();
                }
        }
    }
    #endif
    if(host.empty() || uri.empty())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Add client to dead http url downloader: " << client << std::endl;
        #endif
        client->httpError("Add client to dead http url downloader");
        return;
    }

    //drop performance, but more secure, remove when more stable
    size_t i=0;
    while(i<clientsList.size())
    {
        if(clientsList.at(i)==client)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " dual addClient detected: " << client << std::endl;
            #endif
            return;
        }
        i++;
    }

    clientsList.push_back(client);
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " post check dual client + host+uri not empty" << std::endl;
    #endif
    if(tempCache)
    {
        if(getFileMoved())
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " tempCache!=nullptr getFileMoved() cachePath: " << cachePath << std::endl;
            #endif
            client->startRead(cachePath,false);
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " tempCache!=nullptr !getFileMoved() cachePath: " << cachePath << std::endl;
            #endif
            client->startRead(cachePath+".tmp",!getEndDetected());
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " tempCache==nullptr cachePath: " << cachePath << " getEndDetected(): " << getEndDetected() << std::endl;
        #endif
    }
    #ifdef DEBUGFASTCGI
    if(backend==nullptr)
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " backend==nullptr cachePath: " << cachePath << std::endl;
    else
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " backend " << backend << " cachePath: " << cachePath << std::endl;
    #endif
    // can be without backend asigned due to max backend
}

bool Http::removeClient(Client * client)
{
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " remove client: " << client << " cachePath: " << cachePath << std::endl;
    #endif
    #ifdef DEBUGFASTCGI
    if(cachePath.empty())
    {
        {
            std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Http::pathToHttp;
            for( const auto &n : pathToHttp )
                if(n.second==this)
                {
                    std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Http::pathToHttp at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                    abort();
                }
        }
        {
            std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Https::pathToHttps;
            for( const auto &n : pathToHttp )
                if(n.second==this)
                {
                    std::cerr << "Http::~Http(): destructor post opt this " << this << " can't be into Https::pathToHttps at " << n.first << " " << __FILE__ << ":" << __LINE__ << " cachePath: " << cachePath << std::endl;
                    abort();
                }
        }
    }
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " remove client: " << client << " cachePath: " << cachePath << std::endl;
    #endif
    //some drop performance at exchange of bug prevent
    size_t i=0;
    size_t itemDropped=0;
    while(i<clientsList.size())
    {
        if(clientsList.at(i)==client)
        {
            client->http=nullptr;//now unlinked with this backend, prevent integrity violation bottom
            clientsList.erase(clientsList.cbegin()+i);
            itemDropped++;
            //return true;
        }
        else
            i++;
    }
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " remove client: " << client << " cachePath: " << cachePath << " clientsList size: " << clientsList.size();
    for(const Client * c : clientsList)
        std::cerr << " " << c;
    if(backend==nullptr)
        std::cerr << " backend==nullptr";
    else
        std::cerr << " backend!=nullptr";
    if(isAlive())
        std::cerr << " isAlive()";
    else
        std::cerr << " !isAlive()";
    std::cerr << std::endl;
    #endif
    //return false;
    #ifdef DEBUGFASTCGI
    if(itemDropped!=1)
    {
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " remove client failed: " << client << ", itemDropped: " << itemDropped << " cachePath: " << cachePath << std::endl;
        abort();
    }
    #endif
    bool retVal=(itemDropped==1);

    //integrity violation if not client->http=null;
    if(!isWithClient())
    {
        std::unordered_map<std::string,Http *> &pathToHttp=pathToHttpList();
        #ifdef DEBUGFASTCGI
        if(tempCache!=nullptr)
        {
            if(pathToHttp.find(cachePath+".tmp")==pathToHttp.cend())
            {
                std::cerr << "Http::removeClient(), but pathToHttp.find(" << cachePath+".tmp" << ") not found (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort(); have low chance to pass here
            }
            else if(pathToHttp.at(cachePath+".tmp")!=this)
            {
                std::cerr << "Http::removeClient(), but pathToHttp.find(" << cachePath+".tmp" << ")!=this (abort) " << this << std::endl;
                //abort();
            }
            else
                std::cerr << "Http::removeClient(), erase pathToHttp.find(" << cachePath+".tmp" << ") " << this << std::endl;
        }
        if(finalCache!=nullptr)
        {
            if(pathToHttp.find(cachePath)==pathToHttp.cend())
            {
                std::cerr << "Http::removeClient(), but pathToHttp.find(" << cachePath << ") not found (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort();
            }
            else if(pathToHttp.at(cachePath)!=this)
            {
                std::cerr << "Http::removeClient(), but pathToHttp.find(" << cachePath << ")!=this (abort) " << this << std::endl;
                //abort();
            }
            else
                std::cerr << "Http::removeClient(), erase pathToHttp.find(" << cachePath << ") " << this << std::endl;
        }
        #endif
        //if(finalCache!=nullptr) -> file descriptor can be NOT open due to timeout while Http object is in pending queue
        {
            #ifdef DEBUGFASTCGI
            if(&pathToHttp==&Http::pathToHttp)
                std::cerr << "pathToHttp.erase(" << cachePath << ") " << this << std::endl;
            if(&pathToHttp==&Https::pathToHttps)
                std::cerr << "pathToHttps.erase(" << cachePath << ") " << this << std::endl;
            #endif
            pathToHttp.erase(cachePath);
        }
        //if(tempCache!=nullptr) -> file descriptor can be NOT open due to timeout while Http object is in pending queue
        {
            #ifdef DEBUGFASTCGI
            if(&pathToHttp==&Http::pathToHttp)
                std::cerr << "pathToHttp.erase(" << cachePath+".tmp" << ") " << this << std::endl;
            if(&pathToHttp==&Https::pathToHttps)
                std::cerr << "pathToHttps.erase(" << cachePath+".tmp" << ") " << this << std::endl;
            #endif
            pathToHttp.erase(cachePath+".tmp");
        }


        disconnectFrontend(true);
        if(backend==nullptr)//after disconnectFrontend(), only can be !isAlive()
        {
            #ifdef DEBUGFASTCGI
            if(Http::toDebug.find(this)==Http::toDebug.cend())
            {
                std::cerr << this << " Http::toDelete.insert() failed because not into debug" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            else
                std::cerr << this << " Http::toDelete.insert() ok" << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            Http::toDelete.insert(this);
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " client list is empty, but backend is not null";
            std::cerr << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
    }

    if(!isAlive() && getEndDetected() && !isWithClient())
        flushRead();

    return retVal;


    //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " failed to remove: " << client << std::endl;
    /*auto p=std::find(clientsList.cbegin(),clientsList.cend(),client);
    if(p!=clientsList.cend())
        clientsList.erase(p);*/
}

int Http::write(const char * const data,const size_t &size)
{
    if(endDetected)
        return -1;
    if(tempCache==nullptr)
    {
        //std::cerr << "tempCache==nullptr internal error" << std::endl;
        return size;
    }

    if(contentsize>=0)
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " contentsize>=0 fixed size" << std::endl;
        #endif
        #ifndef ONFLYENCODEFASTCGI
        //fastcgi header
        uint16_t sizebe=htobe16(size);
        memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
        if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
        {
            std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
            tempCache->close();
            delete tempCache;
            tempCache=nullptr;
            backendError("Cache file write error");
            disconnectBackend();
        }
        #endif

        const size_t &writedSize=tempCache->write((char *)data,size);
        if(writedSize!=size)
        {
            std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
            tempCache->close();
            delete tempCache;
            tempCache=nullptr;
            backendError("Cache file write error");
            disconnectBackend();
        }
        contentwritten+=size;
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " contentsize: " << contentsize << ", contentwritten: " << contentwritten << std::endl;
        #endif
        if(contentsize<=contentwritten)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "contentsize<=contentwritten into Http::write() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            endDetected=true;

            #ifndef ONFLYENCODEFASTCGI
            //FCGI_END_REQUEST
            tempCache->write(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));
            #endif

            for(Client * client : clientsList)
                client->tryResumeReadAfterEndOfFile();

            disconnectFrontend(false);
            disconnectBackend();
            return size;
        }
        else
        {
            for(Client * client : clientsList)
                client->tryResumeReadAfterEndOfFile();
        }
    }
    else
    {
        #ifdef DEBUGFASTCGI
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " contentsize<0 then chunk mode" << std::endl;
        #endif
        size_t pos=0;
        size_t pos2=0;
        //content-length: 5000
        if(http_code!=0)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            while(pos<size)
            {
                if(chunkLength>0)
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                    std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                    #endif
                    if((size_t)chunkLength>(size-pos))
                    {
                        if(streamingDetected)
                        {
                            for(Client * client : clientsList)
                                client->writeOutputDropDataIfNeeded((char *)data+pos,size-pos);
                        }
                        else
                        {
                            #ifndef ONFLYENCODEFASTCGI
                            //fastcgi header
                            uint16_t sizebe=htobe16(size-pos);
                            memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
                            if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
                            {
                                std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                tempCache->close();
                                delete tempCache;
                                tempCache=nullptr;
                                backendError("Cache file write error");
                                disconnectBackend();
                            }
                            #endif

                            const size_t &writedSize=tempCache->write((char *)data+pos,size-pos);
                            (void)writedSize;
                            for(Client * client : clientsList)
                                client->tryResumeReadAfterEndOfFile();
                        }
                        chunkLength-=(size-pos);
                        if(chunkLength==0)
                            chunkLength=-1;
                        contentwritten+=(size-pos);
                        pos+=size-pos;
                        pos2=pos;
                        #ifdef DEBUGFASTCGI
                        std::cerr << this << " block read size: " << (size-pos) << ", now chunkLength: " << chunkLength << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        #endif
                    }
                    else
                    {
                        if(streamingDetected)
                        {
                            for(Client * client : clientsList)
                                client->writeOutputDropDataIfNeeded((char *)data+pos,size-pos);
                        }
                        else
                        {
                            #ifndef ONFLYENCODEFASTCGI
                            //fastcgi header
                            uint16_t sizebe=htobe16(chunkLength);
                            memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
                            if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
                            {
                                std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                tempCache->close();
                                delete tempCache;
                                tempCache=nullptr;
                                backendError("Cache file write error");
                                disconnectBackend();
                            }
                            #endif

                            const size_t &writedSize=tempCache->write((char *)data+pos,chunkLength);
                            (void)writedSize;
                            for(Client * client : clientsList)
                                client->tryResumeReadAfterEndOfFile();
                        }
                        contentwritten+=chunkLength;
                        pos+=chunkLength;
                        pos2=pos;
                        chunkLength=-1;
                        #ifdef DEBUGFASTCGI
                        std::cerr << this << " block read size: " << (size-pos) << ", now chunkLength: " << chunkLength << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        #endif
                    }
                    #ifdef DEBUGFASTCGI
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                    std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                    #endif
                }
                else
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                    std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                    #endif
                    while((size_t)pos<size)
                    {
                        char c=data[pos];
                        if(c=='\n' || c=='\r')
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                            /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                            std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                            #endif
                            if(pos2==pos)
                            {
                                if(c=='\r')
                                {
                                    pos++;
                                    const char &c2=data[pos];
                                    if(c2=='\n')
                                        pos++;
                                }
                                else
                                    pos++;
                                pos2=pos;
                            }
                            else
                            {
                                #ifdef DEBUGFASTCGI
                                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                #endif
                                if(chunkHeader.empty())
                                {
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "text: " << std::string(data+pos2,pos-pos2) << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    chunkLength=Common::hexaTo64Bits(std::string(data+pos2,pos-pos2));
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "chunkLength: " << chunkLength << std::endl;
                                    if(chunkLength==0 && std::string(data+pos2,pos-pos2)!="0")
                                    {
                                        std::cerr << "chunkLength decoding error (abort)" << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                        abort();
                                    }
                                    #endif
                                }
                                else
                                {
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "chunkHeader ban (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    abort();
                                    #endif
                                    chunkHeader+=std::string(data,pos-1);
                                    chunkLength=Common::hexaTo64Bits(chunkHeader);
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "chunkLength: " << chunkLength << std::endl;
                                    if(chunkLength==0 && chunkHeader!="0")
                                    {
                                        std::cerr << "chunkLength decoding error (2) (abort)" << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                        abort();
                                    }
                                    #endif
                                }
                                #ifdef DEBUGFASTCGI
                                std::cerr << "chunkLength: " << chunkLength << std::endl;
                                #endif
                                #ifdef DEBUGFASTCGI
                                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                                std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                                #endif
                                if(c=='\r')
                                {
                                    pos++;
                                    const char &c2=data[pos];
                                    if(c2=='\n')
                                        pos++;
                                }
                                else
                                    pos++;
                                pos2=pos;
                                #ifdef DEBUGFASTCGI
                                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                                std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                                #endif
                                break;
                            }
                            #ifdef DEBUGFASTCGI
                            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                            /*std::cerr << "parsed) " << Common::binarytoHexa(data,pos) << std::endl;
                            std::cerr << "NOT parsed) " << Common::binarytoHexa(data+pos,size-pos) << std::endl;*/
                            #endif
                        }
                        else
                            pos++;
                    }
                    #ifdef DEBUGFASTCGI
                    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    if(chunkLength==0)
                    {
                        #ifdef DEBUGFASTCGI
                        std::cerr << "chunkLength==0 into Http::write() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        checkIngrityHttpClient();
                        #endif
                        endDetected=true;

                        #ifndef ONFLYENCODEFASTCGI
                        //FCGI_END_REQUEST
                        tempCache->write(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));
                        if(!streamingDetected)
                        {
                            for(Client * client : clientsList)
                                client->tryResumeReadAfterEndOfFile();
                        }
                        #endif

                        disconnectFrontend(false);
                        disconnectBackend();
                        /*if(c=='\r')
                        {
                            pos++;
                            const char &c2=data[pos];
                            if(c2=='\n')
                                pos++;
                        }
                        else
                            pos++;*/
                        return size;
                    }
                    else if((size_t)pos>=size && chunkLength<0 && pos2<pos)
                    {
                        #ifdef DEBUGFASTCGI
                        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        #endif
                        if(chunkHeader.empty())
                        {
                            chunkHeader=std::string(data+pos2,size-pos2);
                        }
                        else
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << "chunkHeader ban (abort)" << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                            abort();
                            #endif
                        }
                    }
                }
            }
        }
    }

    return size;
    //(write partial cache)
    //open to write .tmp (mv at end)
    //std::cout << std::string((const char *)data,size) << std::endl;
}

std::string Http::timestampsToHttpDate(const int64_t &time)
{
    char buffer[256];
    struct tm *my_tm = gmtime(&time);
    if(strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", my_tm)==0)
        return std::string("Thu, 1 Jan 1970 0:0:0 GMT");
    return buffer;
}

bool Http::getEndDetected() const
{
    return endDetected;
}

bool Http::getFileMoved() const
{
    return fileMoved;
}

#ifdef DEBUGFASTCGI
void Http::checkBackend()
{
    //backendList is used for std::vector<Http *> pending;
    if(backendList!=nullptr)
    {
        if(backend==nullptr)//no backend, should be into pending, check if into pending list?
        {
            if(isAlive())
            {
                unsigned int index=0;
                while(index<backendList->pending.size())
                {
                    if(backendList->pending.at(index)==this)
                        break;
                    index++;
                }
                if(index>=backendList->pending.size())
                {
                    std::cerr << this << " backend==nullptr and this " << this << " not found into pending, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            return;
        }

        if(!backendList->idle.empty())
        {
            unsigned int index=0;
            while(index<backendList->idle.size())
            {
                if(backendList->idle.at(index)==backend)
                {
                    std::cerr << this << " located into backendList->idle, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << __FILE__ << ":" << __LINE__ << std::endl;
                    return;
                }
                index++;
            }
        }
        /*Can be in case of remoteSocketClosed and was NOT TCP connected ./Backend.cpp
        Can be normal if number of file downloaded is lower than Backend::maxBackend*/
        if(!backendList->busy.empty())
        {
            unsigned int index=0;
            while(index<backendList->busy.size())
            {
                if(backendList->busy.at(index)==backend)
                {
                    std::cerr << this << " located into backendList->busy, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << __FILE__ << ":" << __LINE__ << std::endl;
                    return;
                }
                index++;
            }
        }
        unsigned int index=0;
        while(index<backendList->pending.size())
        {
            if(backendList->pending.at(index)==this)
            {
                std::cerr << this << " found into backendList->pending but backend!=nullptr, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            index++;
        }
    }
    else
    {
        if(!endDetected)
        {
            std::string host="Unknown IPv6";
            switch(status)
            {
                case Status_WaitTheContent:
                {
                    char str[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, &m_socket.sin6_addr, str, INET6_ADDRSTRLEN) != NULL)
                        host=str;
                }
                break;
                default:
                break;
            }
            if(backend==nullptr)
            {
                if(status!=Status_WaitDns)
                    std::cerr << this << " http backend: nullptr and no backend list found, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << host << " put in queue: " << getUrl() << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << std::endl;
            }
            else
            {
                std::cerr << this << " http backend: " << backend << " and no backend list found, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << host << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                //abort();
            }
        }
    }
}
#endif

//return true if timeout
bool Http::detectTimeout()
{
    const uint64_t msFrom1970=Backend::msFrom1970();
    unsigned int secondForTimeout=5;
    if(status==Status_WaitDns)
        //timeout * server count * try
        secondForTimeout=Dns::dns->resendQueryDNS_ms()*Dns::dns->retryBeforeError();
    else if(pending)
    {
        if(requestSended)
            secondForTimeout=30;
        else
            secondForTimeout=10;
    }

    if(lastReceivedBytesTimestamps>(msFrom1970-secondForTimeout*1000))
    {
        //prevent time drift
        if(lastReceivedBytesTimestamps>msFrom1970)
        {
            std::cerr << "Http::detectTimeout(), time drift" << std::endl;
            lastReceivedBytesTimestamps=msFrom1970;
        }

        #ifdef DEBUGFASTCGI
        //check here if not backend AND free backend or backend count < max
        if(backend==nullptr && (isAlive() || !clientsList.empty()))
        {
            //if have already connected backend on this ip
            checkBackend();
        }
        #endif
        return false;
    }
    if(endDetected && !clientsList.empty())
        return false;
    if(backend!=nullptr)
        std::cerr << std::to_string(msFrom1970) << "/" << std::to_string(lastReceivedBytesTimestamps) << " Http::detectTimeout() need to quit " << this << " and quit backend " << (void *)backend << __FILE__ << ":" << __LINE__ << " clientsList.size(): " << clientsList.size() << " endDetected: " << endDetected << " url: " << getUrl() << std::endl;
    else
        std::cerr << std::to_string(msFrom1970) << "/" << std::to_string(lastReceivedBytesTimestamps) << " Http::detectTimeout() need to quit " << this << " " << __FILE__ << ":" << __LINE__ << " clientsList.size(): " << clientsList.size() << " endDetected: " << endDetected << " url: " << getUrl() << std::endl;
    #ifdef DEBUGFASTCGI
    const auto oldlastReceivedBytesTimestamps=lastReceivedBytesTimestamps;
    #endif
    lastReceivedBytesTimestamps=msFrom1970;//prevent dual Http::detectTimeout()
    if(tempCache!=nullptr)
        std::cerr << "Http::detectTimeout() tempCache: " << tempCache << " fd: " << tempCache->getFD() << " " << __FILE__ << ":" << __LINE__ << std::endl;

    if(pending && requestSended && !etagBackend.empty())
    {
        //failback to stale cache is better than fail
        //startReadFromCacheAfter304() -> included into HttpReturnCode() but HttpReturnCode() do error management
        http_code=304;
        if(!HttpReturnCode(http_code))
        {
            flushRead();
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
        return false;
    }

    //if no byte received into 600s (10m)
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " timeout details: " << oldlastReceivedBytesTimestamps << "<(" << msFrom1970 << "-" << secondForTimeout << "*1000), pending: " << pending << " requestSended: " << requestSended << " etagBackend.empty(): " << etagBackend.empty();
    if(backend!=nullptr)
    {
        std::cerr << " backend: " << backend;
        if(backend->backendList!=nullptr)
            std::cerr << " backend->backendList: " << backend << " backend->backendList->pending.size(): " << backend->backendList->pending.size();
    }
    std::cerr << std::endl;
    #endif
    parseNonHttpError(Backend::NonHttpError_Timeout);
    /*do into disconnectFrontend(true):
    for(Client * client : clientsList)
    {
        client->writeEnd();
        client->disconnect();
    }
    clientsList.clear();*/
    disconnectFrontend(true);
    if(backend!=nullptr)
    {
        disconnectBackend();
        //can't just connect the backend because the remaining data need to be consumed
        //then destroy backend too
        if(backend!=nullptr)
            backend->close();//keep the backend running, clean close
    }
    else // was in pending list
    {
        disconnectBackend();
    }
    return true;
}

std::string Http::getQuery() const
{
    std::string ret;
    char buffer[32];
    std::snprintf(buffer,sizeof(buffer),"%p",(void *)this);
    ret+=std::string(buffer);
    if(!isAlive())
        ret+=" not alive";
    else
        ret+=" alive on "+getUrl();
    switch(status)
    {
    case Status_Idle:
        ret+=" Status_Idle";
        break;
    case Status_WaitDns:
        ret+=" Status_WaitDns";
        break;
    case Status_WaitTheContent:
        ret+=" Status_WaitTheContent";
        break;
    default:
        ret+=" Status_???";
        break;
    }
    if(backend!=nullptr)
    {
        std::snprintf(buffer,sizeof(buffer),"%p",(void *)backend);
        ret+=" on backend "+std::string(buffer);
    }
    if(!clientsList.empty())
        ret+=" with "+std::to_string(clientsList.size())+" client(s)";
    ret+=" last byte "+std::to_string(lastReceivedBytesTimestamps);
    if(!etagBackend.empty())
        ret+=", etagBackend: "+etagBackend;
    if(requestSended)
        ret+=", requestSended";
    else
        ret+=", !requestSended";
    if(tempCache!=nullptr)
        ret+=", tempCache: "+cachePath;
    if(finalCache!=nullptr)
        ret+=", finalCache: "+cachePath;
    if(endDetected)
        ret+=", endDetected";
    else
        ret+=", !endDetected";
    return ret;
}
