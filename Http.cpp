#include "Http.hpp"
#include "Http3.hpp"
#include "Http3Probe.hpp"
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
std::unordered_set<Http *> Http::httpToDebug;
#endif
std::unordered_set<Http *> Http::httpToDelete;

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
bool Http::http3Enabled=false;
uint16_t Http::http3Port=443;
uint64_t Http::http3DeadlineMs=8000;
char Http::fastcgiheaderend[];
char Http::fastcgiheaderstdout[];

std::string gen_random(const int len) {
    static const char alphanum[] =
        "123456789"
        "ABCDEFGHJKMNPQRSTUVWXYZ"
        "abcdefghijkmnpqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return tmp_s;
}

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
    retryCount(0),
    pending(false),
    requestSended(false),
    headerWriten(false),
    backend(nullptr),
    backendList(nullptr),
    contentLengthPos(-1),
    chunkLength(-1),
    http3Conn(nullptr),
    http3StartedMs(0),
    resumeOffset(-1),
    skipBytes(0)
{
    memset(&m_socket,0,sizeof(m_socket));
    memset(&m_socket.sin6_addr,0,sizeof(m_socket.sin6_addr));

    status=Status_Idle;
    #ifdef DEBUGFASTCGI
    httpToDebug.insert(this);
    #endif
    endDetected=false;
    fileMoved=false;
    streamingDetected=false;
    lastReceivedBytesTimestamps=Common::msFrom1970();
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
    if(!uri.empty() && !endDetected)
        std::cerr << "Client::~Client() !uri.empty() && !endTriggered: " << uri << std::endl;
    #ifdef DEBUGFASTCGI
    if(httpToDebug.find(this)!=httpToDebug.cend())
        httpToDebug.erase(this);
    else
    {
        std::cerr << this << ": " << __FILE__ << ":" << __LINE__ << " Http Entry not found into global list, abort()" << std::endl;
        abort();
    }
    #endif
    #ifdef DEBUGFASTCGI
    std::cerr << "Http::~Http(): destructor " << this << " uri: " << uri << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << std::endl;
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
    #ifdef DEBUGDNS
    //very heavy check
    if(Dns::dns->queryHaveThisClient(this))
    {
        std::cerr << "Http::disconnectBackend(): remain http " << this << " on dns " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
        abort();
    }
    #endif

    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    if(tempCache!=nullptr)
    {
        delete tempCache;
        tempCache=nullptr;
    }
    if(http3Conn!=nullptr)
    {
        delete http3Conn;
        http3Conn=nullptr;
    }

    disconnectFrontend(true);
    disconnectBackend(true);
    for(Client * client : clientsList)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " http destructor, client " << client << std::endl;
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
    if(Http::httpToDelete.find(this)!=Http::httpToDelete.cend())
    {
        std::cerr << "Http::~Http(): destructor post opt can't have this into Http::httpToDelete " << this << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
    }
    Http::httpToDelete.erase(this);
    if(b!=nullptr)
    {
        if(b->http==this)
        {
            std::cerr << "Http::~Http(): destructor post backend " << (void *)b << " remain on this Http " << this << __FILE__ << ":" << __LINE__ << std::endl;
            abort();
        }
    }
    #endif

    //to be safe, delete when all is stable
    for( const auto &n : Backend::addressToHttp )
    {
        for( const auto &m : n.second->busy )
        {
            if(m->http==this)
            {
                std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
        }
        for( const auto &m : n.second->idle )
        {
            if(m->http==this)
            {
                std::cerr << (void *)m << " p->http==" << this << " into idle list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
        }
        unsigned int index=0;
        while(index<n.second->pending.size())
        {
            if(n.second->pending.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred" << std::endl;
                n.second->pending.erase(n.second->pending.cbegin()+index);
            }
            else
                index++;
        }
    }
    for( const auto &n : Backend::addressToHttps )
    {
        for( const auto &m : n.second->busy )
        {
            if(m->http==this)
            {
                std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
        }
        for( const auto &m : n.second->idle )
        {
            if(m->http==this)
            {
                std::cerr << (void *)m << " p->http==" << this << " into idle list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
        }
        unsigned int index=0;
        while(index<n.second->pending.size())
        {
            if(n.second->pending.at(index)==this)
            {
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " workaround activated, ERROR should not be exists, backend not correctly unregistred" << std::endl;
                n.second->pending.erase(n.second->pending.cbegin()+index);
            }
            else
                index++;
        }
    }
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
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
        #endif
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

//always drop query in dns before this, then call WITHOUT reference HTTP object
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
    if(!isAlive())
        return;
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
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
    #endif
    disconnectBackend();
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
}

//always drop query in dns before this, then call WITHOUT reference HTTP object
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
    if(!isAlive())
        return;
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
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
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
        std::cerr << "Http::dnsRight() status!=Status_WaitDns: " << (int)status << " " << __FILE__ << ":" << __LINE__ << " " << this << " time: " << Common::msFrom1970() << std::endl;
        return;
    }
    status=Status_WaitTheContent;
    if(!isAlive())
        return;
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    lastReceivedBytesTimestamps=Common::msFrom1970();
    #ifdef DEBUGFASTCGI
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &sIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
    #ifdef DEBUGDNS
    if(Dns::dns->hardcodedDns.find(host)!=Dns::dns->hardcodedDns.cend())
        if(std::string(str)!=Dns::dns->hardcodedDns.at(host))
        {
            std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << " time: " << Common::msFrom1970() << std::endl;
            abort();
        }
    #endif
    std::cerr << this << ": Http::dnsRight() " << host << ": " << str << " url: " << getUrl() << " " << __FILE__ << ":" << __LINE__ << " time: " << Common::msFrom1970() << std::endl;
    #endif
    m_socket=sIPv6;
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    // Telemetry-only HTTP/3 probe. Runs in parallel with the HTTPS leg
    // when --http3-probe is set. Never affects the HTTPS path.
    if(Http3Probe::enabled && isHttps())
    {
        sockaddr_in6 h3target = m_socket;
        h3target.sin6_port = Backend::https_portBE;
        std::string probePath = uri;
        if(probePath.empty() || probePath[0] != '/')
            probePath = "/" + probePath;
        Http3Probe::launch(h3target, host, probePath);
    }
    // HTTP/3 + HTTP/1.1 race. Both legs start in parallel when the
    // flag is on and the origin isn't in the failure cache. checkH3
    // arbitrates each detectTimeout tick:
    //   * H1.1 reached client-emit (headerWriten || tempCache!=null)
    //     before H3 finished -> H1 wins, drop H3, normal flow.
    //   * H3 reached allStreamsDone+200 first -> H3 wins, adopt
    //     response, disconnect H1.1 backend.
    //   * H3 connFailed / deadline / non-2xx -> drop H3, H1.1
    //     continues unaffected (no fallback dispatch needed since H1.1
    //     is already running).
    //
    // The failure cache gates whether we even attempt H3 — if the
    // origin failed H3 recently we skip starting the leg and save the
    // UDP packets.
    if(Http::http3Enabled && isHttps())
    {
        sockaddr_in6 h3target = m_socket;
        h3target.sin6_port = htobe16(Http::http3Port);
        if(!Http3::isOriginRecentlyFailed(h3target))
            startH3();
    }
    tryConnectInternal(m_socket);
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
    if(backend!=nullptr)
    {
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
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
        #endif
        disconnectBackend();
    }
    backend=Backend::tryConnectHttp(s,this,connectInternal,&backendList);
    if(backendList==nullptr)
    {
        std::cerr << this << " Http::tryConnectInternal() call Backend::tryConnectHttp() should at least set backendList" << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
        abort();
    }
    if(backend==nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::string host2="Unknown IPv6";
        char str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &m_socket.sin6_addr, str, INET6_ADDRSTRLEN) != NULL)
            host2=str;
        std::cerr << Common::msFrom1970() << " " << this << ": unable to get backend for " << host << uri << " Backend::addressToHttp[" << host2 << "] then put in pending" << " " << __FILE__ << ":" << __LINE__ << std::endl;

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
    std::cerr << "[" << Common::msFrom1970() << "] " << this << ": http->backend=" << backend << " " << __FILE__ << ":" << __LINE__ << std::endl;
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
    lastReceivedBytesTimestamps=Common::msFrom1970();

    #ifdef DEBUGFASTCGI
    std::cerr << "[" << Common::msFrom1970() << "] " << "Http::sendRequest() " << this << " " << __FILE__ << ":" << __LINE__ << " uri: " << uri << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << std::endl;
    if(uri.empty())
    {
        std::cerr << "Http::readyToWrite(): but uri.empty()" << std::endl;
        flushRead();
        return;
    }
    #endif
    requestSended=true;
    {
        std::string h(std::string("GET ")+uri);
        if(Backend::forceHttpClose)
            h+=" HTTP/1.1\r\nConnection: close\r\nHost: ";
        else
            h+=" HTTP/1.1\r\nHost: ";
        h+=host+"\r\nEPNOERFT: ysff43Uy\r\n";
        // Resume after mid-body disconnect: ask origin for `bytes=N-`. If origin
        // honours Range it replies 206 Partial Content and we append the suffix
        // to the partial cache; if origin replies 200 (Range ignored) we discard
        // the head bytes from the new body to avoid duplicating to the client.
        // Don't combine If-None-Match with Range — the semantics around 304 vs
        // 206 collisions are murky, and the client has already started receiving
        // body from the previous attempt so a 304 here is unhelpful.
        if(resumeOffset>0)
        {
            h+="Range: bytes="+std::to_string(resumeOffset)+"-\r\n";
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Http::sendRequest() Range: bytes=" << resumeOffset << "-" << std::endl;
            #endif
        }
        else if(!etagBackend.empty())
        {
            h+="If-None-Match: "+etagBackend+"\r\n";
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Http::sendRequest() etagBackend set to \"" << etagBackend << "\" (cache found)" << std::endl;
            #endif
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Http::sendRequest() etagBackend.empty() (no cache)" << std::endl;
            #endif
        }
        if(Http::useCompression && gzip)
            h+="Accept-Encoding: gzip\r\n";
        h+="\r\n";
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

//true if have read something
bool Http::readyToRead()
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
        return false;
    }
    bool haveReadSomething=false;

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
        if(backend==nullptr)//stop, finish to read, else you will have problem in check into socketRead()
            return true;
        //disable to debug
        const ssize_t size=socketRead(buffer+offset,sizeof(buffer)-offset);
        readSize=size;
        #ifdef DEBUGFASTCGI
        if(readSize!=-1 || offset!=0) {std::cout << __FILE__ << ":" << __LINE__ << " " << readSize << " offset: " << offset << std::endl;}
        #endif
        if(size>0)
        {
            haveReadSomething=true;
            if(status!=Status_WaitTheContent)
            {
                std::cerr << "Http::readyToRead() status!=Status_WaitTheContent " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            lastReceivedBytesTimestamps=Common::msFrom1970();
            #ifdef DEBUGFASTCGI
            //std::cout << "Stream block: " << Common::binarytoHexa(buffer,size) << " lastReceivedBytesTimestamps: " << lastReceivedBytesTimestamps << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            if(parsing==Parsing_Content)
            {
                writeToCache(buffer,size);
                if(endDetected)
                    return haveReadSomething;
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
                                //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " http code: " << http_code << " (" << fh << ") headerBuff.empty(): " << std::to_string(headerBuff.empty()) << " data (" << buffer << "," << size << "): " << Common::binarytoHexa(buffer,size) << std::endl;
                                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " http code: " << http_code << " (" << fh << ") backend: " << backend << std::endl;
                                #endif
                                if(backend!=nullptr)
                                    backend->wasTCPConnected=true;
                                if(!HttpReturnCode(http_code))
                                {
                                    #ifdef DEBUGFASTCGI
                                    std::cout << __FILE__ << ":" << __LINE__ << " readyToRead() !HttpReturnCode(http_code) backend: " << backend << " http_code: " << http_code << std::endl;
                                    #endif
                                    if(backend!=nullptr)
                                        flushRead();
                                    return haveReadSomething;
                                }
                                pos++;
                            }
                        }
                        else
                            pos++;
                    }
                }
                // For 200 / 206 (Range resume) / 3xx (forwarded redirect) we continue to
                // header parsing — 30x needs Location, 206 needs Content-Range. All others
                // were already handled inside HttpReturnCode (404/500/etc. send a Status to
                // the client; 304 reads from cache).
                const bool keepParsingHeaders =
                    (http_code==200) || (http_code==206) ||
                    (http_code==301) || (http_code==302) || (http_code==303) ||
                    (http_code==307) || (http_code==308);
                if(!keepParsingHeaders)
                {
                    if(backend!=nullptr)
                        flushRead();
                    #ifdef DEBUGFASTCGI
                    std::cout << __FILE__ << ":" << __LINE__ << " http code !=200 then flushRead, backend: " << backend << std::endl;
                    #endif
                    return haveReadSomething;
                }
                #ifdef DEBUGFASTCGI
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " finish get http code" << std::endl;
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
                            else if((pos-pos2)==8)
                            {
                                std::string var(buffer+pos2,pos-pos2);
                                std::transform(var.begin(), var.end(), var.begin(),[](unsigned char c){return std::tolower(c);});
                                if(var=="location")
                                {
                                    // captured for 3xx redirect forwarding
                                    parsing=Parsing_Location;
                                    pos++;
                                }
                                else
                                {
                                    parsing=Parsing_HeaderVal;
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
                                else if(var=="content-range")
                                {
                                    // captured for 206 Range-resume (matches "bytes N-M/T")
                                    parsing=Parsing_ContentRange;
                                    pos++;
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

                                // Resume after mid-body backend disconnect: cache header,
                                // FastCGI headers record, and tempCache are already
                                // populated from the first attempt. Just validate the
                                // resume response (200 vs 206) and arm skipBytes /
                                // contentsize so body-bytes append cleanly. Then drop
                                // straight into Parsing_Content so writeToCache picks up
                                // from the next byte. Mission item 5: byte-for-byte
                                // identical body delivered to the client.
                                if(resumeOffset>0 && headerWriten)
                                {
                                    if(http_code==206)
                                    {
                                        // Parse "bytes N-M/T". Trust origin for total T;
                                        // reject if N != resumeOffset (origin gave us a
                                        // different slice than we asked for).
                                        int64_t parsedN=-1, parsedM=-1, parsedT=-1;
                                        const std::string &cr=contentRange;
                                        if(cr.size()>6 && cr.compare(0,6,"bytes ")==0)
                                        {
                                            size_t a=6;
                                            size_t dash=cr.find('-',a);
                                            size_t slash=cr.find('/',a);
                                            if(dash!=std::string::npos && slash!=std::string::npos && dash<slash)
                                            {
                                                try {
                                                    parsedN=std::stoll(cr.substr(a,dash-a));
                                                    parsedM=std::stoll(cr.substr(dash+1,slash-dash-1));
                                                    parsedT=std::stoll(cr.substr(slash+1));
                                                } catch(...) {}
                                            }
                                        }
                                        if(parsedT<0 || parsedN!=resumeOffset)
                                        {
                                            #ifdef DEBUGFASTCGI
                                            std::cerr << this << " 206 Content-Range mismatch: cr=" << contentRange
                                                      << " expected start=" << resumeOffset << std::endl;
                                            #endif
                                            backendErrorAndDisconnect("206 Content-Range mismatch");
                                            return haveReadSomething;
                                        }
                                        contentsize=parsedT;
                                        skipBytes=0;
                                        #ifdef DEBUGFASTCGI
                                        std::cerr << this << " resume 206 ok: total=" << contentsize
                                                  << " offset=" << resumeOffset << std::endl;
                                        #endif
                                    }
                                    else if(http_code==200)
                                    {
                                        // Origin ignored Range. Drop the prefix bytes from
                                        // the new body that the client already received
                                        // from the first attempt — assumes the body is
                                        // deterministic (same URL, no in-flight content
                                        // change). Caller must accept this trade.
                                        skipBytes=resumeOffset;
                                        // contentsize already set from Content-Length;
                                        // contentwritten already at resumeOffset, so end-
                                        // detect fires when contentwritten reaches total.
                                        #ifdef DEBUGFASTCGI
                                        std::cerr << this << " resume 200 (range ignored): skipBytes=" << skipBytes
                                                  << " contentsize=" << contentsize << std::endl;
                                        #endif
                                    }
                                    // Streaming continues from existing cache state.
                                    break;  // exit header-parsing loop, fall through to body
                                }

                                // 3xx redirect: forward Status + Location to client
                                // verbatim (mission item 1: status codes round-trip).
                                // Confiacdn must NOT follow redirects server-side — clients
                                // decide. We don't cache 30x responses here; the response
                                // is one-shot per request.
                                if(http_code==301 || http_code==302 || http_code==303 ||
                                   http_code==307 || http_code==308)
                                {
                                    const char *reason="Found";
                                    switch(http_code) {
                                        case 301: reason="Moved Permanently"; break;
                                        case 302: reason="Found"; break;
                                        case 303: reason="See Other"; break;
                                        case 307: reason="Temporary Redirect"; break;
                                        case 308: reason="Permanent Redirect"; break;
                                    }
                                    std::string resp("Status: ");
                                    resp+=std::to_string(http_code);
                                    resp+=' ';
                                    resp+=reason;
                                    resp+="\r\n";
                                    if(!location.empty())
                                    {
                                        resp+="Location: ";
                                        resp+=location;
                                        resp+="\r\n";
                                    }
                                    resp+="Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n";

                                    for(Client * client : clientsList)
                                        client->sendRedirectResponse(resp);
                                    if(backend!=nullptr)
                                        flushRead();
                                    return haveReadSomething;
                                }

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
                                tempPath=cachePath+gen_random(16)+".tmp";
                                #ifdef DEBUGFASTCGI
                                std::cout << "open(tempPath.c_str() " << tempPath << std::endl;
                                #endif
                                ::unlink(tempPath.c_str());
                                #ifdef DEBUGFASTCGI
                                std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                                #endif
                                int cachefd = open(tempPath.c_str(), O_RDWR | O_CREAT | O_TRUNC/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
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
                                        ::unlink(tempPath.c_str());
                                        #ifdef DEBUGFASTCGI
                                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                                        #endif
                                        cachefd = open(tempPath.c_str(), O_RDWR | O_CREAT | O_TRUNC/* | O_NONBLOCK*/, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                                        if(cachefd==-1)
                                        {
                                            #ifdef DEBUGFASTCGI
                                            std::cout << "open((cachePath+.tmp).c_str() failed " << tempPath << " errno " << errno << std::endl;
                                            #endif
                                            //return internal error
                                            backendErrorAndDisconnect("Cache file FS access error");
                                            disconnectFrontend(true);
                                            #ifdef DEBUGFASTCGI
                                            std::cout << __FILE__ << ":" << __LINE__ << std::endl;
                                            #endif
                                            return haveReadSomething;
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
                                        std::cout << "open((cachePath+.tmp).c_str() failed " << tempPath << " errno " << errno << std::endl;
                                        #endif
                                        //return internal error
                                        backendErrorAndDisconnect("Cache file FS access error");
                                        disconnectFrontend(true);
                                        #ifdef DEBUGFASTCGI
                                        std::cout << __FILE__ << ":" << __LINE__ << std::endl;
                                        #endif
                                        return haveReadSomething;
                                    }
                                }
                                else
                                {
                                    Cache::newFD(cachefd,this,EpollObject::Kind::Kind_Cache);
                                    #ifdef DEBUGFILEOPEN
                                    std::cerr << "Http::readyToRead() open: " << tempPath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
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
                                // last_modification_time_check is stored in milliseconds
                                // (vs access_time in seconds) so that --http200Time can be
                                // observed at sub-second precision: with second resolution,
                                // a 2 s TTL may evaluate as 1 s or 2 s depending on
                                // wall-clock alignment, breaking warm-fresh / warm-stale
                                // boundary tests at the 1900/2100 ms tick.
                                const uint64_t currentTimeMs=Common::msFrom1970();
                                if(!tempCache->set_access_time(currentTime))
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_access_time(currentTime): " << tempPath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendErrorAndDisconnect("Cache file FS access error");
                                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                    return haveReadSomething;
                                }
                                if(!tempCache->set_last_modification_time_check(currentTimeMs))
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_last_modification_time_check(currentTime): " << tempPath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendErrorAndDisconnect("Cache file FS access error");
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                    #endif
                                    std::cerr << this << " drop corrupted cache " << cachePath << ".tmp";
                                    {
                                        struct stat sb;
                                        const int rstat=fstat(cachefd,&sb);
                                        if(rstat==0 && sb.st_size>=0)
                                            std::cerr << " size: " << sb.st_size;
                                    }
                                    std::cerr << std::endl;
                                    ::unlink(tempPath.c_str());//drop corrupted cache
                                    #ifdef DEBUGFASTCGI
                                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                                    #endif
                                    return haveReadSomething;
                                }
                                if(!tempCache->set_http_code(http_code))
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_http_code(http_code): " << tempPath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendErrorAndDisconnect("Cache file FS access error");
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                    #endif
                                    return haveReadSomething;
                                }
                                if(!tempCache->set_ETagFrontend(r))//string of 6 char
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_ETagFrontend(r): " << tempPath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendErrorAndDisconnect("Cache file FS access error");
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                    #endif
                                    return haveReadSomething;
                                }
                                if(!tempCache->set_ETagBackend(etagBackend))//at end seek to content pos
                                {
                                    tempCache->close();
                                    delete tempCache;
                                    tempCache=nullptr;
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << "!tempCache->set_ETagBackend(etagBackend): " << tempPath << ", fd: " << cachefd << " " << __FILE__ << ":" << __LINE__ << std::endl;
                                    #endif
                                    backendErrorAndDisconnect("Cache file FS access error");
                                    #ifdef DEBUGFASTCGI
                                    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                    #endif
                                    return haveReadSomething;
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
                                    // Reachable on a resume retry where the new response
                                    // wasn't a 206/200 we recognised as a continuation —
                                    // the resume-detection code at line ~1011 should have
                                    // caught those. Anything else here means we'd be
                                    // double-writing headers into the cache file, which
                                    // would make the FastCGI stream nginx receives invalid
                                    // (it'd see two Status: lines). Bail out as a backend
                                    // error rather than abort()ing the daemon — same
                                    // outcome (client gets a synthetic error) but the
                                    // process keeps serving other connections.
                                    std::cerr << "headerWriten already true on second header write — backend error" << std::endl;
                                    backendErrorAndDisconnect("Duplicate header write on resume");
                                    return haveReadSomething;
                                }
                                else
                                {
                                    headerWriten=true;

                                    //fastcgi header
                                    uint16_t sizebe=htobe16(header.size());
                                    memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
                                    if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
                                    {
                                        std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                        tempCache->close();
                                        delete tempCache;
                                        tempCache=nullptr;
                                        backendErrorAndDisconnect("Cache file FS access error");
                                        #ifdef DEBUGFASTCGI
                                        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                        #endif
                                    }
                                    else
                                    {
                                        if(tempCache->write(header.data(),header.size())!=(ssize_t)header.size())
                                        {
                                            std::cerr << "Header creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                            tempCache->close();
                                            delete tempCache;
                                            tempCache=nullptr;
                                            backendErrorAndDisconnect("Cache file FS access error");
                                            #ifdef DEBUGFASTCGI
                                            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                            #endif
                                        }
                                        else
                                        {
                                            if(getFileMoved())
                                            {
                                                for(Client * client : clientsList)
                                                    client->startRead(cachePath,true);
                                            }
                                            else
                                            {
                                                for(Client * client : clientsList)
                                                    client->startRead(tempPath,true);
                                            }
                                        }
                                    }
                                }
                                // Zero-body response (Content-Length: 0): no body chunks
                                // will arrive, so fire end-of-content here. Without this,
                                // the backend just sits waiting for a body that never
                                // comes, the origin EOF eventually triggers a Range-resume
                                // retry, and the retry trips the "headerWriten already" abort.
                                if(contentsize==0 && tempCache!=nullptr && !endDetected)
                                {
                                    endDetected=true;
                                    tempCache->write(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));
                                    for(Client * client : clientsList)
                                        client->tryResumeReadAfterEndOfFile();
                                    disconnectFrontend(false);
                                    disconnectBackend();
                                    return haveReadSomething;
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
                                    case Parsing_Location:
                                        location=std::string(buffer+pos2,pos-pos2);
                                        // Trim a leading space if origin used "Location: <url>" with a space
                                        if(!location.empty() && location.front()==' ')
                                            location.erase(0,1);
                                    break;
                                    case Parsing_ContentRange:
                                        contentRange=std::string(buffer+pos2,pos-pos2);
                                        if(!contentRange.empty() && contentRange.front()==' ')
                                            contentRange.erase(0,1);
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
                        return haveReadSomething;
                    const size_t finalSize=size-pos;
                    const size_t rSize=writeToCache(buffer+pos,finalSize);
                    if(endDetected || rSize<=0 || rSize!=finalSize)
                        return haveReadSomething;
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
                std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " end procesing http header, backend: " << backend << std::endl;
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
            /// 113: no route to the host
            if(errno!=11 && errno!=113 && errno!=0)
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
    return haveReadSomething;
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
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " Http::socketRead ERROR backend==nullptr (abort)" << std::endl;
        abort();
        #endif
        return -1;
    }
    if(!backend->isValid())
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::socketRead error backend is not valid: " << backend << " " << __FILE__ << ":" << __LINE__ << std::endl;
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
        std::cerr << "Http::socketWrite error backend is not valid: " << backend << " " << __FILE__ << ":" << __LINE__ << std::endl;
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
                /*not allow std::vector<HTTP*>::clear()
                if(client->http->get_status()==Status_WaitDns)
                {
                    if(!Dns::dns->queryHaveThisClient(client->http,client->http->host,client->http->isHttps()))
                    {
                        std::cerr << "Http::checkIngrityHttpClient() " << client->http << " getStatus(): Status_WaitDns but not query have this client " << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        abort();
                    }
                }*/
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
    for(const Http * http : Http::httpToDebug)
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
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    if(force || !endDetected)
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << "disconnectFrontend force " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        for(Client * client : clientsList)
        {
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
    if(clientsList.empty() && backend==nullptr && backendList!=nullptr)
    {
        unsigned int index=0;
        while(index<backendList->pending.size())
        {
            if(backendList->pending.at(index)==this)
            {
                backendList->pending.erase(backendList->pending.cbegin()+index);
                //break;for security
            }
            index++;
        }
        backendList=nullptr;
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
        std::string cachePathTmp=tempPath;
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
            Http::httpToDelete.insert(this);*/
    }
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
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
        if(!finalCache->set_last_modification_time_check(Common::msFrom1970()))
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
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
            #endif
            ::unlink(tempPath.c_str());//drop corrupted cache
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
    // 206 Partial Content: response to a Range request we issued for resume after
    // a mid-body backend disconnect. Treat like 200 — the body bytes returned are
    // the suffix [resumeOffset, end) and get appended to the existing cache file.
    if(errorCode==206)
        return true;
    // 3xx redirects that are NOT 304 (revalidate). We need the Location header
    // before responding to the client, so let header parsing continue; the
    // emission happens at end-of-headers in readyToRead().
    if(errorCode==301 || errorCode==302 || errorCode==303 || errorCode==307 || errorCode==308)
        return true;
    if(errorCode==304) //when have header 304 Not Modified
    {
        #ifdef DEBUGFASTCGI
        std::cout << "304 http code!, cache already good" << std::endl;
        #endif
        if(startReadFromCacheAfter304())
            return false;
    }
    // 5xx during revalidation with a stale cache available → serve stale.
    // Mission item 5: "if the origin can't be reached, fall back to the stale
    // entry rather than returning an error to the client." Origin-side 5xx is
    // semantically a backend failure for caching purposes.
    if(errorCode>=500 && errorCode<600 && finalCache!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cout << this << " HttpReturnCode " << errorCode
                  << ": serving stale from finalCache" << std::endl;
        #endif
        if(startReadFromCacheAfter304())
            return false;
    }
    // 4xx and 5xx: propagate the actual status code to clients. Mission item 1:
    // "status codes must round-trip" — a 404 must finish as a 404, not as a
    // generic 500.
    if(errorCode>=400 && errorCode<600)
    {
        for(Client * client : clientsList)
            client->httpStatus(errorCode);
        disconnectFrontend(true);
        return false;
    }
    const std::string errorString("Http "+std::to_string(errorCode));
    for(Client * client : clientsList)
        client->httpError(errorString);
    disconnectFrontend(true);
    return false;
    //disconnectSocket();
}

void Http::retryAfterError()
{
    std::cerr<< this << " " << __FILE__ << ":" << __LINE__ << " Http::retryAfterError() pending: " << pending << " requestSended: " << requestSended << " etagBackend: " << etagBackend << " status: " << (int)status << std::endl;

    //failback 1: warm cache → serve stale rather than 5xx the client.
    //
    // Mission item 5 / CLAUDE.md "backend leg unstable" corollary 2: when
    // we have a previously-cached complete body (finalCache != nullptr),
    // any unrecoverable backend error during revalidation should serve the
    // stale entry, not propagate the failure. The original gate also
    // required `pending && requestSended` (i.e. a queued retry where the
    // request had already gone on the wire) — but a permanent TLS-handshake
    // refusal, a TCP-connect-failed peer, or a silent-after-connect VPN
    // endpoint never advances `requestSended` past zero, and those are
    // exactly the cases the unstable-VPN topology produces. Gating on
    // finalCache covers them all (and is the same marker used by the 5xx
    // stale-fallback path in HttpReturnCode).
    if(finalCache!=nullptr)
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
        return;
    }

    //failback 2
    if(status!=Status_WaitTheContent)
    {
        std::cerr<< this << " " << __FILE__ << ":" << __LINE__ << " internal status!=Status_WaitTheContent (abort)" << std::endl;
        abort();
    }
    #ifdef DEBUGFASTCGI
    checkIngrityHttpClient();
    #endif
    lastReceivedBytesTimestamps=Common::msFrom1970();
    tryConnectInternal(m_socket);
}

void Http::backendErrorAndDisconnect(const std::string &errorString)
{
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Http::backendError(\"" << errorString << "\"), erase pathToHttp.find(" << cachePath << ") " << this << " retryCount: " << (int)retryCount << " contentwritten: " << contentwritten << " backend: " << backend << std::endl;
    std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " client: ,clientsList size: " << clientsList.size();
    for(const Client * c : clientsList)
        std::cerr << " " << c;
    std::cerr << std::endl;
    #endif
    if(retryCount<2 && contentwritten==0 && status==Status_WaitTheContent && haveUrlAndFrontendConnected())
    {
        retryCount++;
        std::cerr<< this << " " << __FILE__ << ":" << __LINE__ << " retry here after error: \"" << errorString << "\" retryCount: " << (int)retryCount << " contentwritten: " << contentwritten << std::endl;
        retryAfterError();
        return;
    }
    retryCount=255;
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    for(Client * client : clientsList)
        client->httpError(errorString);
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif
    disconnectFrontend(true);
    if(!cachePath.empty())
    {
        std::unordered_map<std::string,Http *> &pathToHttp=pathToHttpList();
        #ifdef DEBUGFASTCGI
        if(tempCache!=nullptr)
        {
            if(pathToHttp.find(tempPath)==pathToHttp.cend())
            {
                std::cerr << "Http::backendError(" << errorString << "), but pathToHttp.find(" << tempPath << ") not found (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort(); have low chance to pass here
            }
            else if(pathToHttp.at(tempPath)!=this)
            {
                std::cerr << "Http::backendError(" << errorString << "), but pathToHttp.find(" << tempPath << ")!=this (abort) " << this << std::endl;
                //abort();
            }
            else
                std::cerr << "Http::backendError(" << errorString << "), erase pathToHttp.find(" << tempPath << ") " << this << std::endl;
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
                std::cerr << "pathToHttp.erase(" << tempPath << ") " << this << std::endl;
            if(&pathToHttp==&Https::pathToHttps)
                std::cerr << "pathToHttps.erase(" << tempPath << ") " << this << std::endl;
            #endif
            pathToHttp.erase(tempPath);
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
    /// \todo should have here process the backend pending if no more retry
    //disconnectSocket();
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
    #endif
    if(backend!=nullptr)
        backend->close();
    disconnectBackend();
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
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " Http::flushRead()" << std::endl;
    #endif
    endDetected=true;
    while(socketRead(Http::buffer,sizeof(Http::buffer))>0)
    {}
    disconnectFrontend(false);
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
    #endif
    disconnectBackend();
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
    std::cerr << Common::msFrom1970() << " Http::disconnectBackend() " << this << ", fromDestructor: " << fromDestructor << "  " << __FILE__ << ":" << __LINE__ <<  std::endl;
    if(retryCount<255 && !fromDestructor)
        std::cerr << Common::msFrom1970() << " Http::disconnectBackend() WARN seam not pass here  " << __FILE__ << ":" << __LINE__ <<  std::endl;
    #endif

    retryCount=255;//not retry, this disable retry from here, if you wish retry, call the retryAfterError() function
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
            std::cerr << this << " " << tempPath << " corrupted temp file: " << tempCache->size() << " fd: " << tempCache->getFD() << " (abort)" << std::endl;
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
            #endif
            ::unlink(cstr);
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
            #endif
            ::unlink(tempPath.c_str());
            moveTempToFinal=false;
            //abort();
        }
        else if(endDetected)
        {
            // Refresh the lmtc to "now" at finalisation, not at file creation. The
            // initial lmtc was set when the first response byte arrived from origin
            // — fine when http200Time is hours, but for short TTLs (e.g. the test
            // matrix's --http200Time=2) a slow download can finish AFTER the cache
            // is already considered stale, forcing pointless revalidation churn
            // for late joiners and breaking de-dup (multi_client_flapping). Move
            // the freshness anchor to the moment the cache became serveable.
            tempCache->set_last_modification_time_check(Common::msFrom1970());
        }
        #ifdef DEBUGFASTCGI
        std::cerr << "Http::disconnectBackend() " << tempPath << " temp file size: " << tempSize << " (close)" << std::endl;
        #endif

        tempCache->close();
        if(moveTempToFinal)
        {
            if(endDetected)
            {
                struct stat sb;
                const int rstat=stat(tempPath.c_str(),&sb);
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
                            if(rename(tempPath.c_str(),cstr)!=0)
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
                                    if(rename(tempPath.c_str(),cstr)!=0)
                                    {
                                        std::cerr << "unable to move " << cachePath << ".tmp to " << cachePath << ", errno: " << errno << std::endl;
                                        #ifdef DEBUGFASTCGI
                                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                                        #endif
                                        ::unlink(tempPath.c_str());
                                    }
                                }
                                else
                                {
                                    std::cerr << "unable to move " << cachePath << ".tmp to " << cachePath << ", errno: " << errno << std::endl;
                                    #ifdef DEBUGFASTCGI
                                    std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                                    #endif
                                    ::unlink(tempPath.c_str());
                                }
                            }
                            else
                            {
                                #ifdef DEBUGFASTCGI
                                std::cout << __FILE__ << ":" << __LINE__ << " move: " << tempPath << " to " << cstr << std::endl;
                                #endif
                                fileMoved=true;
                            }
                        }
                        else
                        {
                            std::cerr << "Too small to be saved (abort): " << tempPath << " " << __FILE__ << ":" << __LINE__ << std::endl;
                            #ifdef DEBUGFASTCGI
                            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
                            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                            #endif
                            ::unlink(cstr);
                            ::unlink(tempPath.c_str());
                        }
                    }
                    else
                    {
                        std::cerr << "Too big to be saved (abort): " << tempPath << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        #ifdef DEBUGFASTCGI
                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
                        std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
                        #endif
                        ::unlink(cstr);
                        ::unlink(tempPath.c_str());
                    }
                }
            }
            else
                std::cout << __FILE__ << ":" << __LINE__ << " disconnect backend but no endDetected detected! file: " << tempPath << " url " << getUrl() << std::endl;
            ::unlink(tempPath.c_str());
        }
        else
        {
            std::cerr << "Not found: " << tempPath << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #ifdef DEBUGFASTCGI
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << (cstr) << std::endl;
            std::cout << __FILE__ << ":" << __LINE__ << " ::unlink(" << tempPath << std::endl;
            #endif
            ::unlink(cstr);
            ::unlink(tempPath.c_str());
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
    {
        #ifdef DEBUGFASTCGI
        if(backend->http!=this)
        {
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ": backend->http!=this: " << backend->http << ", backend: " << backend << " backend of this http should have this http as parent (abort)" << std::endl;
            abort();
        }
        #endif
        Backend *backend=this->backend;
        this->backend=nullptr;
        this->backendList=nullptr;
        backend->downloadFinished();//after this, the backend should not point to http
        #ifdef DEBUGFASTCGI
        if(backend!=nullptr && backend->http==this)
        {
            std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ": backend->http==this, backend: " << backend << " backend of this http should have this http as parent (abort)" << std::endl;
            abort();
        }
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ": backend: " << this->backend << std::endl;

        //if this can be located into another backend, then error
        for( const auto& n : Backend::addressToHttp )
        {
            const Backend::BackendList * list=n.second;
            for(const Backend * b : list->busy)
                if(b->http==this)
                    std::cerr << this << ": backend->http==this, can be retry here after error case, http backend: " << backend << " but found in this busy backend " << b << " " << getUrl() << " (abort)" << std::endl;
        }
        for( const auto& n : Backend::addressToHttps )
        {
            const Backend::BackendList * list=n.second;
            for(const Backend * b : list->busy)
                if(b->http==this)
                    std::cerr << this << ": backend->http==this, can be retry here after error case, https backend: " << backend << " but found in this busy backend " << b << " " << getUrl() << " (abort)" << " " << __FILE__ << ":" << __LINE__ << std::endl;
        }
        checkBackend();
        #endif
    }
    else
    {
        //remove from pending
        if(backendList!=nullptr)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " backendList!=nullptr but no backend, remove from pending " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
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
            {
                backendList->pending.erase(backendList->pending.cbegin()+index);
                backendList=nullptr;
            }
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " backendList==nullptr WARNING " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            //slow but workaround
            for( const auto& n : Backend::addressToHttp )
            {
                const Backend::BackendList * list=n.second;
                for(Backend * b : list->busy)
                    if(b->http==this)
                    {
                        std::cerr << this << ": backend->http==this, http backend: " << backend << " " << getUrl() << " (abort)" << std::endl;
                        abort();//b->http=nullptr;
                    }
            }
            for( const auto& n : Backend::addressToHttps )
            {
                const Backend::BackendList * list=n.second;
                for(Backend * b : list->busy)
                    if(b->http==this)
                    {
                        std::cerr << this << ": backend->http==this, https backend: " << backend << " " << getUrl() << " (abort)" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                        abort();//b->http=nullptr;
                    }
            }
        }
    }
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
    #ifdef DEBUGFASTCGI
    if(backend!=nullptr && backend->http!=this)
    {
        std::cerr << this << " " << __FILE__ << ":" << __LINE__ << ": backend->http!=this, backend: " << backend << " backend of this http should have this http as parent (abort)" << std::endl;
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
                std::cerr << this << ": b backend->http==this, http backend: " << backend << " b backend: " << b << " backend->http: " << backend->http << " " << getUrl() << " (abort)" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
    }
    for( const auto& n : Backend::addressToHttps )
    {
        const Backend::BackendList * list=n.second;
        for(const Backend * b : list->busy)
            if(b->http==this)
            {
                std::cerr << this << ": b backend->http==this, https backend: " << backend << " b backend: " << b << " backend->http: " << backend->http << " " << getUrl() << " (abort)" << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
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
            if(Http::httpToDebug.find(this)==Http::httpToDebug.cend())
            {
                std::cerr << this << " Http::httpToDelete.insert() failed because not into debug" << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            else
                std::cerr << this << " Http::httpToDelete.insert() ok (backend)" << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            Http::httpToDelete.insert(this);
            #ifdef DEBUGDNS
            //very heavy check
            if(Dns::dns->queryHaveThisClient(this))
            {
                std::cerr << "Http::disconnectBackend(): remain http " << this << " on dns " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                //abort();
                return;
            }
            #endif
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
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        //abort();
                    }
                }
                for( const auto &m : n.second->idle )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into idle list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        //abort();
                    }
                }
                for( const auto &m : n.second->pending )
                {
                    if(m==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into pending list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        //abort();
                    }
                }
            }
            for( const auto &n : Backend::addressToHttps )
            {
                for( const auto &m : n.second->busy )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into busy list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        //abort();
                    }
                }
                for( const auto &m : n.second->idle )
                {
                    if(m->http==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into idle list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        //abort();
                    }
                }
                for( const auto &m : n.second->pending )
                {
                    if(m==this)
                    {
                        std::cerr << (void *)m << " p->http==" << this << " into pending list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                        //abort();
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
        std::string cachePathTmp=tempPath;
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
            client->startRead(tempPath,!getEndDetected());
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
    checkBackend();
    #endif
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
    #ifdef DEBUGFASTCGI
    checkBackend();
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
    if(clientsList.empty() && backend==nullptr && backendList!=nullptr)
    {
        unsigned int index=0;
        while(index<backendList->pending.size())
        {
            if(backendList->pending.at(index)==this)
            {
                backendList->pending.erase(backendList->pending.cbegin()+index);
                //break;for security
            }
            index++;
        }
        backendList=nullptr;
    }
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
            if(pathToHttp.find(tempPath)==pathToHttp.cend())
            {
                std::cerr << "Http::removeClient(), but pathToHttp.find(" << tempPath << ") not found (abort) " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
                //abort(); have low chance to pass here
            }
            else if(pathToHttp.at(tempPath)!=this)
            {
                std::cerr << "Http::removeClient(), but pathToHttp.find(" << tempPath << ")!=this (abort) " << this << std::endl;
                //abort();
            }
            else
                std::cerr << "Http::removeClient(), erase pathToHttp.find(" << tempPath << ") " << this << std::endl;
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
                std::cerr << "pathToHttp.erase(" << tempPath << ") " << this << std::endl;
            if(&pathToHttp==&Https::pathToHttps)
                std::cerr << "pathToHttps.erase(" << tempPath << ") " << this << std::endl;
            #endif
            pathToHttp.erase(tempPath);
        }

        #ifdef DEBUGFASTCGI
        checkBackend();
        #endif
        disconnectFrontend(true);
        #ifdef DEBUGFASTCGI
        checkBackend();
        #endif
        if(backend==nullptr)//after disconnectFrontend(), only can be !isAlive()
        {
            #ifdef DEBUGFASTCGI
            if(Http::httpToDebug.find(this)==Http::httpToDebug.cend())
            {
                std::cerr << this << " Http::httpToDelete.insert() failed because not into debug, backendlist: " << backendList << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            else
                std::cerr << this << " Http::httpToDelete.insert() ok (remove client), backendlist: " << backendList << " status: " << (int)status << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            if(backendList!=nullptr)
            {
                #ifdef DEBUGFASTCGI
                std::cerr << this << " !isWithClient() backendList!=nullptr backendlist: " << backendList << " then is in pendding, remove from pendding " << __FILE__ << ":" << __LINE__ << std::endl;
                #endif
                unsigned int index=0;
                while(index<backendList->pending.size())
                {
                    if(backendList->pending.at(index)==this)
                    {
                        backendList->pending.erase(backendList->pending.cbegin()+index);
                        //break;-> full scan to prevent error
                    }
                    index++;
                }
                backendList=nullptr;
            }
            Http::httpToDelete.insert(this);
            #ifdef DEBUGDNS
            //very heavy check
            if(Dns::dns->queryHaveThisClient(this))
            {
                /*#4  0x000055555559a4d6 in Http::removeClient (this=<optimized out>, client=client@entry=0x55555560ca10) at ./Http.cpp:2827
#5  0x0000555555570285 in Client::disconnectFromHttp (this=0x55555560ca10) at ./Client.cpp:313
#6  0x000055555557229a in Client::writeEnd (this=0x55555560ca10, fileBytesSended=<optimized out>) at ./Client.cpp:2496
#7  0x000055555557593d in Client::internalWriteEnd (this=0x55555560ca10) at ./Client.cpp:2204
#8  Client::httpError (this=0x55555560ca10, errorString="Dns error") at ./Client.cpp:2198
#9  0x000055555558342c in Http::parseNonHttpError (this=this@entry=0x55555560dd30, error=error@entry=@0x7fffffffb07f: Backend::NonHttpError_DnsError) at ./Http.cpp:1982
#10 0x000055555558e320 in Http::dnsError (this=0x55555560dd30) at ./Http.cpp:368
then can't be abort, skip ignore this
*/
                std::cerr << "Http::disconnectBackend(): remain http " << this << " on dns " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            #endif
        }
        else
        {
            #ifdef DEBUGFASTCGI
            std::cerr << this << " client list is empty, but backend is not null";
            std::cerr << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
        }
    }
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif

    if(!isAlive() && getEndDetected() && !isWithClient())
        flushRead();
    #ifdef DEBUGFASTCGI
    checkBackend();
    #endif

    return retVal;


    //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " failed to remove: " << client << std::endl;
    /*auto p=std::find(clientsList.cbegin(),clientsList.cend(),client);
    if(p!=clientsList.cend())
        clientsList.erase(p);*/
}

int Http::writeToCache(const char * const data_in,const size_t &size_in)
{
    if(endDetected)
        return -1;
    if(tempCache==nullptr)
    {
        //std::cerr << "tempCache==nullptr internal error" << std::endl;
        return size_in;
    }
    // Resume-after-disconnect with origin returning 200 (Range ignored): drop
    // the prefix bytes the client already received from the first attempt so
    // the FastCGI stream stays continuous (mission item 5: byte-identical body
    // delivered to the client). Origin must be deterministic — we trust that
    // the bytes we just discarded match the bytes the client already has.
    const char *data=data_in;
    size_t size=size_in;
    if(skipBytes>0 && size>0)
    {
        const size_t drop=(skipBytes>(int64_t)size)?size:(size_t)skipBytes;
        skipBytes-=drop;
        data+=drop;
        size-=drop;
        if(size==0)
            return size_in;
    }
    if(contentsize>=0)
    {
        #ifdef DEBUGFASTCGI
        //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " contentsize>=0 fixed size" << std::endl;
        #endif
        //fastcgi header
        uint16_t sizebe=htobe16(size);
        memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
        if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
        {
            std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
            tempCache->close();
            delete tempCache;
            tempCache=nullptr;
            backendErrorAndDisconnect("Cache file write error");
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
            #endif
        }

        const size_t &writedSize=tempCache->write((char *)data,size);
        if(writedSize!=size)
        {
            std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
            tempCache->close();
            delete tempCache;
            tempCache=nullptr;
            backendErrorAndDisconnect("Cache file write error");
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
            #endif
        }
        contentwritten+=size;
        #ifdef DEBUGFASTCGI
        //std::cerr << this << " " << __FILE__ << ":" << __LINE__ << " contentsize: " << contentsize << ", contentwritten: " << contentwritten << std::endl;
        #endif
        if(contentsize<=contentwritten)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << "contentsize<=contentwritten into Http::write() " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            endDetected=true;

            //FCGI_END_REQUEST
            tempCache->write(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));

            for(Client * client : clientsList)
                client->tryResumeReadAfterEndOfFile();

            disconnectFrontend(false);
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
            #endif
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
                            //fastcgi header
                            uint16_t sizebe=htobe16(size-pos);
                            memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
                            if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
                            {
                                std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                tempCache->close();
                                delete tempCache;
                                tempCache=nullptr;
                                backendErrorAndDisconnect("Cache file write error");
                                #ifdef DEBUGFASTCGI
                                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                #endif
                            }

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
                            //fastcgi header
                            uint16_t sizebe=htobe16(chunkLength);
                            memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
                            if(tempCache->write(Http::fastcgiheaderstdout,sizeof(Http::fastcgiheaderstdout))!=sizeof(Http::fastcgiheaderstdout))
                            {
                                std::cerr << "Header fastcgi creation failed, abort to debug " << __FILE__ << ":" << __LINE__ << host << uri << " " << cachePath << std::endl;
                                tempCache->close();
                                delete tempCache;
                                tempCache=nullptr;
                                backendErrorAndDisconnect("Cache file write error");
                                #ifdef DEBUGFASTCGI
                                std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                                #endif
                            }

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
                                    //std::cerr << "text: " << std::string(data+pos2,pos-pos2) << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
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

                        //FCGI_END_REQUEST
                        tempCache->write(Http::fastcgiheaderend,sizeof(Http::fastcgiheaderend));
                        if(!streamingDetected)
                        {
                            for(Client * client : clientsList)
                                client->tryResumeReadAfterEndOfFile();
                        }

                        disconnectFrontend(false);
                        #ifdef DEBUGFASTCGI
                        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
                        #endif
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

int64_t Http::getContentwritten() const
{
    return contentwritten;
}

void Http::prepareForResume()
{
    // The current body offset becomes the Range start for the retry. We keep
    // contentwritten / tempCache / headerWriten intact: contentwritten so that
    // (a) we know how far we've gone, and (b) writeToCache's "endDetected when
    // contentwritten>=contentsize" logic continues to count from the right
    // place after the retry's bytes append; tempCache because the partial
    // body in cache must be preserved (so we can append rather than restart);
    // headerWriten so we don't double-emit a Status: line + headers to the
    // client (the client has already received the original headers from the
    // first attempt).
    resumeOffset=contentwritten;
    skipBytes=0;
    // Reset parser state so the new response is parsed fresh from the status
    // line. The caller (Backend::remoteSocketClosed) already cleared
    // requestSended; we redo it here for clarity.
    http_code=0;
    parsing=Parsing_None;
    contentsize=-1;
    contenttype.clear();
    contentEncoding.clear();
    location.clear();
    contentRange.clear();
    headerBuff.clear();
    chunkLength=-1;
    chunkHeader.clear();
    endDetected=false;
    streamingDetected=false;
    requestSended=false;
    lastReceivedBytesTimestamps=Common::msFrom1970();
    #ifdef DEBUGFASTCGI
    std::cerr << this << " " << __FILE__ << ":" << __LINE__
              << " prepareForResume: resumeOffset=" << resumeOffset << std::endl;
    #endif
}

void Http::resetActivityTimestampForReassign()
{
    lastReceivedBytesTimestamps=Common::msFrom1970();
}

#ifdef DEBUGFASTCGI
void Http::checkBackend()
{
    //backendList is used for std::vector<Http *> pending;
    if(backendList!=nullptr)
    {
        if(backend==nullptr)//no backend, should be into pending, check if into pending list?
        {
            //check if not busy/idle
            if(!backendList->idle.empty())
            {
                unsigned int index=0;
                while(index<backendList->idle.size())
                {
                    if(backendList->idle.at(index)==backend)
                    {
                        std::cerr << this << " located into backendList->idle, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                        abort();
                    }
                    index++;
                }
            }
            if(!backendList->busy.empty())
            {
                unsigned int index=0;
                while(index<backendList->busy.size())
                {
                    if(backendList->busy.at(index)==backend)
                    {
                        std::cerr << this << " located into backendList->busy, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << " time: " << Common::msFrom1970() << " (abort)" << std::endl;
                        abort();
                    }
                    index++;
                }
            }
            if(isAlive() && haveUrlAndFrontendConnected())
            {
                //check if pending
                unsigned int index=0;
                while(index<backendList->pending.size())
                {
                    if(backendList->pending.at(index)==this)
                        break;
                    index++;
                }
            }
            else
            {
                //check if pending
                unsigned int index=0;
                while(index<backendList->pending.size())
                {
                    if(backendList->pending.at(index)==this)
                    {
                        std::cerr << this << " backend==nullptr and this " << this << " found into pending, isAlive(): " << std::to_string((int)isAlive()) << " haveUrlAndFrontendConnected(): " << std::to_string((int)haveUrlAndFrontendConnected()) << ", clientsList size: " << std::to_string(clientsList.size()) << " host: " << host << " uri: " << uri << " (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                        abort();
                    }
                    index++;
                }
            }
            return;
        }

        //here backend!=nullptr
        unsigned int index=0;
        while(index<backendList->pending.size())
        {
            if(backendList->pending.at(index)==this)
            {
                std::cerr << this << " found into backendList->pending but backend!=nullptr, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
            index++;
        }

        if(!backendList->idle.empty())
        {
            unsigned int index=0;
            while(index<backendList->idle.size())
            {
                if(backendList->idle.at(index)==backend)
                {
                    std::cerr << this << " located into backendList->idle, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
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
                    std::cerr << this << " located into backendList->busy, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << " time: " << Common::msFrom1970() << std::endl;
                    return;
                }
                index++;
            }
        }
        std::cerr << this << " not found anywhere but backendList: " << backendList << " and backend: " << backend << ", isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
        abort();
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

        for( const auto &n : Backend::addressToHttp )
        {
            for( Backend * p : n.second->busy )
            {
                if(p->http==this)
                {
                    std::cerr << this << " p->http==this busy, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            for( Backend * p : n.second->idle )
            {
                if(p->http==this)
                {
                    std::cerr << this << " p->http==this idle, isAlive(): " << std::to_string((int)isAlive()) << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            unsigned int index=0;
            while(index<n.second->pending.size())
            {
                if(n.second->pending.at(index)==this)
                {
                    std::cerr << this << " found into BackendList but Backend list not correctly set! " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
                index++;
            }
        }
        for( const auto &n : Backend::addressToHttps )
        {
            for( Backend * p : n.second->busy )
            {
                if(p->http==this)
                {
                    std::cerr << this << " p->http==this busy, isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            for( Backend * p : n.second->idle )
            {
                if(p->http==this)
                {
                    std::cerr << this << " p->http==this idle, isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            unsigned int index=0;
            while(index<n.second->pending.size())
            {
                if(n.second->pending.at(index)==this)
                {
                    std::cerr << this << " found into BackendList but Backend list not correctly set! " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
                index++;
            }
        }
    }
    if(Http::httpToDelete.find(this)!=Http::httpToDelete.cend())
    {
        for( const auto &n : Backend::addressToHttp )
        {
            for( Backend * p : n.second->busy )
            {
                if(p->http==this)
                {
                    std::cerr << this << " Http::httpToDelete.find(this)!=Http::httpToDelete.cend(), isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            for( Backend * p : n.second->idle )
            {
                if(p->http==this)
                {
                    std::cerr << this << " Http::httpToDelete.find(this)!=Http::httpToDelete.cend(), isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            for( Http * p : n.second->pending )
            {
                if(p==this)
                {
                    std::cerr << this << " Http::httpToDelete.find(this)!=Http::httpToDelete.cend(), isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
        }
        for( const auto &n : Backend::addressToHttps )
        {
            for( Backend * p : n.second->busy )
            {
                if(p->http==this)
                {
                    std::cerr << this << " Http::httpToDelete.find(this)!=Http::httpToDelete.cend(), isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            for( Backend * p : n.second->idle )
            {
                if(p->http==this)
                {
                    std::cerr << this << " Http::httpToDelete.find(this)!=Http::httpToDelete.cend(), isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
            for( Http * p : n.second->pending )
            {
                if(p==this)
                {
                    std::cerr << this << " Http::httpToDelete.find(this)!=Http::httpToDelete.cend(), isAlive(): " << std::to_string((int)isAlive()) << " backend: " << p << ", clientsList size: " << std::to_string(clientsList.size()) << " " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }
            }
        }
    }
}
#endif

//return true if timeout
bool Http::detectTimeout()
{
    const uint64_t msFrom1970=Common::msFrom1970();
    // H3-first poll: if an Http3 leg is in flight, advance the state
    // machine. checkH3 either adopts the response (request finished) or
    // dispatches H1.1 fallback (will set backend != nullptr on its way).
    if(http3Conn!=nullptr)
        checkH3();
    if(backend!=nullptr && status==Status_WaitTheContent && requestSended)
    {
        if(readyToRead())//try again read something, if read something the problem is the event
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " readyToRead() WARN had more data but read by poll not by event!" << std::endl;
            lastReceivedBytesTimestamps=msFrom1970;
            return false;
        }
    }
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
    #ifdef DEBUGFASTCGI
    if(!requestSended && status==Status_WaitTheContent)
    {
        if(backend!=nullptr)
            std::cerr << Common::msFrom1970() << " In detect timeout if(!requestSended && status==Status_WaitTheContent) with backend " << backend << " " << this << " " << __FILE__ << ":" << __LINE__ << " clientsList.size(): " << clientsList.size() << " endDetected: " << endDetected << " url: " << getUrl() << std::endl;
        else
            std::cerr << Common::msFrom1970() << " In detect timeout if(!requestSended && status==Status_WaitTheContent) " << this << " " << __FILE__ << ":" << __LINE__ << " clientsList.size(): " << clientsList.size() << " endDetected: " << endDetected << " url: " << getUrl() << std::endl;
    }
    #endif

    //if no byte received into 600s (10m)
    #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " timeout details: " << lastReceivedBytesTimestamps << "<(" << msFrom1970 << "-" << secondForTimeout << "*1000), pending: " << pending << " requestSended: " << requestSended << " etagBackend.empty(): " << etagBackend.empty() << std::endl;
        if(backend!=nullptr)
        {
            std::cerr << " backend: " << backend << " backend download finished: " << backend->get_downloadFinishedCount() << std::endl;
            if(backend->backendList!=nullptr)
                std::cerr << " backend->backendList: " << backend << " backend->backendList->pending.size(): " << backend->backendList->pending.size() << std::endl;
        }
        std::cerr << std::endl;
    #endif

    if(backend!=nullptr && status==Status_WaitTheContent && requestSended)
    {
        if(readyToRead())//try again read something, if read something the problem is the event
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " readyToRead() WARN had more data but event readyToReady never getected!" << std::endl;
            lastReceivedBytesTimestamps=msFrom1970;
            return false;
        }
    }

    //be sure the backend will not reuse if have timeout problem
    //disconnectFrontend(true);
    if(backend!=nullptr)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
        #endif
        //disconnectBackend();
        backendErrorAndDisconnect("Timeout");//then able to retry
        //can't just connect the backend because the remaining data need to be consumed
        //then destroy backend too
        if(backend!=nullptr)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " close backend " << backend << " from http " << this << std::endl;
            backend->close();//keep the backend running, clean close
        }
    }
    else // was in pending list
    {
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " " << this << " call disconnectBackend()" << std::endl;
        #endif
        disconnectBackend();
    }

    std::cerr << std::to_string(msFrom1970) << "/" << std::to_string(lastReceivedBytesTimestamps) << " Http::detectTimeout() need to quit " << this;
    if(backend!=nullptr)
        std::cerr << " and quit backend " << (void *)backend << " backend download finished: " << backend->get_downloadFinishedCount();
    else
        std::cerr << " ";
    std::cerr  << __FILE__ << ":" << __LINE__ << " clientsList.size(): " << clientsList.size() << " endDetected: " << endDetected << " url: " << getUrl() << " contentwritten: " << contentwritten << " retryCount: " << (int)retryCount << " status: " << (int)status << std::endl;
    lastReceivedBytesTimestamps=msFrom1970;//prevent dual Http::detectTimeout()
    if(tempCache!=nullptr)
        std::cerr << "Http::detectTimeout() tempCache: " << tempCache << " fd: " << tempCache->getFD() << " " << __FILE__ << ":" << __LINE__ << std::endl;

    if(contentwritten==0)
        backendErrorAndDisconnect("Timeout into reply header");
    else
        backendErrorAndDisconnect("Timeout into body waiting");
    //parseNonHttpError(Backend::NonHttpError_Timeout);
    /*do into disconnectFrontend(true):
    for(Client * client : clientsList)
    {
        client->writeEnd();
        client->disconnect();
    }
    clientsList.clear();*/

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
    {
        ret+=", tempCacheFD: "+std::to_string(tempCache->getFD());
        std::ostringstream address;
        address << (void const *)tempCache;
        std::string name = address.str();
        ret+=", tempCache: "+name;
    }
    if(!tempPath.empty())
        ret+=", tempPath: "+tempPath;
    if(finalCache!=nullptr)
        ret+=", finalCache: "+cachePath;
    if(endDetected)
        ret+=", endDetected";
    else
        ret+=", !endDetected";
    return ret;
}

// === HTTP/3-first dial =====================================================

void Http::startH3()
{
    if(http3Conn!=nullptr) return;
    http3StartedMs = Common::msFrom1970();

    sockaddr_in6 h3target = m_socket;
    h3target.sin6_port = htobe16(Http::http3Port);

    http3Conn = new Http3();
    const std::string sessionKey = host + ":" + std::to_string(Http::http3Port);
    if(!http3Conn->start(h3target, host, sessionKey))
    {
        Http3::markOriginFailed(h3target);
        delete http3Conn;
        http3Conn = nullptr;
        return;
    }
    std::string h3path = uri;
    if(h3path.empty() || h3path[0] != '/')
        h3path = "/" + h3path;
    if(!http3Conn->submitGet(host, h3path))
    {
        Http3::markOriginFailed(h3target);
        delete http3Conn;
        http3Conn = nullptr;
        return;
    }
}

void Http::checkH3()
{
    if(http3Conn==nullptr) return;
    sockaddr_in6 h3target = m_socket;
    h3target.sin6_port = htobe16(Http::http3Port);

    // ---- H1.1 won the race ----
    // The H1.1 parser sets tempCache before headerWriten. Once EITHER
    // is set, H1.1 has begun client emit — H3 loses. We drop the H3 leg
    // without marking origin failed when H3 itself was OK (just slower
    // this round), and let H1.1 finish.
    if(headerWriten || tempCache != nullptr)
    {
        if(http3Conn->allStreamsDone() &&
           http3Conn->response().status >= 200 &&
           http3Conn->response().status < 500)
            Http3::markOriginSuccess(h3target);
        delete http3Conn;
        http3Conn = nullptr;
        return;
    }

    const uint64_t now = Common::msFrom1970();
    const bool deadlineExpired =
        http3StartedMs > 0 && now > http3StartedMs + Http::http3DeadlineMs;
    const bool connFailed = !http3Conn->isHealthy();
    const bool done       = http3Conn->allStreamsDone();

    // ---- H3 won the race ----
    if(done && http3Conn->response().status == 200)
    {
        // Detach from the H1.1 leg WITHOUT going through
        // disconnectBackend(): when the H1.1 Backend hasn't reached
        // wasTCPConnected (e.g. origin pauses before sending the
        // response line, exactly the slow-origin case where H3 wins),
        // Backend::downloadFinished interprets the detach as a
        // TCP-connect failure and fires backendErrorAndDisconnect on
        // *us* — surfacing a 500 to the client even though H3 just
        // succeeded. We can't take that error path during a successful
        // adopt.
        //
        // Instead: orphan the Backend by clearing the back-pointer.
        // The Backend's own state machine continues; when its connect
        // eventually completes (or times out) it sees http==nullptr,
        // drains any received bytes to /dev/null, returns itself to
        // the idle pool, or is reaped by CheckTimeout. No 500 leaks
        // back to clients.
        if(backend != nullptr)
        {
            backend->http = nullptr;
            backend = nullptr;
        }
        if(backendList != nullptr)
        {
            // If we were pending (not yet assigned a Backend), remove
            // ourselves from the queue so we don't get one later.
            unsigned int idx = 0;
            while(idx < backendList->pending.size())
            {
                if(backendList->pending.at(idx) == this)
                {
                    backendList->pending.erase(
                        backendList->pending.cbegin() + idx);
                }
                else
                    idx++;
            }
            backendList = nullptr;
        }
        if(!adoptH3Response())
        {
            Http3::markOriginFailed(h3target);
            delete http3Conn;
            http3Conn = nullptr;
            backendErrorAndDisconnect("H3 adopt failed");
        }
        return;
    }

    // ---- H3 lost (failed, deadlined, or non-200) ----
    if(connFailed || deadlineExpired ||
       (done && http3Conn->response().status >= 500))
    {
        Http3::markOriginFailed(h3target);
        delete http3Conn;
        http3Conn = nullptr;
        // H1.1 is running in parallel; nothing more to do here.
        return;
    }
    // Still in flight — nothing to do this tick.
}

bool Http::adoptH3Response()
{
    if(http3Conn==nullptr) return false;
    const Http3::ResponseState &r = http3Conn->response();
    if(r.status != 200) return false; // caller should have gated

    // ----- Open tempCache -----
    if(tempCache!=nullptr) { delete tempCache; tempCache=nullptr; }
    tempPath = cachePath + std::string(".tmp"); // simple per-Http suffix;
                                                  // mirrors the parser's
                                                  // tempPath convention
    // Append random for uniqueness same as parser.
    {
        char r6[6];
        if(::read(Http::fdRandom, r6, sizeof(r6)) != (ssize_t)sizeof(r6))
        {
            std::memset(r6, 0, sizeof(r6));
        }
        std::string rand;
        for(int i=0;i<6;++i) rand += randomETagChar(r6[i]);
        tempPath = cachePath + rand + ".tmp";
    }
    ::unlink(tempPath.c_str());
    int cachefd = ::open(tempPath.c_str(),
                         O_RDWR | O_CREAT | O_TRUNC,
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(cachefd == -1)
    {
        #ifdef HOSTSUBFOLDER
        {
            const std::string::size_type n=cachePath.rfind("/");
            if(n!=std::string::npos)
            {
                const std::string basePath=cachePath.substr(0,n);
                mkdir(basePath.c_str(),S_IRWXU);
            }
        }
        ::unlink(tempPath.c_str());
        cachefd = ::open(tempPath.c_str(),
                         O_RDWR | O_CREAT | O_TRUNC,
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        #endif
        if(cachefd == -1)
            return false;
    }
    Cache::newFD(cachefd, this, EpollObject::Kind::Kind_Cache);
    tempCache = new Cache(cachefd, nullptr);

    // ----- Frontend ETag (random 6 chars; parser does the same) -----
    char randomIndex[6];
    if(::read(Http::fdRandom, randomIndex, sizeof(randomIndex)) !=
       (ssize_t)sizeof(randomIndex))
        std::memset(randomIndex, 0, sizeof(randomIndex));
    std::string frontendEtag;
    for(int i=0;i<6;++i) frontendEtag += randomETagChar(randomIndex[i]);

    const int64_t currentTime   = time(NULL);
    const uint64_t currentTimeMs = Common::msFrom1970();

    if(!tempCache->set_access_time(currentTime) ||
       !tempCache->set_last_modification_time_check(currentTimeMs) ||
       !tempCache->set_http_code(200) ||
       !tempCache->set_ETagFrontend(frontendEtag) ||
       !tempCache->set_ETagBackend(r.etag))
    {
        tempCache->close();
        delete tempCache; tempCache=nullptr;
        return false;
    }

    // ----- Set Http parser-state members so subsequent invariants hold -----
    http_code      = 200;
    contenttype    = r.contentType;
    contentEncoding= r.contentEncoding;
    contentsize    = static_cast<int64_t>(r.body.size());
    etagBackend    = r.etag;
    parsing        = Parsing_Content;

    // ----- Build response header bytes -----
    std::string header;
    if(contentsize >= 0)
        header += "Content-Length: " + std::to_string(contentsize) + "\n";
    if(Http::useCompression && gzip && !contentEncoding.empty())
    {
        header += "Content-Encoding: " + contentEncoding + "\n";
        contentEncoding.clear();
    }
    if(!contenttype.empty())
        header += "Content-Type: " + contenttype + "\n";
    else
        header += "Content-Type: text/html\n";
    {
        const std::string date   = timestampsToHttpDate(currentTime);
        const std::string expire = timestampsToHttpDate(
            currentTime + Cache::timeToCache(200));
        header += "Date: "+date+"\n"
                  "Expires: "+expire+"\n"
                  "Cache-Control: public\n"
                  "ETag: \""+frontendEtag+"\"\n";
    }
    header += "\n";

    tempCache->seekToContentPos();

    // ----- Write fastcgi stdout header + response header -----
    uint16_t sizebe = htobe16(header.size());
    std::memcpy(Http::fastcgiheaderstdout+1+1+2, &sizebe, 2);
    if(tempCache->write(Http::fastcgiheaderstdout,
                        sizeof(Http::fastcgiheaderstdout))
       != (ssize_t)sizeof(Http::fastcgiheaderstdout))
    {
        tempCache->close();
        delete tempCache; tempCache=nullptr;
        return false;
    }
    if(tempCache->write(header.data(), header.size()) !=
       (ssize_t)header.size())
    {
        tempCache->close();
        delete tempCache; tempCache=nullptr;
        return false;
    }
    headerWriten = true;

    // Clients start reading the temp cache file now; writeToCache will
    // append body bytes which they will pick up.
    for(Client * client : clientsList)
        client->startRead(tempPath, true);

    // ----- Write body via existing path (handles fastcgi end + emit) -----
    if(!r.body.empty())
    {
        writeToCache(reinterpret_cast<const char *>(r.body.data()),
                     r.body.size());
    }
    else
    {
        // Zero-body shortcut, mirroring the parser's Content-Length:0 path.
        endDetected = true;
        tempCache->write(Http::fastcgiheaderend, sizeof(Http::fastcgiheaderend));
        for(Client * client : clientsList)
            client->tryResumeReadAfterEndOfFile();
        disconnectFrontend(false);
    }

    // ----- Cleanup the H3 leg; mark origin as healthy -----
    sockaddr_in6 h3target = m_socket;
    h3target.sin6_port = htobe16(Http::http3Port);
    Http3::markOriginSuccess(h3target);
    delete http3Conn;
    http3Conn = nullptr;
    return true;
}


