#include <errno.h>
#include <sys/epoll.h>
#include "Server.hpp"
#include "ServerReload.hpp"
#ifdef DEBUGFASTCGITCP
#include "ServerTCP.hpp"
#endif
#include "Common.hpp"
#include "Client.hpp"
#include "ClientReload.hpp"
#include "Http.hpp"
#include "Http3.hpp"
#include "Http3Probe.hpp"
#include "Dns.hpp"
#include "Backend.hpp"
#include "Cache.hpp"
#include "Timer.hpp"
#include "Timer/DNSCache.hpp"
#include "Timer/DNSQuery.hpp"
#include "Timer/CheckTimeout.hpp"
#include "Timer/CleanOldCache.hpp"
#include <vector>
#include <cstring>
#include <cstdio>
#include <signal.h>
#include <iostream>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <chrono>

#define MAX_EVENTS 1024

void signal_callback_handler(int signum) {
    (void)signum;
    #ifdef DEBUGFASTCGI
    printf("Caught signal SIGPIPE %d\n",signum);
    #endif
}

int main(int argc, char *argv[])
{
    if(argc==2 && strcmp(argv[1],"--check-static-dns")==0)
    {
        return Dns::checkStaticEntry();
    }
    if(argc==2 && strcmp(argv[1],"reload")==0)
    {
        auto start = std::chrono::steady_clock::now();
        sockaddr_un addr;
        int fd;

        if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
          perror("socket error");
          exit(-1);
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "reload.sock", sizeof(addr.sun_path)-1);

        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
          perror("connect error");
          exit(-1);
        }

        const std::vector<std::pair<in6_addr,std::string>> &data=Dns::getStaticEntry();
        unsigned int buffersize=0;
        {
            unsigned int index=0;
            while(index<data.size())
            {
                const std::pair<in6_addr,std::string> &e=data.at(index);
                if(e.second.size()<255)
                {
                    buffersize+=sizeof(in6_addr);
                    buffersize+=sizeof(uint8_t);
                    buffersize+=e.second.size();
                }
                index++;
            }
        }
        char buffer[buffersize];
        {
            size_t pos=0;
            unsigned int index=0;
            while(index<data.size())
            {
                const std::pair<in6_addr,std::string> &e=data.at(index);
                if(e.second.size()<255)
                {
                    memcpy(buffer,&e.first,sizeof(e.first));pos+=sizeof(e.first);
                    const uint8_t &s=e.second.size();
                    memcpy(buffer,&s,sizeof(s));pos+=sizeof(s);
                    memcpy(buffer,e.second.data(),s);pos+=s;
                }
                index++;
            }
        }
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        long long milliseconds = duration.count();
        std::cout << "loaded and serialised into: " << milliseconds << " ms" << std::endl;

        if(::write(fd, buffer, buffersize) != (ssize_t)buffersize)
        {
            std::cerr << "failed to write" << std::endl;
            return -1;
        }

        return 0;
    }
    std::cout << "start main()" << std::endl;
    #ifdef FASTCGIASYNC
    std::cerr << "compiled with ASYNC support" << std::endl;
    #endif
    /* ------------ */
    /* Init openssl */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    Backend::meth = TLS_client_method();

    /* Catch Signal Handler SIGPIPE */
    if(signal(SIGPIPE, signal_callback_handler)==SIG_ERR)
    {
        std::cerr << "signal(SIGPIPE, signal_callback_handler)==SIG_ERR, errno: " << std::to_string(errno) << std::endl;
        abort();
    }
    memset(Http::buffer,0,sizeof(Http::buffer));
    #ifdef FORCEDPORT_TLS
    Backend::https_portBE=htobe16(FORCEDPORT_TLS);
    #else
    Backend::https_portBE=htobe16(443);
    #endif

    for (int i = 1; i < argc; ++i) {
        std::string argvcpp(argv[i]);
        #ifdef DEBUGFASTCGI
        std::cout << "Parse arg: " << argvcpp << std::endl;
        #endif
        if (argvcpp == "--nocache") {
            #ifdef DEBUGFASTCGI
            std::cout << "Now cache is deleted when finish" << std::endl;
            #endif
            Cache::enable=false;
        }
        else if (argvcpp == "--forcehttpclose") {
            #ifdef DEBUGFASTCGI
            std::cout << "Now force http close connection after each request" << std::endl;
            #endif
            Backend::forceHttpClose=true;
        }
        else if (argvcpp == "--disableCompressionForBackend") {
            #ifdef DEBUGFASTCGI
            std::cout << "Now compression disabled for backend" << std::endl;
            #endif
            Http::useCompression=false;
        }
        else if (argvcpp == "--http3") {
            Http::http3Enabled = true;
            #ifdef DEBUGFASTCGI
            std::cout << "HTTP/3-first dial enabled for HTTPS fetches" << std::endl;
            #endif
        }
        else if (argvcpp == "--http3-probe") {
            Http3Probe::enabled = true;
            #ifdef DEBUGFASTCGI
            std::cout << "Now HTTP/3 telemetry probe enabled" << std::endl;
            #endif
        }
        else if (argvcpp == "--disableStreaming") {
            #ifdef DEBUGFASTCGI
            std::cout << "Now streaming disabled (parse as normal file)" << std::endl;
            #endif
            Http::allowStreaming=false;
        }
        else if (std::string(argv[i]) == "--help") {
                    std::cerr << "--nocache: to file on disk is only used to have temp file, removed at end of downloading" << std::endl;
                    std::cerr << "--http200Time=999: for http 200, time in seconds without recheck" << std::endl;
                    std::cerr << "--maxdownloadtime=3600: maximum time in seconds to download file on CDN" << std::endl;
                    std::cerr << "--maxreadtime=20: maximum time in seconds to get new data from url for the CDN" << std::endl;
                    std::cerr << "--maxdwritetime=10: maximum time in seconds to send new data to client" << std::endl;
                    std::cerr << "--maxBackend=999: maximum backend to a single IP (connexion limit)" << std::endl;
                    std::cerr << "--forcehttpclose: force http close connection after each request" << std::endl;
                    std::cerr << "--disableCompressionForBackend: disable request http compression for backend" << std::endl;
                    std::cerr << "--disableStreaming: disable streaming detection and replay" << std::endl;
                    std::cerr << "--http3-probe: telemetry-only HTTP/3 side-channel for HTTPS fetches (logs only, no traffic effect)" << std::endl;
                    std::cerr << "--http3: dial HTTPS fetches over HTTP/3 first, fall back to HTTP/1.1 on failure or timeout" << std::endl;
                    std::cerr << "--http3-port=443: UDP port for HTTP/3 backend dials" << std::endl;
                    std::cerr << "--http3-deadline-ms=8000: per-fetch HTTP/3 budget; on expiry the daemon falls back to HTTP/1.1" << std::endl;
                    std::cerr << "--check-static-dns: parse static-DNS sources (ssl/, /etc/nginx/ssl/, hosts) and exit 0 on success / non-zero if a source is present but yields no entries" << std::endl;
                    //std::cerr << "--maxiumSizeToBeSmallFile: (TODO) if smaller than this size, save into RAM, performance features where syscall have time more check and is slower (few bandwith is lost if restart/redownload, too small content, but hurge performance impact)" << std::endl;
                    //std::cerr << "--maxiumSmallFileCacheSize: (TODO) The maximum content stored in RAM, this cache prevent syscall and disk seek, performance features where syscall have time more check and is slower (few bandwith is lost if restart/redownload, too small content, but hurge performance impact)" << std::endl;
                    return 1;
        }
        else
        {
            std::string::size_type n=argvcpp.find("=");
            if (n != std::string::npos) {
                std::string var=argvcpp.substr(0,n);
                std::string val=argvcpp.substr(n+1);
                if (var=="--http200Time") {
                    Cache::http200Time=std::stoi(val);
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Cache::http200Time is " << Cache::http200Time << "s" << std::endl;
                    #endif
                }
                else if (var=="--maxdownloadtime") {
                    Cache::maxDownloadTimeInMS=std::stoi(val)*1000;
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Cache::maxDownloadTimeInMS is " << Cache::maxDownloadTimeInMS << "s" << std::endl;
                    #endif
                }
                else if (var=="--maxreadtime") {
                    Cache::maxDownloadIdleTimeREADInMS=std::stoi(val)*1000;
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Cache::maxDownloadIdleTimeREADInMS is " << Cache::maxDownloadIdleTimeREADInMS << "s" << std::endl;
                    #endif
                }
                else if (var=="--maxdwritetime") {
                    Cache::maxDownloadIdleTimeWRITEInMS=std::stoi(val)*1000;
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Cache::maxDownloadIdleTimeWRITEInMS is " << Cache::maxDownloadIdleTimeWRITEInMS << "s" << std::endl;
                    #endif
                }
                else if (var=="--http3-port") {
                    Http::http3Port = static_cast<uint16_t>(std::stoi(val));
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Http::http3Port is " << Http::http3Port << std::endl;
                    #endif
                }
                else if (var=="--http3-deadline-ms") {
                    Http::http3DeadlineMs = static_cast<uint64_t>(std::stoull(val));
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Http::http3DeadlineMs is " << Http::http3DeadlineMs << "ms" << std::endl;
                    #endif
                }
                else if (var=="--maxBackend") { //--maxBackend=64
                    Backend::maxBackend=std::stoi(val);
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Backend::maxBackend is " << Backend::maxBackend << std::endl;
                    #endif
                }
                else
                {
                    std::cout << "Parameter unknown: " << var << std::endl;
                    return 1;
                }
            }
        }
    }

    /*//memset(Client::pathVar,0,sizeof(Client::pathVar));
    #ifdef HOSTSUBFOLDER
    {
        strncpy(Client::pathVar,"XXXXXXXX/XXXXXXXXXXXXXXXXY",sizeof(Client::pathVar));
        strncpy(Client::folderVar,"XXXXXXXX",sizeof(Client::folderVar));
        memset(Client::folderVar,0,sizeof(Client::folderVar));
        strncpy(Client::folderVar,"",sizeof(Client::folderVar));
    }
    #else
    {
        //strncpy(Client::pathVar,"XXXXXXXXXXXXXXXXY",sizeof(Client::pathVar));
    }
    #endif*/

    (void)argc;
    (void)argv;

    //the event loop
    struct epoll_event ev, events[MAX_EVENTS];
    memset(&ev,0,sizeof(ev));
    int nfds, epollfd;

    Http::fdRandom=open("/dev/urandom",O_RDONLY);

    ev.events = EPOLLIN|EPOLLET;

    if ((epollfd = epoll_create1(0)) == -1) {
        printf("epoll_create1: %s", strerror(errno));
        return -1;
    }
    EpollObject::epollfd=epollfd;
    Dns::dns=new Dns();
    Dns::dns->reloadStaticEntry(Dns::getStaticEntry());
    DNSCache dnsCache;
    dnsCache.start(3600*1000);
    DNSQuery dnsQuery;
    dnsQuery.start(50);
    CheckTimeout checkTimeout;
    checkTimeout.start(1000);
    CleanOldCache cleanOldCache;
    cleanOldCache.start(1000);

    //FCGI_END_REQUEST
    {
        Http::fastcgiheaderend[0]=1;
        Http::fastcgiheaderend[1]=3;
        uint16_t idbe=htobe16(1);
        memcpy(Http::fastcgiheaderend+1+1,&idbe,2);
        uint16_t sizebe=htobe16(8);
        memcpy(Http::fastcgiheaderend+1+1+2,&sizebe,2);
        uint16_t padding=0;
        memcpy(Http::fastcgiheaderend+1+1+2+2,&padding,2);
        uint32_t applicationStatus=0;
        memcpy(Http::fastcgiheaderend+1+1+2+2+2,&applicationStatus,4);
        uint32_t protocolStatus=0;
        memcpy(Http::fastcgiheaderend+1+1+2+2+2+4,&protocolStatus,4);
    }

    {
        uint16_t padding=0;
        Http::fastcgiheaderstdout[0]=1;
        //FCGI_STDOUT
        Http::fastcgiheaderstdout[1]=6;
        uint16_t idbe=htobe16(1);
        memcpy(Http::fastcgiheaderstdout+1+1,&idbe,2);
        uint16_t sizebe=htobe16(0);
        memcpy(Http::fastcgiheaderstdout+1+1+2,&sizebe,2);
        memcpy(Http::fastcgiheaderstdout+1+1+2+2,&padding,2);
    }

    #ifdef DEBUGDNS
    {
        FILE *stream;
        char *line = NULL;
        size_t len = 0;
        ssize_t nread;

        stream = fopen("dns.txt", "r");
        if (stream != NULL)
        {
            while ((nread = getline(&line, &len, stream)) != -1) {
                std::string str(line);
                std::size_t pos=str.find(" ");
                if (pos!=std::string::npos)
                {
                    std::string host=str.substr(0,pos);
                    std::string ipv6=str.substr(pos+1);
                    if(!ipv6.empty())
                    {
                        if(ipv6.at(ipv6.size()-1)=='\n')
                            ipv6=ipv6.substr(0,ipv6.size()-1);
                        Dns::dns->hardcodedDns[host]=ipv6;
                    }
                }
            }

            free(line);
            fclose(stream);
        }
    }
    #endif

    /* cachePath (content header, 64Bits aligned):
     * 64Bits: access time
     * 64Bits: last modification time check
     * 64Bits: modification time */

    /*Server *server=*///new Server("/run/fastcgicdn.sock");
    Server s("fastcgicdn.sock");
    ServerReload sR("reload.sock");
    #ifdef DEBUGFASTCGITCP
    ServerTCP sTcp("127.0.0.1","5556");
    #endif
    (void)s;
    std::unordered_set<Client *> newDeleteClient,oldDeleteClient;
    std::vector<Backend *> newDeleteBackend,oldDeleteBackend;
    std::unordered_set<Http *> newDeleteHttp,oldDeleteHttp;

    //change dir to cache to minize change
    mkdir("cache", S_IRWXU);
    if(chdir("cache")==-1)
    {
        printf("epoll_wait error %s", strerror(errno));
        abort();
    }

/*    Client *c=new Client(99);
    c->readyToRead();
    abort();*/

    //try multi thread with efd = eventfd(0, EFD_NONBLOCK);
    for (;;) {
        if ((nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1)) == -1)
            printf("epoll_wait error %s", strerror(errno));
        for(Client * client : oldDeleteClient)
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << "Try delete Client " << (void *)client << std::endl;
            if(Client::clientToDebug.find(client)==Client::clientToDebug.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete Client failed, not found into debug " << (void *)client << " (abort)" << std::endl;
                //abort();
            }
            else
            #endif
            if(Client::clients.find(client)==Client::clients.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete Client failed, not found into debug " << (void *)client << " (abort)" << std::endl;
                //abort();
            }
            else
            {
                #ifdef DEBUGFASTCGI
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete Client " << (void *)client << std::endl;
                #endif
                delete client;
                #ifdef DEBUGFASTCGI
                //do into the destructor
                //Client::clientToDebug.erase(client);
                //CHECK IF DELETE LOOP! IF THE DESTRUCTOR insert again the object into toDelete list!
                if(Client::clientToDelete.find(client)!=Client::clientToDelete.cend())
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " " << "DOBLE DELETE LOOP! THE DESTRUCTOR insert again the object into toDelete list! " << (void *)client << " (abort)" << std::endl;
                    abort();
                }
                #endif
            }
        }
        for(Backend * b : oldDeleteBackend)
        {
            #ifdef DEBUGFASTCGI
            if(Backend::backendToDebug.find(b)==Backend::backendToDebug.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete Backend failed, not found into debug " << (void *)b << " (abort)" << std::endl;
                abort();
            }
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete backend " << (void *)b << std::endl;
            #endif
            delete b;
            #ifdef DEBUGFASTCGI
            //do into the destructor
            //Backend::backendToDebug.erase(b);
            #endif
        }
        for(Http * r : oldDeleteHttp)
        {
            #ifdef DEBUGFASTCGI
            if(Http::httpToDebug.find(r)==Http::httpToDebug.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete Http failed, not found into debug " << (void *)r << " time: " << Common::msFrom1970() << " (abort)" << std::endl;
                //abort();
            }
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete http " << (void *)r << " time: " << Common::msFrom1970() << std::endl;
            #endif
            if(r->get_status()==Http::Status::Status_WaitDns)
            {
                Dns::dns->cancelClient(r,r->get_host(),r->isHttps(),true);
                #ifdef DEBUGDNS
                Dns::checkCorruption();
                #endif
            }
            r->disconnectBackend(true);
            #ifdef DEBUGDNS
            Dns::checkCorruption();
            #endif
            delete r;
            #ifdef DEBUGFASTCGI
            //do into the destructor
            //Http::httpToDebug.erase(r);
            #endif
            #ifdef DEBUGDNS
            Dns::checkCorruption();
            //do into the destructor
            /*if(Http::httpToDelete.find(r)!=Http::httpToDelete.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete http loop" << (void *)r << " (abort)" << std::endl;
                abort();
            }*/
            #endif
            #ifdef DEBUGFASTCGI
            if(Http::httpToDebug.find(r)!=Http::httpToDebug.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "delete Http failed, found after delete into debug " << (void *)r << " (abort)" << std::endl;
                //abort();
            }
            //CHECK IF DELETE LOOP! IF THE DESTRUCTOR insert again the object into toDelete list!
            if(Http::httpToDelete.find(r)!=Http::httpToDelete.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " " << "DOBLE DELETE LOOP! THE DESTRUCTOR insert again the object into toDelete list! " << (void *)r << " (abort)" << std::endl;
                abort();
            }
            #endif
        }
        #ifdef DEBUGDNS
        Dns::checkCorruption();
        #endif
        oldDeleteClient=newDeleteClient;
        newDeleteClient.clear();
        oldDeleteBackend=newDeleteBackend;
        newDeleteBackend.clear();
        oldDeleteHttp=newDeleteHttp;
        newDeleteHttp.clear();
        for (int n = 0; n < nfds; ++n)
        {
            #ifdef DEBUGFASTCGI
            Http::checkIngrityHttpClient();
            #endif
            #ifdef DEBUGFASTCGI
            Backend::checkBackend();
            #endif
            #ifdef DEBUGDNS
            Dns::dns->checkCorruption();
            #endif
            epoll_event &e=events[n];
            switch(static_cast<EpollObject *>(e.data.ptr)->getKind())
            {
                case EpollObject::Kind::Kind_Server:
                {
                    Server * server=static_cast<Server *>(e.data.ptr);
                    server->parseEvent(e);
                }
                break;
                case EpollObject::Kind::Kind_ServerReload:
                {
                    ServerReload * server=static_cast<ServerReload *>(e.data.ptr);
                    server->parseEvent(e);
                }
                break;
                case EpollObject::Kind::Kind_Client:
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << "Event on Client " << e.data.ptr << " e.events: " << e.events << " time: " << Common::msFrom1970() << " nfds: " << nfds << std::endl;
                    std::cerr << "Event dump: " << std::endl;
                    for (int n = 0; n < nfds; ++n)
                        std::cerr << "Event " << events[n].events << " on " << events[n].data.ptr << std::endl;
                    #endif
                    Client * client=static_cast<Client *>(e.data.ptr);
                    client->parseEvent(e);
                    if(!client->isValid())
                    {
                        #ifdef DEBUGFASTCGI
                        std::cerr << "now " << client << " !client->isValid()" << std::endl;
                        #endif
                        //if(!deleteClient.empty() && deleteClient.back()!=client)
                        newDeleteClient.insert(client);
                        client->disconnect();
                    }
                }
                break;
                case EpollObject::Kind::Kind_ClientReload:
                {
                    ClientReload * client=static_cast<ClientReload *>(e.data.ptr);
                    client->parseEvent(e);
                    if(!client->isValid())
                    {
                        client->disconnect();
                        delete client;
                    }
                }
                break;
                case EpollObject::Kind::Kind_Backend:
                {
                    Backend * backend=static_cast<Backend *>(e.data.ptr);
                    backend->parseEvent(e);
                    /*if(!http->toRemove.empty())
                        newDeleteHttp.insert(newDeleteHttp.end(),http->toRemove.cbegin(),http->toRemove.cend());*/
                    if(!backend->isValid())
                    {
                        #ifdef DEBUGFASTCGI
                        std::cerr << "Event on Backend " << e.data.ptr << " e.events: " << e.events << " time: " << Common::msFrom1970() << " nfds: " << nfds << " now delete" << std::endl;
                        std::cerr << "Event dump: " << std::endl;
                        for (int n = 0; n < nfds; ++n)
                            std::cerr << "Event " << events[n].events << " on " << events[n].data.ptr << std::endl;
                        #endif
                        backend->close();
                        backend->remoteSocketClosed();
                        newDeleteBackend.push_back(backend);
                    }
                }
                break;
                case EpollObject::Kind::Kind_Dns:
                {
                    DnsSocket * dnsSocket=static_cast<DnsSocket *>(e.data.ptr);
                    dnsSocket->parseEvent(e);
                }
                break;
                case EpollObject::Kind::Kind_Timer:
                {
                    static_cast<Timer *>(e.data.ptr)->exec();
                    static_cast<Timer *>(e.data.ptr)->validateTheTimer();
                }
                break;
                case EpollObject::Kind::Kind_Http3:
                {
                    Http3 * h3=static_cast<Http3 *>(e.data.ptr);
                    h3->parseEvent(e);
                }
                break;
                #ifdef DEBUGFASTCGITCP
                case EpollObject::Kind::Kind_ServerTCP:
                {
                    ServerTCP * serverTcp=static_cast<ServerTCP *>(e.data.ptr);
                    serverTcp->parseEvent(e);
                }
                break;
                #endif
                default:
                break;
            }
            #ifdef DEBUGFASTCGI
            Http::checkIngrityHttpClient();
            #endif
            #ifdef DEBUGFASTCGI
            Backend::checkBackend();
            #endif
            #ifdef DEBUGDNS
            Dns::dns->checkCorruption();
            #endif
        }
        #ifdef DEBUGFASTCGI
        for(Client * client : Client::clientToDelete)
            std::cerr << "client planed to delete: " << client << " " << __FILE__ << ":" << __LINE__ << std::endl;
        for(Backend * b : newDeleteBackend)
            std::cerr << "Backend planed to delete: " << b << " " << __FILE__ << ":" << __LINE__ << std::endl;
        for(Http * r : Http::httpToDelete)
            std::cerr << "http planed to delete: " << r << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        // Filter: don't re-queue clients/http already in oldDeleteClient/Http.
        // Those items are about to be deleted at the top of the *next* iteration
        // (line 353 / line 405). If we re-add them here, they re-enter
        // newDeleteClient → next-next iter's oldDeleteClient → a second delete
        // attempt on an already-freed pointer ("delete Client failed, not found
        // into debug" — see the multi_client_flapping test case). The race is:
        // CheckTimeout iterates Client::clients between the iter that marks the
        // client invalid and the iter that actually deletes it; the client is
        // still in clients (destructor hasn't run yet) and CheckTimeout adds
        // it to Client::clientToDelete a second time.
        for(Client * client : Client::clientToDelete)
            if(oldDeleteClient.find(client) == oldDeleteClient.cend())
                newDeleteClient.insert(client);
        Client::clientToDelete.clear();
        for(Http * http : Http::httpToDelete)
            if(oldDeleteHttp.find(http) == oldDeleteHttp.cend())
                newDeleteHttp.insert(http);
        Http::httpToDelete.clear();
    }

    return 0;
}
