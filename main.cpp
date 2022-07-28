#include <errno.h>
#include <sys/epoll.h>
#include "Server.hpp"
#ifdef DEBUGFASTCGITCP
#include "ServerTCP.hpp"
#endif
#include "Client.hpp"
#include "Http.hpp"
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

#define MAX_EVENTS 1024

void signal_callback_handler(int signum) {
    (void)signum;
    #ifdef DEBUGFASTCGI
    printf("Caught signal SIGPIPE %d\n",signum);
    #endif
}

int main(int argc, char *argv[])
{
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
    Backend::https_portBE=be16toh(443);

    for (int i = 1; i < argc; ++i) {
        std::string argvcpp(argv[i]);
        if (argvcpp == "--nocache") {
            #ifdef DEBUGFASTCGI
            std::cout << "Now cache is deleted when finish" << std::endl;
            #endif
            Cache::enable=false;
        }
        else if (argvcpp == "--disableCompressionForBackend") {
            #ifdef DEBUGFASTCGI
            std::cout << "Now compression disabled for backend" << std::endl;
            #endif
            Http::useCompression=false;
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
                    std::cerr << "--maxBackend=999: maximum backend to a single IP (connexion limit)" << std::endl;
                    std::cerr << "--disableCompressionForBackend: disable request http compression for backend" << std::endl;
                    std::cerr << "--disableStreaming: disable streaming detection and replay" << std::endl;
                    //std::cerr << "--maxiumSizeToBeSmallFile: (TODO) if smaller than this size, save into memory" << std::endl;
                    //std::cerr << "--maxiumSmallFileCacheSize: (TODO) The maximum content stored in memory, this cache prevent syscall and disk seek" << std::endl;
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
                else if (var=="--maxBackend") {
                    Backend::maxBackend=std::stoi(val);
                    #ifdef DEBUGFASTCGI
                    std::cout << "Now Backend::maxBackend is " << Backend::maxBackend << std::endl;
                    #endif
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
    DNSCache dnsCache;
    dnsCache.start(3600*1000);
    DNSQuery dnsQuery;
    dnsQuery.start(10);
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

    /* cachePath (content header, 64Bits aligned):
     * 64Bits: access time
     * 64Bits: last modification time check
     * 64Bits: modification time */

    /*Server *server=*///new Server("/run/fastcgicdn.sock");
    Server s("fastcgicdn.sock");
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
            std::cerr << "Try delete Client " << (void *)client << std::endl;
            if(Client::toDebug.find(client)==Client::toDebug.cend())
            {
                std::cerr << "delete Client failed, not found into debug " << (void *)client << " (abort)" << std::endl;
                //abort();
            }
            else
            #endif
            if(Client::clients.find(client)==Client::clients.cend())
            {
                std::cerr << "delete Client failed, not found into debug " << (void *)client << " (abort)" << std::endl;
                //abort();
            }
            else
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "delete Client " << (void *)client << std::endl;
                #endif
                delete client;
            }
        }
        for(Backend * b : oldDeleteBackend)
        {
            #ifdef DEBUGFASTCGI
            if(Backend::toDebug.find(b)==Backend::toDebug.cend())
            {
                std::cerr << "delete Backend failed, not found into debug " << (void *)b << " (abort)" << std::endl;
                abort();
            }
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << "delete backend " << (void *)b << std::endl;
            #endif
            delete b;
        }
        for(Http * r : oldDeleteHttp)
        {
            #ifdef DEBUGFASTCGI
            if(Http::toDebug.find(r)==Http::toDebug.cend())
            {
                std::cerr << "delete Http failed, not found into debug " << (void *)r << " (abort)" << std::endl;
                abort();
            }
            #endif
            #ifdef DEBUGFASTCGI
            std::cerr << "delete http " << (void *)r << std::endl;
            #endif
            delete r;
        }
        oldDeleteClient=newDeleteClient;
        newDeleteClient.clear();
        oldDeleteBackend=newDeleteBackend;
        newDeleteBackend.clear();
        oldDeleteHttp=newDeleteHttp;
        newDeleteHttp.clear();
        for (int n = 0; n < nfds; ++n)
        {
            epoll_event &e=events[n];
            switch(static_cast<EpollObject *>(e.data.ptr)->getKind())
            {
                case EpollObject::Kind::Kind_Server:
                {
                    Server * server=static_cast<Server *>(e.data.ptr);
                    server->parseEvent(e);
                }
                break;
                case EpollObject::Kind::Kind_Client:
                {
                    #ifdef DEBUGFASTCGI
                    std::cerr << "Event on Client " << e.data.ptr << std::endl;
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
                case EpollObject::Kind::Kind_Backend:
                {
                    Backend * backend=static_cast<Backend *>(e.data.ptr);
                    backend->parseEvent(e);
                    /*if(!http->toRemove.empty())
                        newDeleteHttp.insert(newDeleteHttp.end(),http->toRemove.cbegin(),http->toRemove.cend());*/
                    if(!backend->isValid())
                        newDeleteBackend.push_back(backend);
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
        }
        newDeleteClient.insert(Client::toDelete.begin(),Client::toDelete.end());
        Client::toDelete.clear();
        newDeleteHttp.insert(Http::toDelete.begin(),Http::toDelete.end());
        Http::toDelete.clear();
    }

    return 0;
}
