#include "Dns.hpp"
#include "Http.hpp"
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <algorithm>

struct __attribute__ ((__packed__)) dns_query {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t add_count;
    uint8_t  payload[];
};

Dns *Dns::dns=nullptr;
const unsigned char Dns::include[]={0x28,0x03,0x19,0x20};
const unsigned char Dns::exclude[]={0x28,0x03,0x19,0x20,0x00,0x00,0x00,0x00,0xb4,0xb2,0x5f,0x61,0xd3,0x7f};
#ifdef DEBUGDNS
std::unordered_map<std::string,std::string> Dns::hardcodedDns;
#endif

Dns::Dns()
{
    memset(&targetHttp,0,sizeof(targetHttp));
    targetHttp.sin6_port = htobe16(80);
    targetHttp.sin6_family = AF_INET6;

    memset(&targetHttps,0,sizeof(targetHttps));
    targetHttps.sin6_port = htobe16(443);
    targetHttps.sin6_family = AF_INET6;

    httpInProgress=0;
    IPv4Socket=nullptr;
    IPv6Socket=nullptr;

    uint8_t indexPreferedServerOrder=0;

    /*memset(&targetDnsIPv6, 0, sizeof(targetDnsIPv6));
    targetDnsIPv6.sin6_port = htobe16(53);
    memset(&targetDnsIPv4, 0, sizeof(targetDnsIPv4));
    targetDnsIPv4.sin_port = htobe16(53);*/

    memset(&sin6_addr,0,sizeof(sin6_addr));
    if(!tryOpenSocket())
    {
        std::cerr << "tryOpenSocket() failed (abort)" << std::endl;
        abort();
    }

    //read resolv.conf
    {
        FILE * fp;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        fp = fopen("/etc/resolv.conf", "r");
        if (fp == NULL)
        {
            std::cerr << "Unable to open /etc/resolv.conf" << std::endl;
            exit(EXIT_FAILURE);
        }

        while ((read = getline(&line, &len, fp)) != -1) {
            //create udp socket to dns server

            std::string line2(line);
            std::string prefix=line2.substr(0,11);
            if(prefix=="nameserver ")
            {
                line2=line2.substr(11);
                line2.resize(line2.size()-1);
                const std::string &host=line2;

                sockaddr_in6 targetDnsIPv6;
                memset(&targetDnsIPv6, 0, sizeof(targetDnsIPv6));
                targetDnsIPv6.sin6_port = htobe16(53);
                const char * const hostC=host.c_str();
                int convertResult=inet_pton(AF_INET6,hostC,&targetDnsIPv6.sin6_addr);
                if(convertResult!=1)
                {
                    sockaddr_in targetDnsIPv4;
                    memset(&targetDnsIPv4, 0, sizeof(targetDnsIPv4));
                    targetDnsIPv4.sin_port = htobe16(53);
                    convertResult=inet_pton(AF_INET,hostC,&targetDnsIPv4.sin_addr);
                    if(convertResult!=1)
                    {
                        std::cerr << "not IPv4 and IPv6 address, host: \"" << host << "\", portstring: \"53\", errno: " << std::to_string(errno) << std::endl;
                        abort();
                    }
                    else
                    {
                        targetDnsIPv4.sin_family = AF_INET;

                        DnsServerEntry e;
                        e.mode=Mode_IPv4;
                        memcpy(&e.targetDnsIPv4,&targetDnsIPv4,sizeof(targetDnsIPv4));
                        memset(&e.targetDnsIPv6,0,sizeof(e.targetDnsIPv6));
                        e.lastFailed=0;
                        dnsServerList.push_back(e);
                        preferedServerOrder[indexPreferedServerOrder]=indexPreferedServerOrder;
                        indexPreferedServerOrder++;

                        #ifdef DEBUGDNS
                        char str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &e.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                        std::cerr << "add new dns server: " << str << std::endl;
                        #endif
                    }
                }
                else
                {
                    targetDnsIPv6.sin6_family = AF_INET6;

                    DnsServerEntry e;
                    e.mode=Mode_IPv6;
                    memcpy(&e.targetDnsIPv6,&targetDnsIPv6,sizeof(targetDnsIPv6));
                    memset(&e.targetDnsIPv4,0,sizeof(e.targetDnsIPv4));
                    e.lastFailed=0;
                    dnsServerList.push_back(e);
                    preferedServerOrder[indexPreferedServerOrder]=indexPreferedServerOrder;
                    indexPreferedServerOrder++;

                    #ifdef DEBUGDNS
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &e.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                    std::cerr << "add new dns server: " << str << std::endl;
                    #endif
                }
            }

        }

        fclose(fp);
        if (line)
            free(line);
    }
    while(indexPreferedServerOrder<MAXDNSSERVER)
    {
        preferedServerOrder[indexPreferedServerOrder]=0;
        indexPreferedServerOrder++;
    }

    if(dnsServerList.empty())
    {
        std::cerr << "Sorry but the server list is empty" << std::endl;
        abort();
    }
    increment=1;
}

Dns::~Dns()
{
}

bool Dns::tryOpenSocket()
{
    {
        const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == -1)
        {
            std::cerr << "unable to create UDP socket" << std::endl;
            abort();
        }
        sockaddr_in si_me;
        memset((char *) &si_me, 0, sizeof(si_me));
        si_me.sin_family = AF_INET;
        si_me.sin_port = htons(50053);
        si_me.sin_addr.s_addr = htonl(INADDR_ANY);
        if(bind(fd,(struct sockaddr*)&si_me, sizeof(si_me))==-1)
        {
            std::cerr << "unable to bind UDP socket, errno: " << errno << std::endl;
            abort();
        }

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
        }
        IPv4Socket=new DnsSocket(fd);
    }
    {
        const int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == -1)
        {
            std::cerr << "unable to create UDP socket" << std::endl;
            abort();
        }
        sockaddr_in6 si_me;
        memset((char *) &si_me, 0, sizeof(si_me));
        si_me.sin6_family = AF_INET6;
        si_me.sin6_port = htons(50054);
        si_me.sin6_addr = IN6ADDR_ANY_INIT;
        if(bind(fd,(struct sockaddr*)&si_me, sizeof(si_me))==-1)
        {
            std::cerr << "unable to bind UDP socket, errno: " << errno << std::endl;
            abort();
        }

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
        }
        IPv6Socket=new DnsSocket(fd);
    }
    return true;
}

void Dns::parseEvent(const epoll_event &event,const DnsSocket *socket)
{
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
    if(event.events & EPOLLIN)
    {
        int size = 0;
        do
        {
            #ifdef DEBUGFASTCGI
            Http::checkIngrityHttpClient();
            #endif
            char buffer[1500];
            sockaddr_in6 si_other6;
            sockaddr_in si_other4;
            if(socket==IPv6Socket)
            {
                unsigned int slen = sizeof(si_other6);
                memset(&si_other6,0,sizeof(si_other6));
                size = recvfrom(socket->getFD(), buffer, sizeof(buffer), 0, (struct sockaddr *) &si_other6, &slen);
                if(size<0)
                    break;
            }
            else if(socket==IPv4Socket)
            {
                unsigned int slen = sizeof(si_other4);
                memset(&si_other4,0,sizeof(si_other4));
                size = recvfrom(socket->getFD(), buffer, sizeof(buffer), 0, (struct sockaddr *) &si_other4, &slen);
                if(size<0)
                    break;
            }
            else
            {
                std::cerr << "Dns::parseEvent() unknown socket" << std::endl;
                return;
            }

            int pos=0;
            uint16_t transactionId=0;
            if(!read16BitsRaw(transactionId,buffer,size,pos))
                return;
            #ifdef DEBUGDNS
            std::cerr << __FILE__ << ":" << __LINE__ << " dns reply for " << transactionId << std::endl;
            #endif
            uint16_t flags=0;
            if(!read16Bits(flags,buffer,size,pos))
                return;
            uint16_t questions=0;
            if(!read16Bits(questions,buffer,size,pos))
                return;
            uint16_t answersIndex=0;
            uint16_t answers=0;
            if(!read16Bits(answers,buffer,size,pos))
                return;
            if(!canAddToPos(2+2,size,pos))
                return;

            //skip query
            uint8_t len,offs=0;
            while((offs<(size-pos)) && (len = buffer[pos+offs]))
                offs += len+1;
            pos+=offs+1;
            uint16_t type=0;
            if(!read16Bits(type,buffer,size,pos))
                return;
            if(type!=0x001c)
                return;
            uint16_t classIn=0;
            if(!read16Bits(classIn,buffer,size,pos))
                return;
            if(classIn!=0x0001)
                return;

            #ifdef DEBUGDNS
            checkCorruption();
            #endif
            #ifdef DEBUGFASTCGI
            Http::checkIngrityHttpClient();
            #endif
            //answers list
            if(queryList.find(transactionId)!=queryList.cend())
            {
                const Query &q=queryList.at(transactionId);

                #ifdef DEBUGFASTCGI
                Http::checkIngrityHttpClient();
                #endif

                if(socket==IPv6Socket)
                {
                    unsigned int index=0;
                    while(index<dnsServerList.size())
                    {
                        const DnsServerEntry &dnsServer=dnsServerList.at(index);
                        if(dnsServer.mode==Mode_IPv6 && memcmp(&dnsServer.targetDnsIPv6.sin6_addr,&si_other6.sin6_addr,16)==0)
                            break;
                        index++;
                    }
                    if(index>=dnsServerList.size())
                    {
                        #ifdef DEBUGDNS
                        char str2[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &si_other6.sin6_addr, str2, INET6_ADDRSTRLEN);
                        std::cerr << str2 << " unknow source for " << transactionId << " " << std::to_string(q.retryTime) << "%" << dnsServerList.size() << std::endl;
                        #endif
                        return;
                    }
                }
                else
                {
                    unsigned int index=0;
                    while(index<dnsServerList.size())
                    {
                        const DnsServerEntry &dnsServer=dnsServerList.at(index);
                        if(dnsServer.mode==Mode_IPv4 && memcmp(&dnsServer.targetDnsIPv4.sin_addr,&si_other4.sin_addr,4)==0)
                            break;
                        index++;
                    }
                    if(index>=dnsServerList.size())
                    {
                        #ifdef DEBUGDNS
                        char str2[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &si_other4.sin_addr, str2, INET_ADDRSTRLEN);
                        std::cerr << str2 << " unknow source for " << transactionId << " " << std::to_string(q.retryTime) << "%" << dnsServerList.size() << std::endl;
                        #endif
                        return;
                    }
                }
                if(httpInProgress>0)
                    httpInProgress--;
                #ifdef DEBUGDNS
                checkCorruption();
                #endif

                #ifdef DEBUGDNS
                std::cerr << __FILE__ << ":" << __LINE__ << " dns reply for " << q.host << std::endl;
                #endif
                #ifdef DEBUGFASTCGI
                Http::checkIngrityHttpClient();
                #endif
                const std::vector<Http *> &http=q.http;
                const std::vector<Http *> &https=q.https;
                //std::string hostcpp(std::string hostcpp(q.host));-> not needed
                if(!http.empty() || !https.empty())
                {
                    bool clientsFlushed=false;

                    if((flags & 0x000F)==0x0001)
                    {
                        #ifdef DEBUGFASTCGI
                        Http::checkIngrityHttpClient();
                        #endif
                        if(!clientsFlushed)
                        {
                            clientsFlushed=true;
                            //addCacheEntry(StatusEntry_Wrong,0,q.host);-> wrong string to resolve, host is not dns valid
                            bool cacheFound=false;
                            if(cacheAAAA.find(q.host)!=cacheAAAA.cend())
                            {
                                CacheAAAAEntry &entry=cacheAAAA.at(q.host);
                                uint64_t t=time(NULL);
                                const uint64_t &maxTime=t+24*3600;
                                //fix time drift
                                if(entry.outdated_date>maxTime)
                                    entry.outdated_date=maxTime;

                                #ifdef DEBUGDNS
                                const std::string &host=q.host;
                                char str[INET6_ADDRSTRLEN];
                                inet_ntop(AF_INET6, &targetHttps.sin6_addr, str, INET6_ADDRSTRLEN);
                                if(host=="www.confiared.com" && std::string(str)!="2803:1920::3:72")
                                {
                                    std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                                    abort();
                                }
                                if(host=="ventun.com" && std::string(str)!="2803:1920::4:a45")
                                {
                                    std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                                    abort();
                                }
                                if(host=="ultracopier.herman-brule.com" && std::string(str)!="2803:1920::3:f201")
                                {
                                    std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                                    abort();
                                }
                                if(host=="orilla-ecositio-bolivia.com" && std::string(str)!="2803:1920::4:ae5")
                                {
                                    std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                                    abort();
                                }
                                if(host=="www.redestelbolivia.com" && std::string(str)!="2803:1920::4:a6c")
                                {
                                    std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                                    abort();
                                }
                                #endif

                                if(entry.status==StatusEntry_Right)
                                {
                                    if(!https.empty())
                                    {
                                        memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                                        for(Http * const c : https)
                                            c->dnsRight(targetHttps);
                                    }
                                    if(!http.empty())
                                    {
                                        memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                                        for(Http * const c : http)
                                            c->dnsRight(targetHttp);
                                    }
                                    cacheFound=true;
                                }
                            }
                            if(cacheFound==false)
                            {
                                for(Http * const c : http)
                                    c->dnsError();
                                for(Http * const c : https)
                                    c->dnsError();
                            }
                            #ifdef DEBUGDNS
                            std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to  wrong string to resolve, host is not dns valid: " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                            #endif
                            removeQuery(transactionId);
                            #ifdef DEBUGDNS
                            checkCorruption();
                            #endif
                        }
                    }
                    else if((flags & 0xFA0F)!=0x8000)
                    {
                        #ifdef DEBUGFASTCGI
                        Http::checkIngrityHttpClient();
                        #endif
                        if(!clientsFlushed)
                        {
                            clientsFlushed=true;
                            bool cacheFound=false;
                            if(cacheAAAA.find(q.host)!=cacheAAAA.cend())
                            {
                                CacheAAAAEntry &entry=cacheAAAA.at(q.host);
                                uint64_t t=time(NULL);
                                const uint64_t &maxTime=t+24*3600;
                                //fix time drift
                                if(entry.outdated_date>maxTime)
                                    entry.outdated_date=maxTime;
                                if(entry.status==StatusEntry_Right)
                                {
                                    if(!https.empty())
                                    {
                                        memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                                        for(Http * const c : https)
                                            c->dnsRight(targetHttps);
                                    }
                                    if(!http.empty())
                                    {
                                        memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                                        for(Http * const c : http)
                                            c->dnsRight(targetHttp);
                                    }
                                    cacheFound=true;
                                }
                            }
                            if(cacheFound==false)
                            {
                                addCacheEntryFailed(StatusEntry_Wrong,300,q.host);
                                for(Http * const c : http)
                                    c->dnsError();
                                for(Http * const c : https)
                                    c->dnsError();
                            }
                            #ifdef DEBUGDNS
                            std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to (flags & 0xFA0F)!=0x8000: " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                            #endif
                            removeQuery(transactionId);
                            #ifdef DEBUGDNS
                            checkCorruption();
                            #endif
                        }
                        #ifdef DEBUGFASTCGI
                        Http::checkIngrityHttpClient();
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGFASTCGI
                        Http::checkIngrityHttpClient();
                        #endif
                        while(answersIndex<answers)
                        {
                            uint16_t AName=0;
                            if(!read16Bits(AName,buffer,size,pos))
                            {
                                #ifdef DEBUGDNS
                                std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read AName: " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                                #endif
                                return;
                            }
                            uint16_t type=0;
                            if(!read16Bits(type,buffer,size,pos))
                                if(!clientsFlushed)
                                {
                                    clientsFlushed=true;
                                    bool cacheFound=false;
                                    if(cacheAAAA.find(q.host)!=cacheAAAA.cend())
                                    {
                                        CacheAAAAEntry &entry=cacheAAAA.at(q.host);
                                        uint64_t t=time(NULL);
                                        const uint64_t &maxTime=t+24*3600;
                                        //fix time drift
                                        if(entry.outdated_date>maxTime)
                                            entry.outdated_date=maxTime;
                                        if(entry.status==StatusEntry_Right)
                                        {
                                            if(!https.empty())
                                            {
                                                memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                                                for(Http * const c : https)
                                                    c->dnsRight(targetHttps);
                                            }
                                            if(!http.empty())
                                            {
                                                memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                                                for(Http * const c : http)
                                                    c->dnsRight(targetHttp);
                                            }
                                            cacheFound=true;
                                        }
                                    }
                                    if(cacheFound==false)
                                    {
                                        addCacheEntryFailed(StatusEntry_Error,300,q.host);
                                        for(Http * const c : http)
                                            c->dnsError();
                                        for(Http * const c : https)
                                            c->dnsError();
                                    }
                                    #ifdef DEBUGDNS
                                    std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read type: " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                                    #endif
                                    removeQuery(transactionId);
                                    #ifdef DEBUGDNS
                                    checkCorruption();
                                    #endif
                                }
                            #ifdef DEBUGFASTCGI
                            Http::checkIngrityHttpClient();
                            #endif
                            switch(type)
                            {
                                //AAAA
                                case 0x001c:
                                {
                                    uint16_t classIn=0;
                                    if(!read16Bits(classIn,buffer,size,pos))
                                    {
                                        #ifdef DEBUGDNS
                                        std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read classIn: " << transactionId << std::endl;
                                        #endif
                                        return;
                                    }
                                    if(classIn!=0x0001)
                                    {
                                        #ifdef DEBUGDNS
                                        std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to classIn!=0x0001: " << transactionId << std::endl;
                                        #endif
                                        break;
                                    }
                                    uint32_t ttl=0;
                                    if(!read32Bits(ttl,buffer,size,pos))
                                    {
                                        #ifdef DEBUGDNS
                                        std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read ttl: " << transactionId << std::endl;
                                        #endif
                                        return;
                                    }
                                    uint16_t datasize=0;
                                    if(!read16Bits(datasize,buffer,size,pos))
                                    {
                                        #ifdef DEBUGDNS
                                        std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read datasize: " << transactionId << std::endl;
                                        #endif
                                        return;
                                    }
                                    if(datasize!=16)
                                    {
                                        #ifdef DEBUGDNS
                                        std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read datasize!=16: " << transactionId << std::endl;
                                        #endif
                                        return;
                                    }
                                    #ifdef DEBUGFASTCGI
                                    Http::checkIngrityHttpClient();
                                    #endif

                                    //TODO saveToCache();
                                    if(memcmp(buffer+pos,Dns::include,sizeof(Dns::include))!=0 || memcmp(buffer+pos,Dns::exclude,sizeof(Dns::exclude))==0)
                                    {
                                        if(!clientsFlushed)
                                        {
                                            clientsFlushed=true;
                                            addCacheEntry(StatusEntry_Wrong,ttl,q.host,*reinterpret_cast<in6_addr *>(buffer+pos));
                                            for(Http * const c : http)
                                                c->dnsWrong();
                                            for(Http * const c : https)
                                                c->dnsWrong();
                                            #ifdef DEBUGDNS
                                            std::cerr << __FILE__ << ":" << __LINE__ << " wrong ip, dns done: " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                                            #endif
                                            removeQuery(transactionId);
                                            #ifdef DEBUGDNS
                                            checkCorruption();
                                            #endif
                                        }
                                    }
                                    else
                                    {
                                        if(!clientsFlushed)
                                        {
                                            clientsFlushed=true;
                                            addCacheEntry(StatusEntry_Right,ttl,q.host,*reinterpret_cast<in6_addr *>(buffer+pos));
                                            #ifdef DEBUGFASTCGI
                                            Http::checkIngrityHttpClient();
                                            #endif

                                            if(!http.empty())
                                            {
                                                memcpy(&targetHttp.sin6_addr,buffer+pos,16);
                                                for(Http * const c : http)
                                                {
                                                    #ifdef DEBUGDNS
                                                    std::cerr << __FILE__ << ":" << __LINE__ << " dns right http: " << c << std::endl;
                                                    #endif
                                                    c->dnsRight(targetHttp);
                                                    #ifdef DEBUGFASTCGI
                                                    Http::checkIngrityHttpClient();
                                                    if(c->get_status()!=Http::Status_WaitTheContent)
                                                    {
                                                        std::cerr << __FILE__ << ":" << __LINE__ << " incorrect post status for " << c << std::endl;
                                                        abort();
                                                    }
                                                    #endif
                                                }
                                                #ifdef DEBUGFASTCGI
                                                Http::checkIngrityHttpClient();
                                                #endif
                                            }
                                            #ifdef DEBUGFASTCGI
                                            Http::checkIngrityHttpClient();
                                            #endif
                                            if(!https.empty())
                                            {
                                                memcpy(&targetHttps.sin6_addr,buffer+pos,16);
                                                for(Http * const c : https)
                                                {
                                                    #ifdef DEBUGDNS
                                                    std::cerr << __FILE__ << ":" << __LINE__ << " dns right https: " << c << std::endl;
                                                    #endif
                                                    c->dnsRight(targetHttps);
                                                    #ifdef DEBUGFASTCGI
                                                    Http::checkIngrityHttpClient();
                                                    if(c->get_status()!=Http::Status_WaitTheContent)
                                                    {
                                                        std::cerr << __FILE__ << ":" << __LINE__ << " incorrect post status for " << c << std::endl;
                                                        abort();
                                                    }
                                                    #endif
                                                }
                                                #ifdef DEBUGFASTCGI
                                                Http::checkIngrityHttpClient();
                                                #endif
                                            }
                                            #ifdef DEBUGFASTCGI
                                            Http::checkIngrityHttpClient();
                                            #endif
                                            #ifdef DEBUGDNS
                                            std::cerr << __FILE__ << ":" << __LINE__ << " right ip, dns done: " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                                            #endif
                                            removeQuery(transactionId);
                                            #ifdef DEBUGDNS
                                            checkCorruption();
                                            #endif
                                            #ifdef DEBUGFASTCGI
                                            Http::checkIngrityHttpClient();
                                            #endif
                                        }
                                    }
                                }
                                break;
                                default:
                                {
                                    #ifdef DEBUGDNS
                                    std::cerr << __FILE__ << ":" << __LINE__ << " skip query: " << transactionId << " type " << type << " for " << q.host << std::endl;
                                    #endif
                                    canAddToPos(2+4,size,pos);
                                    uint16_t datasize=0;
                                    if(!read16Bits(datasize,buffer,size,pos))
                                    {
                                        #ifdef DEBUGDNS
                                        std::cerr << __FILE__ << ":" << __LINE__ << " skip query, failed read datasize " << type << std::endl;
                                        #endif
                                        return;
                                    }
                                    canAddToPos(datasize,size,pos);
                                }
                                break;
                            }
                            answersIndex++;
                        }
                        #ifdef DEBUGDNS
                        checkCorruption();
                        #endif
                        if(!clientsFlushed)
                        {
                            clientsFlushed=true;
                            bool cacheFound=false;
                            if(cacheAAAA.find(q.host)!=cacheAAAA.cend())
                            {
                                CacheAAAAEntry &entry=cacheAAAA.at(q.host);
                                uint64_t t=time(NULL);
                                const uint64_t &maxTime=t+24*3600;
                                //fix time drift
                                if(entry.outdated_date>maxTime)
                                    entry.outdated_date=maxTime;
                                if(entry.status==StatusEntry_Right)
                                {
                                    if(!https.empty())
                                    {
                                        memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                                        for(Http * const c : https)
                                            c->dnsRight(targetHttps);
                                    }
                                    if(!http.empty())
                                    {
                                        memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                                        for(Http * const c : http)
                                            c->dnsRight(targetHttp);
                                    }
                                    cacheFound=true;
                                }
                            }
                            if(cacheFound==false)
                            {
                                addCacheEntryFailed(StatusEntry_Error,300,q.host);
                                for(Http * const c : http)
                                    c->dnsError();
                                for(Http * const c : https)
                                    c->dnsError();
                            }
                            #ifdef DEBUGDNS
                            std::cerr << __FILE__ << ":" << __LINE__ << " if(!clientsFlushed): " << transactionId << " into " << (Backend::msFrom1970()-q.startTimeInms) << "ms" << std::endl;
                            #endif
                            removeQuery(transactionId);
                            #ifdef DEBUGDNS
                            checkCorruption();
                            #endif
                        }
                        #ifdef DEBUGDNS
                        checkCorruption();
                        #endif
                    }
                }
            }
        #ifdef DEBUGFASTCGI
        Http::checkIngrityHttpClient();
        #endif
        } while(size>=0);
    }
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
}

void Dns::cleanCache()
{
    if(cacheAAAA.size()<100000)
        return;
    const std::map<uint64_t/*outdated_date in s from 1970*/,std::vector<std::string>> cacheByOutdatedDate=this->cacheAAAAByOutdatedDate;
    for (auto const& x : cacheByOutdatedDate)
    {
        const uint64_t t=x.first;
        if(t>(uint64_t)time(NULL))
            return;
        const std::vector<std::string> &list=x.second;
        for (auto const& host : list)
            cacheAAAA.erase(host);
        this->cacheAAAAByOutdatedDate.erase(t);
        if(cacheAAAA.size()<100000)
            return;
    }
}

void Dns::addCacheEntryFailed(const StatusEntry &s,const uint32_t &ttl,const std::string &host)
{
    #ifdef DEBUGDNS
    if(s==StatusEntry_Right)
    {
        std::cerr << "Can't call right without IP" << std::endl;
        abort();
    }
    #endif
    if(ttl<600)//always retry after 10min max
        addCacheEntry(s,ttl,host,sin6_addr);
    else
        addCacheEntry(s,600,host,sin6_addr);
}

void Dns::addCacheEntry(const StatusEntry &s,const uint32_t &ttl,const std::string &host,const in6_addr &sin6_addr)
{
    #ifdef DEBUGDNS
    //return;
    #endif
    //prevent DDOS due to out of memory situation
    if(cacheAAAA.size()>120000)
        return;

    //remove old entry from cacheByOutdatedDate
    if(cacheAAAA.find(host)!=cacheAAAA.cend())
    {
        const CacheAAAAEntry &e=cacheAAAA.at(host);
        std::vector<std::string> &list=cacheAAAAByOutdatedDate[e.outdated_date];
        for (size_t i = 0; i < list.size(); i++) {
            const std::string &s=list.at(i);
            if(s==host)
            {
                list.erase(list.cbegin()+i);
                break;
            }
        }
    }

    CacheAAAAEntry &entry=cacheAAAA[host];
    // normal case: check time minimum each 5min, maximum 24h
    if(s==StatusEntry_Right)
    {
        #ifdef LOWTIMEDNSCACHE
        if(ttl<5)
            entry.outdated_date=time(NULL)+5/CACHETIMEDIVIDER;
        else if(ttl<10)
            entry.outdated_date=time(NULL)+ttl/CACHETIMEDIVIDER;
        else
            entry.outdated_date=time(NULL)+10/CACHETIMEDIVIDER;
        #else
        if(ttl<5*60)
            entry.outdated_date=time(NULL)+5*60/CACHETIMEDIVIDER;
        else if(ttl<24*3600)
            entry.outdated_date=time(NULL)+ttl/CACHETIMEDIVIDER;
        else
            entry.outdated_date=time(NULL)+24*3600/CACHETIMEDIVIDER;
        #endif
    }
    else // error case: check time minimum each 10s, maximum 10min
    {
        #ifdef LOWTIMEDNSCACHE
        if(ttl<5)
            entry.outdated_date=time(NULL)+5/CACHETIMEDIVIDER;
        else if(ttl<10)
            entry.outdated_date=time(NULL)+ttl/CACHETIMEDIVIDER;
        else
            entry.outdated_date=time(NULL)+10/CACHETIMEDIVIDER;
        #else
        if(ttl<10)
            entry.outdated_date=time(NULL)+10/CACHETIMEDIVIDER;
        else if(ttl<600)
            entry.outdated_date=time(NULL)+ttl/CACHETIMEDIVIDER;
        else
            entry.outdated_date=time(NULL)+600/CACHETIMEDIVIDER;
        #endif
    }
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " insert into cache " << host << " " << (int64_t)entry.outdated_date << std::endl;
    #endif
    entry.status=s;

    #ifdef DEBUGDNS
    if(s==StatusEntry_Right)
    {
        char astring[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(sin6_addr), astring, INET6_ADDRSTRLEN);
        if(std::string(astring)=="::")
        {
            std::cerr << "Internal error, try connect on ::" << std::endl;
            abort();
        }
    }
    #endif

    memcpy(&entry.sin6_addr,&sin6_addr,sizeof(in6_addr));

    //insert entry to cacheByOutdatedDate
    cacheAAAAByOutdatedDate[entry.outdated_date].push_back(host);
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
}

bool Dns::canAddToPos(const int &i, const int &size, int &pos)
{
    if((pos+i)>size)
        return false;
    pos+=i;
    return true;
}

bool Dns::read8Bits(uint8_t &var, const char * const data, const int &size, int &pos)
{
    if((pos+(int)sizeof(var))>size)
        return false;
    var=data[pos];
    pos+=sizeof(var);
    return true;
}

bool Dns::read16Bits(uint16_t &var, const char * const data, const int &size, int &pos)
{
    uint16_t t=0;
    read16BitsRaw(t,data,size,pos);
    var=be16toh(t);
    return var;
}

bool Dns::read16BitsRaw(uint16_t &var, const char * const data, const int &size, int &pos)
{
    if((pos+(int)sizeof(var))>size)
        return false;
    memcpy(&var,data+pos,sizeof(var));
    pos+=sizeof(var);
    return true;
}

bool Dns::read32Bits(uint32_t &var, const char * const data, const int &size, int &pos)
{
    if((pos+(int)sizeof(var))>size)
        return false;
    uint32_t t;
    memcpy(&t,data+pos,sizeof(var));
    var=be32toh(t);
    pos+=sizeof(var);
    return true;
}

bool Dns::getAAAA(Http * client, const std::string &host, const bool &https)
{
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    if(dnsServerList.empty())
    {
        std::cerr << "Sorry but the server list is empty" << std::endl;
        abort();
    }
    if(client==nullptr)
    {
        std::cerr << __FILE__ << ":" << __LINE__ << " Dns::get() client==nullptr" << std::endl;
        abort();
    }
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " " << (int64_t)time(NULL) << " https: " << https << " client: " << client << std::endl;
    if(host=="www.bolivia-online.com" || host=="bolivia-online.com")
    {
        std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
        char ipv6[]={0x28,0x03,0x19,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x10};
        memcpy(&targetHttp.sin6_addr,&ipv6,16);
        client->dnsRight(targetHttp);
        return true;
    }
    #endif
    bool forceCache=false;
    if(queryListByHost.find(host)!=queryListByHost.cend())
    {
        const uint16_t &queryId=queryListByHost.at(host);
        if(queryList.find(queryId)!=queryList.cend())
        {
            Query &q=queryList[queryId];
            if(q.host==host)
            {
                if(q.retryTime>=Dns::retryBeforeError() && cacheAAAA.find(host)!=cacheAAAA.cend())
                    forceCache=true;
                else
                {
                    if(https)
                    {
                        q.https.push_back(client);
                        #ifdef DEBUGDNS
                        std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " add " << client << " to query " << queryId << " (" << q.nextRetry << ") for https" << std::endl;
                        #endif
                    }
                    else
                    {
                        q.http.push_back(client);
                        #ifdef DEBUGDNS
                        std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " add " << client << " to query " << queryId << " (" << q.nextRetry << ") for http" << std::endl;
                        #endif
                    }
                    return true;
                }
            }
            else
            {
                #ifdef DEBUGDNS
                std::cerr << __FILE__ << ":" << __LINE__ << " corrupted index: queryListByHost.find(): " << host << " queryId: " << queryId << " Query: " << q.host << " " << q.nextRetry << " " << q.retryTime << std::endl;
                #endif
                queryListByHost.erase(host);
            }
        }
        else //bug, try fix
        {
            #ifdef DEBUGDNS
            std::cerr << __FILE__ << ":" << __LINE__ << " found: " << host << " but " << queryId <<  " not found, warning" << std::endl;
            #endif
            queryListByHost.erase(host);
        }
    }
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " is not into pending query, then search in cache" << std::endl;
    #endif
    #ifdef DEBUGDNS
    checkCorruptionCache();
    #endif
    if(cacheAAAA.find(host)!=cacheAAAA.cend())
    {
        #ifdef DEBUGDNS
        checkCorruptionCache();
        #endif
        CacheAAAAEntry &entry=cacheAAAA.at(host);
        #ifdef DEBUGDNS
        checkCorruptionCache();
        #endif
        uint64_t t=time(NULL);
        if(entry.outdated_date>t || forceCache)
        {
            #ifdef DEBUGDNS
            checkCorruptionCache();
            #endif
            const uint64_t &maxTime=t+24*3600;
            //fix time drift
            if(entry.outdated_date>maxTime)
                entry.outdated_date=maxTime;
            switch(entry.status)
            {
                case StatusEntry_Right:
                    if(https)
                    {
                        #ifdef DEBUGDNS
                        checkCorruptionCache();
                        #endif
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << __FILE__ << ":" << __LINE__ << " have in https cache: " << host << "->" << str << std::endl;
                        #endif
                        memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                        client->dnsRight(targetHttps);
                        #ifdef DEBUGDNS
                        checkCorruptionCache();
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGDNS
                        checkCorruptionCache();
                        #endif
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << __FILE__ << ":" << __LINE__ << " have in http cache: " << host << "->" << str << std::endl;
                        #endif
                        memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                        client->dnsRight(targetHttp);
                        #ifdef DEBUGDNS
                        checkCorruptionCache();
                        #endif
                    }
                break;
                default:
                case StatusEntry_Error:
                    #ifdef DEBUGDNS
                    std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    #ifdef DEBUGDNS
                    checkCorruptionCache();
                    #endif
                    client->dnsError();
                    #ifdef DEBUGDNS
                    checkCorruptionCache();
                    #endif
                break;
                case StatusEntry_Wrong:
                {
                    #ifdef DEBUGDNS
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                    std::cerr << __FILE__ << ":" << __LINE__ << " is wrong in cache: " << host << "->" << str << std::endl;
                    #endif
                    #ifdef DEBUGDNS
                    checkCorruptionCache();
                    #endif
                    client->dnsWrong();
                    #ifdef DEBUGDNS
                    checkCorruptionCache();
                    #endif
                }
                break;
                case StatusEntry_Timeout:
                {
                    #ifdef DEBUGDNS
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                    std::cerr << __FILE__ << ":" << __LINE__ << " is timeout (" << (entry.outdated_date-t) << "s) in cache: " << host << "->" << str << std::endl;
                    #endif
                    #ifdef DEBUGDNS
                    checkCorruptionCache();
                    #endif
                    client->dnsWrong();
                    #ifdef DEBUGDNS
                    checkCorruptionCache();
                    #endif
                }
                break;
            }
            return true;
        }
        #ifdef DEBUGDNS
        else
            std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " entry.outdated_date<=t: " << entry.outdated_date << ">" << (int64_t)time(NULL) << std::endl;
        #endif
    }
    #ifdef DEBUGDNS
    checkCorruptionCache();
    #endif
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " is not in cache, send new query" << std::endl;
    #endif
    if(httpInProgress>1000)
    {
        #ifdef DEBUGDNS
        std::cerr << "overloaded, httpInProgress " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        return false;
    }
    /* TODO if(isInCache())
    {load from cache}*/
    //std::cout << "dns query count merged in progress>1000" << std::endl;
    uint8_t buffer[4096];
    struct dns_query* query = (struct dns_query*)buffer;
    query->id=increment++;
    if(increment>65534)
        increment=1;
    query->flags=htobe16(288);
    query->question_count=htobe16(1);
    query->answer_count=0;
    query->authority_count=0;
    query->add_count=0;
    int pos=2+2+2+2+2+2;

    //hostname encoded
    int hostprevpos=0;
    size_t hostpos=host.find(".",hostprevpos);
    while(hostpos!=std::string::npos)
    {
        const std::string &part=host.substr(hostprevpos,hostpos-hostprevpos);
        //std::cout << part << std::endl;
        buffer[pos]=part.size();
        pos+=1;
        memcpy(buffer+pos,part.data(),part.size());
        pos+=part.size();
        hostprevpos=hostpos+1;
        hostpos=host.find(".",hostprevpos);
    }
    const std::string &part=host.substr(hostprevpos);
    //std::cout << part << std::endl;
    buffer[pos]=part.size();
    pos+=1;
    memcpy(buffer+pos,part.data(),part.size());
    pos+=part.size();

    buffer[pos]=0x00;
    pos+=1;

    //type AAAA
    buffer[pos]=0x00;
    pos+=1;
    buffer[pos]=0x1c;
    pos+=1;

    //class IN
    buffer[pos]=0x00;
    pos+=1;
    buffer[pos]=0x01;
    pos+=1;

    Query queryToPush;
    queryToPush.host=host;
    #ifdef DEBUGDNS
    if(host=="opwsernfvdhdnqaz-timeoutdns.com")
        queryToPush.retryTime=100;
    else
        queryToPush.retryTime=0;
    #else
    queryToPush.retryTime=0;
    #endif
    queryToPush.startTimeInms=Backend::msFrom1970();
    queryToPush.nextRetry=Backend::msFrom1970()+resendQueryDNS_ms();
    queryToPush.query=std::string((char *)buffer,pos);

    bool sendOk=false;
    unsigned int serverDNSindex=0;
    while(serverDNSindex<dnsServerList.size())
    {
        #ifdef DEBUGDNS
        if(host=="opwsernfvdhdnqaz-timeoutdns.com")
            break;
        #endif

        const DnsServerEntry &dnsServer=dnsServerList.at(serverDNSindex);
        if(dnsServer.mode==Mode_IPv6)
        {
            const int result = sendto(IPv6Socket->getFD(),&buffer,pos,0,(struct sockaddr*)&dnsServer.targetDnsIPv6,sizeof(dnsServer.targetDnsIPv6));
            if(result!=pos)
            {
                #ifdef DEBUGDNS
                char str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                std::cerr << "sendto Mode_IPv6 failed: " << str << " to resolv: " << host << " queryToPush.serverOrder[]: " << std::to_string(serverDNSindex) << " queryToPush.retryTime: " << std::to_string(queryToPush.retryTime) << std::endl;
                #endif
            }
            else
            {
                #ifdef DEBUGDNS
                char str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                std::cerr << "sendto Mode_IPv6 ok: " << str << " to resolv: " << host << " queryToPush.serverOrder[]: " << std::to_string(serverDNSindex) << " queryToPush.retryTime: " << std::to_string(queryToPush.retryTime) << std::endl;
                #endif
                sendOk=true;
            }
        }
        else //if(mode==Mode_IPv4)
        {
            const int result = sendto(IPv4Socket->getFD(),&buffer,pos,0,(struct sockaddr*)&dnsServer.targetDnsIPv4,sizeof(dnsServer.targetDnsIPv4));
            if(result!=pos)
            {
                #ifdef DEBUGDNS
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &dnsServer.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                std::cerr << "sendto Mode_IPv4 failed: " << str << " to resolv: " << host << " queryToPush.serverOrder[]: " << std::to_string(serverDNSindex) << " queryToPush.retryTime: " << std::to_string(queryToPush.retryTime) << std::endl;
                #endif
            }
            else
            {
                #ifdef DEBUGDNS
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &dnsServer.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                std::cerr << "sendto Mode_IPv4 ok: " << str << " to resolv: " << host << " queryToPush.serverOrder[]: " << std::to_string(serverDNSindex) << " queryToPush.retryTime: " << std::to_string(queryToPush.retryTime) << std::endl;
                #endif
                sendOk=true;
            }
        }

        serverDNSindex++;
    }
    if(!sendOk)
    {
        bool cacheFound=false;
        if(cacheAAAA.find(host)!=cacheAAAA.cend())
        {
            CacheAAAAEntry &entry=cacheAAAA[host];
            uint64_t t=time(NULL);
            const uint64_t &maxTime=t+24*3600;
            //fix time drift
            if(entry.outdated_date>maxTime)
                entry.outdated_date=maxTime;
            if(entry.status==StatusEntry_Right)
            {
                if(https)
                {
                    memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                    client->dnsRight(targetHttps);
                }
                else
                {
                    memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                    client->dnsRight(targetHttp);
                }
                return true;
            }
        }
        if(cacheFound==false)
        {
            client->dnsError();
            addCacheEntryFailed(StatusEntry_Timeout,30,host);
            return false;
        }
    }

    if(https)
        queryToPush.https.push_back(client);
    else
        queryToPush.http.push_back(client);
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " dns query send " << std::to_string(query->id) << " client: " << client << std::endl;
    #endif
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    addQuery(query->id,queryToPush);
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    return true;
}

void Dns::addQuery(const uint16_t &id, const Query &query)
{
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " dns query send Dns::addQuery(): " << std::to_string(id) << " query.nextRetry: " << query.nextRetry << " current time: " << Backend::msFrom1970() << std::endl;
    #endif
    queryList[id]=query;
    queryListByHost[query.host]=id;
    queryByNextDueTime[query.nextRetry].push_back(id);
    if(httpInProgress<2000000000)
        httpInProgress++;
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
}

void Dns::removeQuery(const uint16_t &id, const bool &withNextDueTime)
{
    const Query &query=queryList.at(id);
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " query " << id << " finish into " << (Backend::msFrom1970()-query.startTimeInms) << "ms" << std::endl;
    #endif
    if(withNextDueTime)
    {
        if(queryByNextDueTime.find(query.nextRetry)==queryByNextDueTime.cend())
            std::cerr << __FILE__ << ":" << __LINE__ << " query " << id << " not found into queryByNextDueTime: " << query.nextRetry << std::endl;
        queryByNextDueTime.erase(query.nextRetry);
    }
    if(queryByNextDueTime.find(query.nextRetry)==queryByNextDueTime.cend())
        std::cerr << __FILE__ << ":" << __LINE__ << " query " << id << " not found into queryListByHost: " << query.host << std::endl;
    queryListByHost.erase(query.host);
    if(queryByNextDueTime.find(query.nextRetry)==queryByNextDueTime.cend())
        std::cerr << __FILE__ << ":" << __LINE__ << " query " << id << " not found into queryList" << std::endl;
    queryList.erase(id);
    if(httpInProgress>0)
        httpInProgress--;
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
}

void Dns::cancelClient(Http * client, const std::string &host,const bool &https)
{
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " cancelClient(" << client << "," << host << "," << https << ")" << std::endl;
    #endif
    if(queryListByHost.find(host)!=queryListByHost.cend())
    {
        const uint16_t queryId=queryListByHost.at(host);
        if(queryList.find(queryId)!=queryList.cend())
        {
            if(https)
            {
                std::vector<Http *> &httpsList=queryList[queryId].https;
                unsigned int index=0;
                while(index<httpsList.size())
                {
                    if(client==httpsList.at(index))
                    {
                        httpsList.erase(httpsList.cbegin()+index);
                        break;
                    }
                    index++;
                }
                #ifdef DEBUGDNS
                if(index>=httpsList.size())
                    std::cerr << __FILE__ << ":" << __LINE__ << " try remove: " << client << " to \"" << host << "\" but not found WARNING https" << std::endl;
                #endif
            }
            else
            {
                std::vector<Http *> &httpList=queryList[queryId].http;
                unsigned int index=0;
                while(index<httpList.size())
                {
                    if(client==httpList.at(index))
                    {
                        httpList.erase(httpList.cbegin()+index);
                        break;
                    }
                    index++;
                }
                #ifdef DEBUGDNS
                if(index>=httpList.size())
                    std::cerr << __FILE__ << ":" << __LINE__ << " try remove: " << client << " to \"" << host << "\" but not found WARNING http" << std::endl;
                #endif
            }
            return;
        }
        else
        {
            //bug, try fix
            queryListByHost.erase(host);

            std::cerr << __FILE__ << ":" << __LINE__ << " try remove: " << client << " to \"" << host << "\" but queryListByHost seam wrong" << std::endl;
            abort();
        }
    }
    else
    {
        #ifdef DEBUGDNS
        std::cerr << __FILE__ << ":" << __LINE__ << " try remove: \"" << host << "\" but not found WARNING (queryListByHost.find(host)!=queryListByHost.cend(), client: " << client << std::endl;
        #endif
    }
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
}

#ifdef DEBUGDNS
//very heavy check
bool Dns::queryHaveThisClient(Http * client,const std::string &host,const bool &https) const
{
    #ifdef DEBUGDNS
    //std::cerr << __FILE__ << ":" << __LINE__ << " queryHaveThisClient(" << client << "," << host << "," << https << ")" << std::endl;
    #endif
    if(queryListByHost.find(host)!=queryListByHost.cend())
    {
        const uint16_t queryId=queryListByHost.at(host);
        if(queryList.find(queryId)!=queryList.cend())
        {
            if(https)
            {
                const std::vector<Http *> &httpsList=queryList.at(queryId).https;
                unsigned int index=0;
                while(index<httpsList.size())
                {
                    if(client==httpsList.at(index))
                        return true;
                    index++;
                }
                return false;
            }
            else
            {
                const std::vector<Http *> &httpList=queryList.at(queryId).http;
                unsigned int index=0;
                while(index<httpList.size())
                {
                    if(client==httpList.at(index))
                        return true;
                    index++;
                }
                return false;
            }
            return false;
        }
        else
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " try remove: " << client << " to \"" << host << "\" but queryListByHost seam wrong" << std::endl;
            return false;
        }
    }
    return false;
}
#endif

int Dns::requestCountMerged()
{
    return queryListByHost.size();
}

std::string Dns::getQueryList() const
{
    std::string ret;

    ret+="[";
    unsigned int index=0;
    while(index<dnsServerList.size())
    {
        if(index!=0)
            ret+=",";
        if(index<sizeof(preferedServerOrder))
        {
            if(preferedServerOrder[index]<dnsServerList.size())
            {
                const DnsServerEntry &d=dnsServerList.at(preferedServerOrder[index]);
                if(d.mode==Mode_IPv6)
                {
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &d.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                    ret+=str;
                }
                else
                {
                    char str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &d.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                    ret+=str;
                }
            }
            else
                ret+="preferedServerOrder["+std::to_string(index)+"]:"+std::to_string(preferedServerOrder[index])+">="+std::to_string(dnsServerList.size());
        }
        else
            ret+="preferedServerOrder: "+std::to_string(index)+">="+std::to_string(sizeof(preferedServerOrder));
        index++;
    }
    ret+="]\r\n";

    ret+="Dns queries ("+std::to_string(this->queryList.size())+"): "+std::to_string(this->queryList.size())+"\r\n";
    const std::unordered_map<uint16_t,Query> queryByNextDueTime=this->queryList;
    for (auto const &x : queryByNextDueTime)
    {
        ret+=std::to_string(x.first)+") ";
        const Query &q=x.second;
        ret+=q.host;
        if(q.https.size()>0)
        {
            ret+=" (http:";
            unsigned int index=0;
            while(index<q.http.size())
            {
                std::string ret;
                char buffer[32];
                std::snprintf(buffer,sizeof(buffer),"%p",(void *)q.http.at(index));
                ret+=" "+std::string(buffer);
                index++;
            }
            ret+=")";
        }
        if(q.https.size()>0)
        {
            ret+=" (https:";
            unsigned int index=0;
            while(index<q.https.size())
            {
                std::string ret;
                char buffer[32];
                std::snprintf(buffer,sizeof(buffer),"%p",(void *)q.https.at(index));
                ret+=" "+std::string(buffer);
                index++;
            }
            ret+=")";
        }
        ret+=" "+std::to_string(q.nextRetry)+" "+std::to_string(q.retryTime)+" ";
        ret+="[";
        index=0;
        while(index<dnsServerList.size())
        {
            if(index!=0)
                ret+=",";
            const DnsServerEntry &d=dnsServerList.at(index);
            if(d.mode==Mode_IPv6)
            {
                char str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &d.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                ret+=str;
            }
            else
            {
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &d.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                ret+=str;
            }
            index++;
        }
        ret+="]";
        #ifdef DEBUGDNS
        ret+=" "+std::to_string(Backend::msFrom1970()-q.startTimeInms)+"ms";
        #endif
        ret+="\r\n";
    }
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif

    return ret;
}

int Dns::get_httpInProgress() const
{
    if(httpInProgress>0)
        return httpInProgress;
    else
        return 0;
}

uint8_t Dns::serverCount() const
{
    return dnsServerList.size();
}

uint8_t Dns::retryBeforeError() const
{
    return 4;
}

uint8_t Dns::resendQueryDNS_ms() const
{
    return 200;
}

void Dns::checkQueries()
{
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    const std::map<uint64_t,std::vector<uint16_t>> queryByNextDueTime=this->queryByNextDueTime;
    for (auto const &x : queryByNextDueTime)
    {
        const uint64_t t=x.first;
        if(t>Backend::msFrom1970())
            return;
        const std::vector<uint16_t> &list=x.second;
        for (auto const& id : list)
        {
            Query &query=queryList.at(id);

            bool sendOk=false;

            query.retryTime++;
            if(query.retryTime>=Dns::retryBeforeError() && (!query.http.empty() || !query.http.empty()))
            {
                const std::vector<Http *> &http=query.http;
                const std::vector<Http *> &https=query.https;
                bool cacheFound=false;
                if(cacheAAAA.find(query.host)!=cacheAAAA.cend())
                {
                    CacheAAAAEntry &entry=cacheAAAA.at(query.host);
                    uint64_t t=time(NULL);
                    const uint64_t &maxTime=t+24*3600;
                    //fix time drift
                    if(entry.outdated_date>maxTime)
                        entry.outdated_date=maxTime;
                    if(entry.status==StatusEntry_Right)
                    {
                        if(!https.empty())
                        {
                            memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                            for(Http * const c : https)
                                c->dnsRight(targetHttps);
                        }
                        if(!http.empty())
                        {
                            memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                            for(Http * const c : http)
                                c->dnsRight(targetHttp);
                        }
                        cacheFound=true;
                    }
                }
                if(cacheFound==false)
                {

                    for(Http * const c : http)
                        c->dnsError();
                    for(Http * const c : https)
                        c->dnsError();
                    #ifdef DEBUGDNS
                    std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to timeout: " << id << " remain query: " << queryList.size() << std::endl;
                    #endif
                    addCacheEntryFailed(StatusEntry_Timeout,30,query.host);
                }
                query.http.clear();
                query.https.clear();
            }

            unsigned int serverDNSindex=0;
            while(serverDNSindex<dnsServerList.size())
            {
                const DnsServerEntry &dnsServer=dnsServerList.at(serverDNSindex);
                if(dnsServer.mode==Mode_IPv6)
                {
                    const int result = sendto(IPv6Socket->getFD(),query.query.data(),query.query.size(),0,(struct sockaddr*)&dnsServer.targetDnsIPv6,sizeof(dnsServer.targetDnsIPv6));
                    if(result!=(int)query.query.size())
                    {
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv6 reemit failed: " << str << " to resolv: " << query.host << " result: " << result << " errno: " << errno << std::endl;
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv6 reemit ok: " << str << " to resolv: " << query.host << std::endl;
                        #endif
                        sendOk=true;
                    }
                }
                else //if(mode==Mode_IPv4)
                {
                    const int result = sendto(IPv4Socket->getFD(),query.query.data(),query.query.size(),0,(struct sockaddr*)&dnsServer.targetDnsIPv4,sizeof(dnsServer.targetDnsIPv4));
                    if(result!=(int)query.query.size())
                    {
                        #ifdef DEBUGDNS
                        char str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dnsServer.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv4 reemit failed: " << str << " to resolv: " << query.host << " result: " << result << " errno: " << errno << std::endl;
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGDNS
                        char str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dnsServer.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv4 reemit ok: " << str << " to resolv: " << query.host << std::endl;
                        #endif
                        sendOk=true;
                    }
                }
                serverDNSindex++;
            }
            #ifdef DEBUGDNS
            std::cerr << "sendto reemit" << std::endl;
            #endif

            if(query.retryTime>=Dns::retryBeforeError() || !sendOk)
            {
                const std::vector<Http *> &http=query.http;
                const std::vector<Http *> &https=query.https;
                bool cacheFound=false;
                if(cacheAAAA.find(query.host)!=cacheAAAA.cend())
                {
                    CacheAAAAEntry &entry=cacheAAAA.at(query.host);
                    uint64_t t=time(NULL);
                    const uint64_t &maxTime=t+24*3600;
                    //fix time drift
                    if(entry.outdated_date>maxTime)
                        entry.outdated_date=maxTime;
                    if(entry.status==StatusEntry_Right)
                    {
                        if(!https.empty())
                        {
                            memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                            for(Http * const c : https)
                                c->dnsRight(targetHttps);
                        }
                        if(!http.empty())
                        {
                            memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                            for(Http * const c : http)
                                c->dnsRight(targetHttp);
                        }
                        cacheFound=true;
                    }
                }
                if(cacheFound==false)
                {

                    for(Http * const c : http)
                        c->dnsError();
                    for(Http * const c : https)
                        c->dnsError();
                    #ifdef DEBUGDNS
                    std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to timeout: " << id << " remain query: " << queryList.size() << std::endl;
                    #endif
                    addCacheEntryFailed(StatusEntry_Timeout,30,query.host);
                }
                #ifdef DEBUGDNS
                std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to timeout: " << id << " remain query: " << queryList.size() << " into " << (Backend::msFrom1970()-query.startTimeInms) << "ms" << std::endl;
                #endif
                removeQuery(id);
                #ifdef DEBUGFASTCGI
                Http::checkIngrityHttpClient();
                #endif
            }
            else
            {
                query.nextRetry=Backend::msFrom1970()+resendQueryDNS_ms();
                this->queryByNextDueTime[query.nextRetry].push_back(id);
            }

            //query=cache.erase(y);
        }
        this->queryByNextDueTime.erase(t);
        //cacheByOutdatedDate.erase(t);
    }
    #ifdef DEBUGFASTCGI
    Http::checkIngrityHttpClient();
    #endif
    #ifdef DEBUGDNS
    checkCorruption();
    #endif
    for( const auto& n : queryList ) {
        const uint16_t &queryId=n.first;
        Query &query=queryList[queryId];

        if(query.retryTime>=Dns::retryBeforeError())
        {
            const std::vector<Http *> &http=query.http;
            const std::vector<Http *> &https=query.https;
            bool cacheFound=false;
            if(cacheAAAA.find(query.host)!=cacheAAAA.cend())
            {
                CacheAAAAEntry &entry=cacheAAAA.at(query.host);
                uint64_t t=time(NULL);
                const uint64_t &maxTime=t+24*3600;
                //fix time drift
                if(entry.outdated_date>maxTime)
                    entry.outdated_date=maxTime;
                if(entry.status==StatusEntry_Right)
                {
                    if(!https.empty())
                    {
                        memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                        for(Http * const c : https)
                            c->dnsRight(targetHttps);
                    }
                    if(!http.empty())
                    {
                        memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                        for(Http * const c : http)
                            c->dnsRight(targetHttp);
                    }
                    cacheFound=true;
                }
            }
            if(cacheFound==false)
            {

                for(Http * const c : http)
                    c->dnsError();
                for(Http * const c : https)
                    c->dnsError();
                #ifdef DEBUGDNS
                std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to timeout: " << queryId << " remain query: " << queryList.size() << std::endl;
                #endif
                addCacheEntryFailed(StatusEntry_Timeout,30,query.host);
            }
            #ifdef DEBUGDNS
            std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to timeout: " << queryId << " remain query: " << queryList.size() << " into " << (Backend::msFrom1970()-query.startTimeInms) << "ms" << std::endl;
            #endif
            removeQuery(queryId);
            #ifdef DEBUGFASTCGI
            Http::checkIngrityHttpClient();
            #endif
        }
    }
}

#ifdef DEBUGDNS
void Dns::checkCorruption()
{
    std::unordered_set<uint16_t> inHost;
    for( const auto& n : Dns::dns->queryListByHost ) {
        const std::string &host=n.first;
        const uint16_t &queryId=n.second;
        inHost.insert(queryId);
        if(Dns::dns->queryList.find(queryId)!=Dns::dns->queryList.cend())
        {
            const Query &q=Dns::dns->queryList[queryId];
            if(q.host!=host)
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " found: " << host << ", " << queryId <<  " found, but query value: " << q.host << " (abort)" << std::endl;
                abort();
            }
        }
        else
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " found: " << host << " but " << queryId <<  " not found (abort)" << std::endl;
            abort();
        }
    }
    for( const auto& n :Dns::dns-> queryList ) {
        const uint16_t &queryId=n.first;
        const Query &query=Dns::dns->queryList.at(queryId);

        if(inHost.find(queryId)==inHost.cend())
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " queryId: " << queryId <<  " found, but into into host reverse " << query.host << " (abort)" << std::endl;
            abort();
        }
        else if(query.retryTime>Dns::dns->dnsServerList.size()*Dns::dns->retryBeforeError())
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " queryId: " << queryId <<  " time count " << query.retryTime << ">" << Dns::dns->dnsServerList.size()*Dns::dns->retryBeforeError() << " (abort)" << std::endl;
            abort();
        }
    }
    const std::map<uint64_t,std::vector<uint16_t>> queryByNextDueTime=Dns::dns->queryByNextDueTime;
    for (auto const &x : queryByNextDueTime)
    {
        const uint64_t t=x.first;
        const std::vector<uint16_t> &queryIdList=x.second;
        if(t>Backend::msFrom1970()+Dns::dns->dnsServerList.size()*Dns::dns->retryBeforeError()*1000)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " lowest time is out of range: " << t
                      <<  ">" << Backend::msFrom1970() << "+" << Dns::dns->dnsServerList.size()*Dns::dns->retryBeforeError()*1000 << " (abort)" << std::endl;
            abort();
        }
        unsigned int index=0;
        while(index<queryIdList.size())
        {
            const uint16_t &queryId=queryIdList.at(index);
            if(Dns::dns->queryList.find(queryId)==Dns::dns->queryList.cend())
            {
                std::cerr << __FILE__ << ":" << __LINE__ << " queryByNextDueTime: " << queryId <<  " not into real query list " << t << " (abort)" << std::endl;
                abort();
            }
            else
            {
                const Query &query=Dns::dns->queryList.at(queryId);
                if(query.nextRetry!=t)
                {
                    std::cerr << __FILE__ << ":" << __LINE__ << " query.nextRetry!=t: " << query.nextRetry <<  "!=" << t << " (abort)" << std::endl;
                    abort();
                }
            }
            index++;
        }
    }
    checkCorruptionCache();
}

void Dns::checkCorruptionCache()
{
    for (auto const &x : Dns::dns->cacheAAAA)
    {
        const std::string &host=x.first;
        const CacheAAAAEntry &cache=x.second;
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &cache.sin6_addr, str, INET6_ADDRSTRLEN);
        if(Dns::dns->hardcodedDns.find(host)!=Dns::dns->hardcodedDns.cend())
            if(std::string(str)!=Dns::dns->hardcodedDns.at(host))
            {
                std::cerr << host << ": " << str << " corruption detected by hard coded value (abort) " << __FILE__ << ":" << __LINE__ << std::endl;
                abort();
            }
    }
}

#endif
