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

    lastDnsFailed=255;
    {
        int index=0;
        while(index<MAXDNSSERVER)
        {
            preferedServerOrder[index]=index;
            index++;
        }
    }

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
    if(event.events & EPOLLIN)
    {
        int size = 0;
        do
        {
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
            #ifdef DEBUGDNS
            std::cerr << __FILE__ << ":" << __LINE__ << " dns reply" << std::endl;
            #endif

            int pos=0;
            uint16_t transactionId=0;
            if(!read16BitsRaw(transactionId,buffer,size,pos))
                return;
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


            //answers list
            if(queryList.find(transactionId)!=queryList.cend())
            {
                if(httpInProgress>0)
                    httpInProgress--;
                const Query &q=queryList.at(transactionId);
                const DnsServerEntry &dnsServer=dnsServerList.at(q.retryTime%dnsServerList.size());

                if(socket==IPv6Socket)
                {
                    if(dnsServer.mode!=Mode_IPv6)
                    {
                        #ifdef DEBUGDNS
                        std::cerr << "dnsServer.mode!=Mode_IPv6, skip" << std::endl;
                        #endif
                        return;
                    }
                    if(memcmp(&dnsServer.targetDnsIPv6.sin6_addr,&si_other6.sin6_addr,16)!=0)
                    {
                        #ifdef DEBUGDNS
                        std::cerr << "memcmp(&dnsServer.targetDnsIPv6,&si_other6.sin6_addr,16)!=0, skip" << std::endl;
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                        char str2[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &si_other6.sin6_addr, str2, INET6_ADDRSTRLEN);
                        std::cerr << str << "!=" << str2 << std::endl;
                        #endif
                        return;
                    }
                }
                else
                {
                    if(dnsServer.mode!=Mode_IPv4)
                    {
                        #ifdef DEBUGDNS
                        std::cerr << "dnsServer.mode!=Mode_IPv4, skip" << std::endl;
                        #endif
                        return;
                    }
                    if(memcmp(&dnsServer.targetDnsIPv4.sin_addr,&si_other4.sin_addr,4)!=0)
                    {
                        #ifdef DEBUGDNS
                        std::cerr << "memcmp(&dnsServer.targetDnsIPv4.sin_addr,&si_other4.sin_addr,4)!=0, skip" << std::endl;
                        char str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dnsServer.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                        char str2[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &si_other4.sin_addr, str2, INET_ADDRSTRLEN);
                        std::cerr << str << "!=" << str2 << std::endl;
                        #endif
                        return;
                    }
                }

                #ifdef DEBUGDNS
                std::cerr << __FILE__ << ":" << __LINE__ << " dns reply for " << q.host << std::endl;
                #endif
                const std::vector<Http *> &http=q.http;
                const std::vector<Http *> &https=q.https;
                //std::string hostcpp(std::string hostcpp(q.host));-> not needed
                if(!http.empty() || !https.empty())
                {
                    bool clientsFlushed=false;

                    if((flags & 0x000F)==0x0001)
                    {
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
                            std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to  wrong string to resolve, host is not dns valid: " << transactionId << std::endl;
                            #endif
                            removeQuery(transactionId);
                        }
                    }
                    else if((flags & 0xFA0F)!=0x8000)
                    {
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
                            std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to (flags & 0xFA0F)!=0x8000: " << transactionId << std::endl;
                            #endif
                            removeQuery(transactionId);
                        }
                    }
                    else
                    {
                        while(answersIndex<answers)
                        {
                            uint16_t AName=0;
                            if(!read16Bits(AName,buffer,size,pos))
                            {
                                #ifdef DEBUGDNS
                                std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read AName: " << transactionId << std::endl;
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
                                    std::cerr << __FILE__ << ":" << __LINE__ << " remove query due to failed read type: " << transactionId << std::endl;
                                    #endif
                                    removeQuery(transactionId);
                                }
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
                                            std::cerr << __FILE__ << ":" << __LINE__ << " wrong ip, dns done: " << transactionId << std::endl;
                                            #endif
                                            removeQuery(transactionId);
                                        }
                                    }
                                    else
                                    {
                                        if(!clientsFlushed)
                                        {
                                            clientsFlushed=true;
                                            addCacheEntry(StatusEntry_Right,ttl,q.host,*reinterpret_cast<in6_addr *>(buffer+pos));

                                            if(!http.empty())
                                            {
                                                memcpy(&targetHttp.sin6_addr,buffer+pos,16);
                                                for(Http * const c : http)
                                                    c->dnsRight(targetHttp);
                                            }
                                            if(!https.empty())
                                            {
                                                memcpy(&targetHttps.sin6_addr,buffer+pos,16);
                                                for(Http * const c : https)
                                                    c->dnsRight(targetHttps);
                                            }
                                            #ifdef DEBUGDNS
                                            std::cerr << __FILE__ << ":" << __LINE__ << " right ip, dns done: " << transactionId << std::endl;
                                            #endif
                                            removeQuery(transactionId);
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
                            std::cerr << __FILE__ << ":" << __LINE__ << " if(!clientsFlushed): " << transactionId << std::endl;
                            #endif
                            removeQuery(transactionId);
                        }
                    }
                }
            }
        } while(size>=0);
    }
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
        if(ttl<5*60)
            entry.outdated_date=time(NULL)+5*60/CACHETIMEDIVIDER;
        else if(ttl<24*3600)
            entry.outdated_date=time(NULL)+ttl/CACHETIMEDIVIDER;
        else
            entry.outdated_date=time(NULL)+24*3600/CACHETIMEDIVIDER;
    }
    else // error case: check time minimum each 10s, maximum 10min
    {
        if(ttl<10)
            entry.outdated_date=time(NULL)+10/CACHETIMEDIVIDER;
        else if(ttl<600)
            entry.outdated_date=time(NULL)+ttl/CACHETIMEDIVIDER;
        else
            entry.outdated_date=time(NULL)+600/CACHETIMEDIVIDER;
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
    std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " " << (int64_t)time(NULL) << std::endl;
    if(host=="www.bolivia-online.com" || host=="bolivia-online.com")
    {
        std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
        char ipv6[]={0x28,0x03,0x19,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x10};
        memcpy(&targetHttp.sin6_addr,&ipv6,16);
        client->dnsRight(targetHttp);
        return true;
    }
    #endif
    if(queryListByHost.find(host)!=queryListByHost.cend())
    {
        const uint16_t &queryId=queryListByHost.at(host);
        if(queryList.find(queryId)!=queryList.cend())
        {
            if(https)
            {
                queryList[queryId].https.push_back(client);
                #ifdef DEBUGDNS
                {
                    const Query &q=queryList[queryId];
                    std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " add " << client << " to query " << queryId << " (" << q.nextRetry << ") for https" << std::endl;
                }
                #endif
            }
            else
            {
                queryList[queryId].http.push_back(client);
                #ifdef DEBUGDNS
                {
                    const Query &q=queryList[queryId];
                    std::cerr << __FILE__ << ":" << __LINE__ << " try resolv " << host << " add " << client << " to query " << queryId << " (" << q.nextRetry << ") for http" << std::endl;
                }
                #endif
            }
            return true;
        }
        else //bug, try fix
            queryListByHost.erase(host);
    }
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    //#ifndef DEBUGDNS
    if(cacheAAAA.find(host)!=cacheAAAA.cend())
    {
        CacheAAAAEntry &entry=cacheAAAA.at(host);
        uint64_t t=time(NULL);
        if(entry.outdated_date>t)
        {
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
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << __FILE__ << ":" << __LINE__ << " have in https cache: " << host << "->" << str << std::endl;
                        #endif
                        memcpy(&targetHttps.sin6_addr,&entry.sin6_addr,16);
                        client->dnsRight(targetHttps);
                    }
                    else
                    {
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << __FILE__ << ":" << __LINE__ << " have in http cache: " << host << "->" << str << std::endl;
                        #endif
                        memcpy(&targetHttp.sin6_addr,&entry.sin6_addr,16);
                        client->dnsRight(targetHttp);
                    }
                break;
                default:
                case StatusEntry_Error:
                    #ifdef DEBUGDNS
                    std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
                    #endif
                    client->dnsError();
                break;
                case StatusEntry_Wrong:
                {
                    #ifdef DEBUGDNS
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                    std::cerr << __FILE__ << ":" << __LINE__ << " is wrong in cache: " << host << "->" << str << std::endl;
                    #endif
                    client->dnsWrong();
                }
                break;
                case StatusEntry_Timeout:
                {
                    #ifdef DEBUGDNS
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &entry.sin6_addr, str, INET6_ADDRSTRLEN);
                    std::cerr << __FILE__ << ":" << __LINE__ << " is timeout (" << (entry.outdated_date-t) << "s) in cache: " << host << "->" << str << std::endl;
                    #endif
                    client->dnsWrong();
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
    //#endif
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    if(httpInProgress>1000)
    {
        #ifdef DEBUGDNS
        std::cerr << "overloaded, httpInProgress " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        return false;
    }
    httpInProgress++;
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
    queryToPush.nextRetry=time(NULL)+5;
    queryToPush.query=std::string((char *)buffer,pos);
    #ifdef DEBUGDNS
    if(sizeof(preferedServerOrder)!=sizeof(queryToPush.serverOrder))
    {
        std::cerr << "sizeof(preferedServerOrder)!=sizeof(queryToPush.serverOrder) (abort)" << std::endl;
        abort();
    }
    #endif
    memcpy(queryToPush.serverOrder,preferedServerOrder,sizeof(preferedServerOrder));

    const DnsServerEntry &dnsServer=dnsServerList.at(queryToPush.serverOrder[0]);
    if(dnsServer.mode==Mode_IPv6)
    {
        const int result = sendto(IPv6Socket->getFD(),&buffer,pos,0,(struct sockaddr*)&dnsServer.targetDnsIPv6,sizeof(dnsServer.targetDnsIPv6));
        if(result!=pos)
        {
            #ifdef DEBUGDNS
            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
            std::cerr << "sendto Mode_IPv6 failed: " << str << " to resolv: " << host << std::endl;
            #endif
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
            std::cerr << "sendto Mode_IPv4 failed: " << str << " to resolv: " << host << std::endl;
            #endif
        }
    }

    if(https)
        queryToPush.https.push_back(client);
    else
        queryToPush.http.push_back(client);
    #ifdef DEBUGDNS
    std::cerr << __FILE__ << ":" << __LINE__ << " dns query send " << query->id << std::endl;
    #endif
    addQuery(query->id,queryToPush);
    return true;
}

void Dns::addQuery(const uint16_t &id, const Query &query)
{
    queryList[id]=query;
    queryListByHost[query.host]=id;
    queryByNextDueTime[query.nextRetry].push_back(id);
}

void Dns::removeQuery(const uint16_t &id, const bool &withNextDueTime)
{
    const Query &query=queryList.at(id);
    if(withNextDueTime)
        queryByNextDueTime.erase(query.nextRetry);
    queryListByHost.erase(query.host);
    queryList.erase(id);
}

void Dns::cancelClient(Http * client, const std::string &host,const bool &https)
{
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
        else //bug, try fix
            queryListByHost.erase(host);
    }
    else
    {
        #ifdef DEBUGDNS
        std::cerr << __FILE__ << ":" << __LINE__ << " try remove: \"" << host << "\" but not found WARNING (queryListByHost.find(host)!=queryListByHost.cend()" << std::endl;
        #endif
    }
}

int Dns::requestCountMerged()
{
    return queryListByHost.size();
}

std::string Dns::getQueryList() const
{
    std::string ret;
    const std::map<uint64_t,std::vector<uint16_t>> queryByNextDueTime=this->queryByNextDueTime;
    for (auto const &x : queryByNextDueTime)
    {
        if(!ret.empty())
            ret+=",";
        ret+=std::to_string(x.first)+" (";
        std::string retT;
        for (auto const &y : x.second)
        {
            if(!retT.empty())
                retT+=",";
            retT+=std::to_string(y);
        }
        ret+=retT+")";
    }
    return ret;
}

int Dns::get_httpInProgress() const
{
    if(httpInProgress>0)
        return httpInProgress;
    else
        return 0;
}

void Dns::checkQueries()
{
    const std::map<uint64_t,std::vector<uint16_t>> queryByNextDueTime=this->queryByNextDueTime;
    for (auto const &x : queryByNextDueTime)
    {
        const uint64_t t=x.first;
        if(t>(uint64_t)time(NULL))
            return;
        const std::vector<uint16_t> &list=x.second;
        for (auto const& id : list)
        {
            Query &query=queryList.at(id);
            if(query.retryTime<dnsServerList.size()*2)
            {
                {
                    const uint8_t &currentQueryIndex=query.retryTime%dnsServerList.size();
                    const uint8_t &currentServerIndex=query.serverOrder[currentQueryIndex];
                    if(lastDnsFailed!=currentServerIndex)
                    {
                        lastDnsFailed=currentServerIndex;
                        DnsServerEntry &dnsServer=dnsServerList[currentServerIndex];
                        dnsServer.lastFailed=time(NULL);

                        std::vector<std::pair<uint8_t,uint64_t>> tempList;
                        uint8_t index=0;
                        while(index<dnsServerList.size())
                        {
                            tempList.push_back(std::pair<uint8_t,uint64_t>(index,dnsServerList.at(index).lastFailed));
                            index++;
                        }
                        std::sort(tempList.begin(), tempList.end(),
                            [](const std::pair<uint8_t,uint64_t> & a, const std::pair<uint8_t,uint64_t> & b)
                            {
                                return a.second < b.second;
                            });
                        index=0;
                        while(index<dnsServerList.size())
                        {
                            preferedServerOrder[index]=tempList[index].first;
                            index++;
                        }
                    }
                }

                query.retryTime++;

                const uint8_t &currentQueryIndex=query.retryTime%dnsServerList.size();
                const uint8_t &currentServerIndex=query.serverOrder[currentQueryIndex];
                const DnsServerEntry &dnsServer=dnsServerList.at(currentServerIndex);
                if(dnsServer.mode==Mode_IPv6)
                {
                    const int result = sendto(IPv6Socket->getFD(),query.query.data(),query.query.size(),0,(struct sockaddr*)&dnsServer.targetDnsIPv6,sizeof(dnsServer.targetDnsIPv6));
                    if(result!=(int)query.query.size())
                    {
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv6 reemit failed: " << str << " to resolv: " << query.host << std::endl;
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGDNS
                        char str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &dnsServer.targetDnsIPv6.sin6_addr, str, INET6_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv6 reemit ok: " << str << " to resolv: " << query.host << std::endl;
                        #endif
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
                        std::cerr << "sendto Mode_IPv4 reemit failed: " << str << " to resolv: " << query.host << std::endl;
                        #endif
                    }
                    else
                    {
                        #ifdef DEBUGDNS
                        char str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dnsServer.targetDnsIPv4.sin_addr, str, INET_ADDRSTRLEN);
                        std::cerr << "sendto Mode_IPv4 reemit ok: " << str << " to resolv: " << query.host << std::endl;
                        #endif
                    }
                }
                #ifdef DEBUGDNS
                std::cerr << "sendto reemit" << std::endl;
                #endif

                query.nextRetry=time(NULL)+5;
                this->queryByNextDueTime[query.nextRetry].push_back(id);
            }
            else
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
                removeQuery(id);
            }

            //query=cache.erase(y);
        }
        this->queryByNextDueTime.erase(t);
        //cacheByOutdatedDate.erase(t);
    }
}
