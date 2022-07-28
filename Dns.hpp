#ifndef Dns_H
#define Dns_H

#include "DnsSocket.hpp"
#include <string>
#include <unordered_map>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>

#define CACHETIMEDIVIDER 1
//should be power of 2
#define MAXDNSSERVER 16

class Http;
class DnsSocket;

class Dns
{
public:
    Dns();
    ~Dns();
    void parseEvent(const epoll_event &event, const DnsSocket *socket);
    inline bool canAddToPos(const int &i, const int &size, int &pos);
    inline bool read8Bits(uint8_t &var, const char * const data, const int &size, int &pos);
    inline bool read16Bits(uint16_t &var, const char * const data, const int &size, int &pos);
    inline bool read16BitsRaw(uint16_t &var, const char * const data, const int &size, int &pos);
    inline bool read32Bits(uint32_t &var, const char * const data, const int &size, int &pos);
    bool tryOpenSocket();
    bool getAAAA(Http * http,const std::string &host,const bool &https);
    void cancelClient(Http * http,const std::string &host,const bool &https);
    int requestCountMerged();
    void cleanCache();
    void checkQueries();
    static Dns *dns;
    std::string getQueryList() const;
    int get_httpInProgress() const;
    static const unsigned char include[];
    static const unsigned char exclude[];
private:
    enum StatusEntry : uint8_t
    {
        StatusEntry_Right=0x00,
        StatusEntry_Wrong=0x01,
        StatusEntry_Error=0x02,
        StatusEntry_Timeout=0x03,
    };
    enum Mode : uint8_t
    {
        Mode_IPv6=0x00,
        Mode_IPv4=0x01,
    };
    struct CacheAAAAEntry {
        in6_addr sin6_addr;
        uint64_t outdated_date;/*in s from 1970*/
        StatusEntry status;
    };
    std::unordered_map<std::string,CacheAAAAEntry> cacheAAAA;
    std::map<uint64_t/*outdated_date in s from 1970*/,std::vector<std::string>> cacheAAAAByOutdatedDate;
    void addCacheEntryFailed(const StatusEntry &s,const uint32_t &ttl,const std::string &host);
    void addCacheEntry(const StatusEntry &s, const uint32_t &ttl, const std::string &host, const in6_addr &sin6_addr);

    struct DnsServerEntry {
        Mode mode;
        sockaddr_in6 targetDnsIPv6;
        sockaddr_in targetDnsIPv4;
        uint64_t lastFailed;//0 if never failed
    };
    std::vector<DnsServerEntry> dnsServerList;
    uint8_t lastDnsFailed;//255 if no server dns failed
    //to put on last try the dns server with problem
    uint8_t preferedServerOrder[MAXDNSSERVER];
    uint16_t increment;

    struct Query {
        std::string host;
        //separate http and https to improve performance by better caching socket to open
        std::vector<Http *> http;
        std::vector<Http *> https;
        uint8_t retryTime;
        uint64_t nextRetry;
        std::string query;
        uint8_t serverOrder[MAXDNSSERVER];
    };
    int httpInProgress;
    void addQuery(const uint16_t &id,const Query &query);
    void removeQuery(const uint16_t &id, const bool &withNextDueTime=true);
    std::map<uint64_t,std::vector<uint16_t>> queryByNextDueTime;
    std::unordered_map<uint16_t,Query> queryList;
    std::unordered_map<std::string,uint16_t> queryListByHost;
    sockaddr_in6 targetHttp;
    sockaddr_in6 targetHttps;
    in6_addr sin6_addr;

    DnsSocket *IPv4Socket;
    DnsSocket *IPv6Socket;
};

#endif // Dns_H
