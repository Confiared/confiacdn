#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <vector>
#include <netinet/in.h>
#include <unordered_map>
#include <unordered_set>

#include "Backend.hpp"

class Client;
class Cache;

class Http
{
public:
    Http(const int &cachefd,//0 if no old cache file found
         const std::string &cachePath,Client *client);
    virtual ~Http();
    bool detectTimeout();
    void backendErrorAndDisconnect(const std::string &errorString);
    void disconnectFrontend(const bool &force);
    void resetRequestSended();
    void disconnectBackend(const bool fromDestructor=false);
    void readyToWrite();
    virtual std::string getUrl() const;
    std::string get_host() const;
    virtual bool isHttps();
    bool haveUrlAndFrontendConnected() const;
    bool readyToRead();//true if have read something
    bool get_requestSended();
    void addClient(Client * client);
    bool removeClient(Client * client);
    std::string getQuery() const;
    bool isAlive() const;
    bool tryConnect(const std::string &host, const std::string &uri, const bool &gzip, const std::string &etagBackend=std::string());
    bool getEndDetected() const;
    bool getFileMoved() const;

    void dnsRight(const sockaddr_in6 &sIPv6);
    void dnsError();
    void dnsWrong();
#ifdef DEBUGFASTCGI
    static void checkIngrityHttpClient();
#endif

    enum Status : uint8_t
    {
        Status_Idle=0x00,
        Status_WaitDns=0x01,
        Status_WaitTheContent=0x02,
    };
    Status get_status() const;
protected:
    virtual bool tryConnectInternal(const sockaddr_in6 &s);
    void parseEvent(const epoll_event &event);
    static char randomETagChar(uint8_t r);
    void sendRequest();

    void flushRead();
    virtual std::unordered_map<std::string,Http *> &pathToHttpList();
    const int &getAction() const;
    int writeToCache(const char * const data, const size_t &size);
    static std::string timestampsToHttpDate(const int64_t &time);
    const std::string &getCachePath() const;
    bool isWithClient() const;
    bool startReadFromCacheAfter304();
    bool HttpReturnCode(const int &errorCode);//return true if need continue
    #ifndef CURL
    void parseNonHttpError(const Backend::NonHttpError &error);
    #endif

    ssize_t socketRead(void *buffer, size_t size);
    bool socketWrite(const void *buffer, size_t size);

    void retryAfterError();
public:
    //index can be: 29E7336BDEA3327B or XXXXXXXX/XXXXXXXXXXXXXXXXY
    static std::unordered_map<std::string,Http *> pathToHttp;
    //static std::unordered_map<std::array<char, X>,Http *> pathToHttp;-> better performance?
    #ifdef HOSTSUBFOLDER
    //static std::unordered_map<char[26],Http *> pathToHttp;
    #else
    //static std::unordered_map<char[17],Http *> pathToHttp;
    #endif
    static int fdRandom;
    static char buffer[65535-1000];//fastcgi don't support more than 65535-1000 bytes
    static bool useCompression;
    static bool allowStreaming;
    std::string cachePath;
    std::string tempPath;//with random to prevent dual open
protected:
    std::vector<Client *> clientsList;
private:
    //why 2 variables here? Should be resolved into one variable to be more clear
    Cache *tempCache;
    Cache *finalCache;

    bool parsedHeader;
    uint64_t lastReceivedBytesTimestamps;

    std::string contenttype;
    std::string url;
    int64_t contentsize;
    int64_t contentwritten;
    std::string headerBuff;
    uint16_t http_code;
    enum Parsing: uint8_t
    {
        Parsing_None,
        Parsing_HeaderVar,
        Parsing_HeaderVal,
        Parsing_RemoteAddr,
        Parsing_ServerAddr,
        Parsing_ContentLength,
        Parsing_ContentType,
        Parsing_ContentEncoding,
        Parsing_CacheControl,
        Parsing_AcceptRanges,
        Parsing_ETag,
        Parsing_Content
    };
    Parsing parsing;
    Status status;

    std::string etagBackend;
    std::string remoteAddr;
protected:
    std::string host;
    std::string uri;
    bool gzip;
public:
    uint8_t retryCount;
    bool pending;
    bool requestSended;
    bool headerWriten;
    bool endDetected;
    bool fileMoved;
    bool streamingDetected;
    #ifndef CURL
    Backend *backend;
    Backend::BackendList * backendList;
    #endif
    int64_t contentLengthPos;
    int64_t chunkLength;
    std::string chunkHeader;
    static char fastcgiheaderend[1+1+2+2+2+4+4];
    static char fastcgiheaderstdout[1+1+2+2+2];
    static std::unordered_set<Http *> httpToDelete;
    std::string contentEncoding;
    #ifdef DEBUGFASTCGI
    static std::unordered_set<Http *> httpToDebug;
    void checkBackend();
    #endif
protected:
    sockaddr_in6 m_socket;//to found the debug backend list AND retry out of debug
};

#endif // HTTP_H
