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
class Http3;

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
    int64_t getContentwritten() const;
    // Backend Range-resume after mid-body disconnect. Caller must have already
    // detached this Http from its (closed) backend; after return, calling
    // readyToWrite() / sendRequest() will issue a fresh request that, if the
    // origin cooperates, reuses the partial body in cache.
    void prepareForResume();
    // Push lastReceivedBytesTimestamps to "now". Called by Backend when this
    // Http is reassigned to a fresh Backend after the previous one timed out:
    // without this, the stale timestamp from the previous backend would make
    // the next CheckTimeout sweep fire Http::detectTimeout immediately, which
    // races the just-issued reassign and trips the
    // `backend->http==this` invariant in Http::tryConnectInternal.
    void resetActivityTimestampForReassign();

    void dnsRight(const sockaddr_in6 &sIPv6);
    void dnsError();
    void dnsWrong();

    // === HTTP/3-first dial + H1.1 fallback ===
    //
    // When `http3Enabled` is set and this is an HTTPS fetch, dnsRight()
    // calls startH3() instead of tryConnectInternal(). The H3 leg runs
    // in parallel with the daemon's normal event loop; detectTimeout()
    // ticks call checkH3() once per second to drive the state machine:
    //
    //   * Http3 reports allStreamsDone with a usable status
    //     (>=200 && <500): adoptH3Response() synthesizes the cache file
    //     + emits headers/body via the existing client-emit path. Done.
    //   * Http3 reports connFailed, deadline exceeded, or a 5xx status:
    //     tear down the H3 leg, call Http3::markOriginFailed(m_socket),
    //     and dispatch to tryConnectInternal(m_socket) — the standard
    //     HTTPS leg picks up from here as if --http3 was off.
    //
    // The origin-failure cache short-circuits this path: if
    // Http3::isOriginRecentlyFailed(m_socket) is true at dnsRight time,
    // we skip H3 entirely and go straight to tryConnectInternal.
    void startH3();
    void checkH3();
    bool adoptH3Response();
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
    // HTTP/3-first dial knobs. http3Enabled gates the new path entirely;
    // http3DeadlineMs caps how long an in-flight H3 attempt may take
    // before we abandon it and fall back to H1.1.
    static bool http3Enabled;
    static uint16_t http3Port;
    static uint64_t http3DeadlineMs;
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
        Parsing_Location,
        Parsing_ContentRange,
        Parsing_Content
    };
    Parsing parsing;
    std::string location;        // captured from origin's Location header (used for 3xx forward)
    std::string contentRange;    // captured from origin's Content-Range header (used for 206 resume)
    int64_t resumeOffset;        // bytes already in cache before this fetch (for Range retry); -1 = fresh fetch
    int64_t skipBytes;           // body-skip counter for 200-on-resume (origin ignored Range and replied with full body — drop the suffix we already have, then continue)
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
    Http3 *http3Conn;            // owned; non-null while H3 leg is in flight
    uint64_t http3StartedMs;     // ms-since-1970 when H3 leg launched
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
