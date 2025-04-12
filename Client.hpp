#ifndef Client_H
#define Client_H

#include "EpollObject.hpp"
#include <string>
#include <netinet/in.h>
#include <unordered_set>

class Cache;
class Http;

class Client : public EpollObject
{
public:
    Client(int cfd);
    ~Client();

    void readyToRead();
    void disconnect();

    bool startRead();
    bool startRead(const std::string &path, const bool &partial);
    void continueRead();
    void tryResumeReadAfterEndOfFile();

    bool detectTimeout();
    void parseEvent(const epoll_event &event) override;
    void httpError(const std::string &errorString);
    void writeOutputDropDataIfNeeded(const char * const data,const size_t &size);
public:
    enum Status : uint8_t
    {
        Status_Idle=0x00,
        Status_WaitTheContent=0x02,
    };

    static std::unordered_set<Client *> clients;//for timeout
    static std::unordered_set<Client *> clientToDelete;
#ifdef DEBUGFASTCGI
    static std::unordered_set<Client *> clientToDebug;
#endif
private:
    void disconnectFromHttp();

    void cacheError();

    void loadUrl(const std::string &host, const std::string &uri, const std::string &ifNoneMatch);
    inline bool canAddToPos(const int &i,const int &size,int &pos);
    inline bool read8Bits(uint8_t &var,const char * const data,const int &size,int &pos);
    inline bool read16Bits(uint16_t &var,const char * const data,const int &size,int &pos);
    inline bool read24Bits(uint32_t &var,const char * const data,const int &size,int &pos);
    void createHttpBackend();
    void createHttpBackendInternal(int cachefd,std::string etag=std::string());

    void readyToWrite();
    int64_t get_bodyAndHeaderFileBytesSended() const;

    bool dataToWriteIsEmpty() const;

    //can't be static, reused later
    #ifdef HOSTSUBFOLDER
    char pathVar[26+1];
    char folderVar[8+1+1];
    #else
    char pathVar[17+1];
    #endif
    /// \todo use std::string_view but need convert to C++17
    //static std::string pathForIndex;
    #ifdef DEBUGFASTCGI
    std::string getStatus() const;
    #endif
    static char bigStaticReadBuffer[65536];//size need be >= to MTU
    std::string requestRawData;

    void addHeaderAndWrite(const char * const data, const int &size);
    void writeEnd(const uint64_t &fileBytesSended);
    void internalWriteEnd();
private:
    void write(const char * const data,const int &size);
    int fastcgi_id;
    Cache *readCache;
public:
    Http *http;//public to be accessible by Http::removeClient()
private:
    std::string dataToWrite;
    bool fullyParsed;
    bool endTriggered;
    Status status;
    bool https;
    bool gzip;
    bool partial;
    bool partialEndOfFileTrigged;
    bool outputWrited;
    std::string uri;
    std::string host;
    uint64_t creationTime;
    uint64_t creationTimeOrUpdate;
    uint64_t bodyAndHeaderFileBytesSended;
    #ifdef DEBUGFASTCGI
    uint64_t bytesSended;
    #endif
    #ifdef DEBUGFROMIP
    std::string REMOTE_ADDR;
    #endif
};

#endif // Client_H
