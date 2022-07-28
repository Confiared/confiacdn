#ifndef SERVERTCP_H
#define SERVERTCP_H

#ifdef DEBUGFASTCGITCP
#include "EpollObject.hpp"

class ServerTCP : public EpollObject
{
public:
    ServerTCP(const char* const ip,const char* const port);
    void parseEvent(const epoll_event &) override;
private:
    bool tryListenInternal(const char* const ip,const char* const port);
};
#endif

#endif // SERVER_H
