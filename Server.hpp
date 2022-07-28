#ifndef SERVER_H
#define SERVER_H

#include "EpollObject.hpp"

class Server : public EpollObject
{
public:
    Server(const char * const path);
    void parseEvent(const epoll_event &) override;
#ifdef DEBUGFASTCGITCP
private:
    bool tryListenInternal(const char* const ip,const char* const port);
#endif
};

#endif // SERVER_H
