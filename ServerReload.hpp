#ifndef SERVERRELOAD_H
#define SERVERRELOAD_H

#include "EpollObject.hpp"

class ServerReload : public EpollObject
{
public:
    ServerReload(const char * const path);
    void parseEvent(const epoll_event &) override;
};

#endif // SERVER_H
