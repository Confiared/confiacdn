#ifndef ClientRELOAD_H
#define ClientRELOAD_H

#include "EpollObject.hpp"
#include <string>
#include <netinet/in.h>
#include <unordered_set>

class ClientReload : public EpollObject
{
public:
    ClientReload(int cfd);
    ~ClientReload();

    void readyToRead();
    void disconnect();
    void parseEvent(const epoll_event &event) override;
private:
    size_t s;
    size_t pos;
    char *buffer;
};

#endif // Client_H
