#ifndef EPOLLOBJECT_H
#define EPOLLOBJECT_H

#include <stdint.h>
#include <sys/epoll.h>

class EpollObject
{
public:
    enum Kind : uint8_t
    {
        Kind_Server,
        Kind_Client,
        Kind_Backend,
        Kind_Dns,
        Kind_Timer,
        Kind_Cache,
        Kind_ServerTCP,
    };
    EpollObject();
    EpollObject(const int fd,const Kind kind);
    virtual ~EpollObject();
    bool isValid() const;
    virtual void parseEvent(const epoll_event &event) = 0;
    const Kind &getKind() const;
    void workAroundBug();
    int getFD() const;
protected:
    int fd;
    Kind kind;
public:
    static int epollfd;
};

#endif // EPOLLOBJECT_H
