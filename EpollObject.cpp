#include "EpollObject.hpp"

int EpollObject::epollfd;

EpollObject::EpollObject() :
    fd(-1),
    kind(Kind_Server)
{
}

EpollObject::EpollObject(const int fd,const Kind kind) :
    fd(fd),
    kind(kind)
{
}

void EpollObject::workAroundBug()
{
    fd=-1;
}

EpollObject::~EpollObject()
{
}

const EpollObject::Kind &EpollObject::getKind() const
{
    return kind;
}

int EpollObject::getFD() const
{
    return fd;
}

bool EpollObject::isValid() const
{
    return fd!=-1;
}
