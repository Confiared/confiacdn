#include "DnsSocket.hpp"
#include "Dns.hpp"
#include <iostream>

DnsSocket::DnsSocket(const int &fd) :
    EpollObject(fd,EpollObject::Kind::Kind_Dns)
{
    this->kind=EpollObject::Kind::Kind_Dns;

    //add to event loop
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    #ifdef DEBUGFASTCGI
    std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    if((uint64_t)event.data.ptr<100)
    {
        std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
        abort();
    }
    if(epoll_ctl(epollfd,EPOLL_CTL_ADD, fd, &event) == -1)
    {
        std::cerr << "epoll_ctl failed to add server errno: " << errno << std::endl;
        abort();
    }
}

DnsSocket::~DnsSocket()
{
}

void DnsSocket::parseEvent(const epoll_event &event)
{
    Dns::dns->parseEvent(event,this);
}
