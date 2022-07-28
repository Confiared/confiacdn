#ifndef DnsSocket_H
#define DnsSocket_H

#include "EpollObject.hpp"

class DnsSocket : public EpollObject
{
public:
    DnsSocket(const int &fd);
    ~DnsSocket();
    void parseEvent(const epoll_event &event) override;
};

#endif // Dns_H
