#ifndef DNSCache_H
#define DNSCache_H

#include "../Timer.hpp"

class DNSCache : public Timer
{
public:
    DNSCache();
    void exec();
};

#endif // DNSCache_H
