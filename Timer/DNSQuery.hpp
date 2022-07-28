#ifndef DNSQuery_H
#define DNSQuery_H

#include "../Timer.hpp"

class DNSQuery : public Timer
{
public:
    DNSQuery();
    void exec();
};

#endif // DNSQuery_H
