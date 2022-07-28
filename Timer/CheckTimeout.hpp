#ifndef CHECKTIMEOUT_H
#define CHECKTIMEOUT_H

#include "../Timer.hpp"

class CheckTimeout : public Timer
{
public:
    CheckTimeout();
    void exec();
};

#endif // CHECKTIMEOUT_H
