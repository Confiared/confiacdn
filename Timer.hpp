#ifndef EPOLL_TIMER_H
#define EPOLL_TIMER_H

#include "EpollObject.hpp"

class Timer : public EpollObject
{
public:
    Timer();
    ~Timer();
    bool start(const unsigned int &msec);
    virtual void exec() = 0;
    void validateTheTimer();
private:
    unsigned int msec;
    void parseEvent(const epoll_event &event);
};

#endif // EPOLL_TIMER_H
