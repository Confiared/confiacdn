#include "Timer.hpp"

#include <iostream>
#include <sys/timerfd.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

char buff_temp[sizeof(uint64_t)];

Timer::Timer() :
    msec(0)
{
    this->kind=EpollObject::Kind::Kind_Timer;
}

Timer::~Timer()
{
    if(fd!=-1)
    {
        #ifdef DEBUGFASTCGI
        std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        ::close(fd);
    }
    //mostly bad usage for my own upper class
    //abort();
}

bool Timer::start(const unsigned int &msec)
{
    if(fd!=-1)
        return false;
    if(msec<1)
        return false;
    if((fd=::timerfd_create(CLOCK_REALTIME,TFD_NONBLOCK)) < 0)
    {
        std::cerr << "Timer creation error" << std::endl;
        return false;
    }

    timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) == -1)
    {
        std::cerr << "clock_gettime error" << std::endl;
        return false;
    }
    itimerspec new_value;
    new_value.it_value.tv_sec = now.tv_sec + 0;
    new_value.it_value.tv_nsec = now.tv_nsec + 0;
    if(new_value.it_value.tv_nsec>999999999)
    {
        new_value.it_value.tv_nsec-=1000000000;
        new_value.it_value.tv_sec++;
    }
    new_value.it_interval.tv_sec = msec/1000;
    new_value.it_interval.tv_nsec = (msec%1000)*1000000;
    if(new_value.it_interval.tv_nsec>999999999)
    {
        new_value.it_interval.tv_nsec-=1000000000;
        new_value.it_interval.tv_sec++;
    }

    const int &result=::timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL);
    if(result<0)
    {
        //settime error: 22: Invalid argument
        std::cerr << "settime error: " << errno << ": " << strerror(errno) << std::endl;
        return false;
    }
    epoll_event event;
    memset(&event,0,sizeof(event));
    event.data.ptr = this;
    event.events = EPOLLIN;// | EPOLLONESHOT: broke
    #ifdef DEBUGFASTCGI
    std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    if(epoll_ctl(epollfd,EPOLL_CTL_ADD,fd,&event) < 0)
    {
        std::cerr << "epoll_ctl error" << std::endl;
        return false;
    }
    return true;
}

void Timer::validateTheTimer()
{
    if(::read(fd, buff_temp, sizeof(uint64_t))!=sizeof(uint64_t))
    {}
}

void Timer::parseEvent(const epoll_event &event)
{
    (void)event;
}
