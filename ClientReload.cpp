#include "ClientReload.hpp"
#include "Dns.hpp"
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <iostream>
#include <new>

ClientReload::ClientReload(int cfd) :
    EpollObject(cfd,EpollObject::Kind::Kind_ClientReload),
    s(0),
    pos(0),
    buffer(NULL)
{
}

ClientReload::~ClientReload()
{
    disconnect();
}

void ClientReload::parseEvent(const epoll_event &event)
{
    if(event.events & EPOLLIN)
        readyToRead();
    if(event.events & EPOLLHUP)
        disconnect();
    if(event.events & EPOLLRDHUP)
        disconnect();
    if(event.events & EPOLLERR)
        disconnect();
}

void ClientReload::readyToRead()
{
    if(s==0)
    {
        if(::read(fd,&s,sizeof(s))!=sizeof(s))
            return;
        // Reject obviously-bogus sizes. The reload protocol's "length" field is
        // the first sizeof(size_t) bytes from the wire — main.cpp's reload sender
        // doesn't actually emit a length prefix today, so what arrives here is
        // raw payload bytes interpreted as a size. Without this bound the daemon
        // calls malloc(huge) and AddressSanitizer aborts on allocation-size-too-
        // big; in production this would surface as an OOM kill or std::bad_alloc.
        // Cap at 16MB — far larger than any sane DNS-static-entry table.
        constexpr size_t kReloadMaxSize=16ULL*1024ULL*1024ULL;
        if(s==0 || s>kReloadMaxSize)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " reject reload of size " << s
                      << " (max " << kReloadMaxSize << "); disconnecting" << std::endl;
            s=0;
            disconnect();
            return;
        }
        buffer=new(std::nothrow) char[s];
        if(buffer==nullptr)
        {
            std::cerr << __FILE__ << ":" << __LINE__ << " reload alloc(" << s << ") failed" << std::endl;
            s=0;
            disconnect();
            return;
        }
        memset(buffer,0,s);
    }
    //read
    int sizeread=0;
    do
    {
        sizeread=::read(fd,buffer+pos,s-pos);
        if(sizeread>0)
            pos+=sizeread;
    } while(sizeread>0 && pos<s);
    if(pos>=s)
    {
        #ifdef DEBUGFASTCGI
        auto start = std::chrono::steady_clock::now();
        #endif
        std::vector<std::pair<in6_addr,std::string>> data;
        //parse the buffer
        in6_addr sin6_addr;
        memset(&sin6_addr,0,sizeof(sin6_addr));
        uint8_t stringsize=0;
        char string[255];
        memset(&string,0,sizeof(string));
        pos=0;
        while(pos<s)
        {
            memcpy(&sin6_addr,buffer+pos,sizeof(sin6_addr));
            pos+=sizeof(sin6_addr);
            memcpy(&stringsize,buffer+pos,sizeof(stringsize));
            pos+=sizeof(stringsize);
            memcpy(string,buffer+pos,stringsize);
            pos+=stringsize;
            data.push_back(std::pair<in6_addr,std::string>(sin6_addr,std::string(string,stringsize)));
        }
        Dns::dns->reloadStaticEntry(data);
        #ifdef DEBUGFASTCGI
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        long long milliseconds = duration.count();
        std::cout << "Reload into: " << milliseconds << " ms" << std::endl;
        #endif

        disconnect();
    }
}

void ClientReload::disconnect()
{
    if(buffer!=nullptr)
    {
        // buffer was allocated with new[], not malloc — must use delete[] (using
        // plain delete on an array is UB and trips ASan).
        delete[] buffer;
        buffer=nullptr;
    }
    s=0;
    pos=0;
    if(fd==-1)
        return;
    epoll_ctl(epollfd,EPOLL_CTL_DEL, fd, NULL);
    ::close(fd);
    fd=-1;
}
