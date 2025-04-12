#include "Server.hpp"
#include "Client.hpp"
#include "Dns.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <iostream>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

Server::Server(const char *const path)
{
    this->kind=EpollObject::Kind::Kind_Server;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        std::cerr << "Can't create the unix socket: " << errno << std::endl;
        abort();
    }

    struct sockaddr_un local;
    local.sun_family = AF_UNIX;
    strcpy(local.sun_path,path);
    unlink(local.sun_path);
    int len = strlen(local.sun_path) + sizeof(local.sun_family);
    if(bind(fd, (struct sockaddr *)&local, len)!=0)
    {
        std::cerr << "Can't bind the unix socket, error (errno): " << errno << std::endl;
        abort();
    }

    if(listen(fd, 4096) == -1)
    {
        std::cerr << "Unable to listen, error (errno): " << errno << std::endl;
        abort();
    }

    int flags, s;
    flags = fcntl(fd, F_GETFL, 0);
    if(flags == -1)
        std::cerr << "fcntl get flags error" << std::endl;
    else
    {
        flags |= O_NONBLOCK;
        s = fcntl(fd, F_SETFL, flags);
        if(s == -1)
            std::cerr << "fcntl set flags error" << std::endl;
    }

    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP | EPOLLHUP | EPOLLERR;
    #ifdef DEBUGFASTCGI
    std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
    #endif
    //std::cerr << "EPOLL_CTL_ADD: " << fd << std::endl;
    if((uint64_t)event.data.ptr<100)
    {
        std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
        abort();
    }
    if(epoll_ctl(epollfd,EPOLL_CTL_ADD, fd, &event) == -1)
    {
        std::cerr << "epoll_ctl failed to add server: " << errno << std::endl;
        abort();
    }
}

void Server::parseEvent(const epoll_event &)
{
    while(1)
    {
        sockaddr in_addr;
        socklen_t in_len = sizeof(in_addr);
        const int &infd = ::accept(fd, &in_addr, &in_len);
        if(infd == -1)
        {
            if((errno != EAGAIN) &&
            (errno != EWOULDBLOCK))
                std::cout << "connexion accepted" << std::endl;
            return;
        }
        if(Dns::dns->requestCountMerged()>1000)
        {
            #ifdef DEBUGFILEOPEN
            std::cerr << "Server::parseEvent(), fd: " << infd << std::endl;
            #endif
            ::close(infd);
            return;
        }

        //do the stuff
        Client *client=new Client(infd);
        //setup unix socket non blocking and listen
        epoll_event event;
        event.data.ptr = client;
        event.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP | EPOLLHUP | EPOLLERR;// | EPOLLONESHOT: broke
        #ifdef DEBUGFASTCGI
        std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        //std::cerr << "EPOLL_CTL_ADD: " << infd << std::endl;
        if(epoll_ctl(epollfd,EPOLL_CTL_ADD, infd, &event) == -1)
        {
            printf("epoll_ctl failed to add server: %s", strerror(errno));
            abort();
        }
        //try read request
        client->readyToRead();
        if(!client->isValid())
        {
            #ifdef DEBUGFASTCGI
            std::cerr << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            client->disconnect();
            //delete client; -> generate use after free bug
        }
    }
}

