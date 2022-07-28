#ifdef DEBUGFASTCGITCP
#include "ServerTCP.hpp"
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

ServerTCP::ServerTCP(const char* const ip,const char* const port)
{
    this->kind=EpollObject::Kind::Kind_ServerTCP;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        std::cerr << "Can't create the unix socket: " << errno << std::endl;
        abort();
    }

    if(!tryListenInternal(ip,port))
        abort();
}

bool ServerTCP::tryListenInternal(const char* const ip,const char* const port)
{
    if(strlen(port)==0)
    {
        std::cout << "ServerTCP::tryListenInternal() port can't be empty (abort)" << std::endl;
        abort();
    }
    std::cout << "ServerTCP::tryListenInternal() on port: " << port << std::endl;

    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    if(ip==NULL || ip[0]=='\0')
        s = getaddrinfo(NULL, port, &hints, &result);
    else
        s = getaddrinfo(ip, port, &hints, &result);
    if (s != 0)
    {
        std::cerr << "getaddrinfo:" << gai_strerror(s) << std::endl;
        return false;
    }

    rp = result;
    if(rp == NULL)
    {
        std::cerr << "rp == NULL, can't bind" << std::endl;
        return false;
    }
    unsigned int bindSuccess=0,bindFailed=0;
    while(rp != NULL)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd == -1)
        {
            std::cerr
                    << "unable to create the socket: familly: " << rp->ai_family
                    << ", rp->ai_socktype: " << rp->ai_socktype
                    << ", rp->ai_protocol: " << rp->ai_protocol
                    << ", rp->ai_addr: " << rp->ai_addr
                    << ", rp->ai_addrlen: " << rp->ai_addrlen
                    << std::endl;
            continue;
        }

        int one=1;
        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one)!=0)
            std::cerr << "Unable to apply SO_REUSEADDR" << std::endl;
        one=1;
        if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one)!=0)
            std::cerr << "Unable to apply SO_REUSEPORT" << std::endl;

        s = bind(fd, rp->ai_addr, rp->ai_addrlen);
        if(s!=0)
        {
            //unable to bind
            ::close(fd);
            std::cerr
                    << "unable to bind: familly: " << rp->ai_family
                    << ", rp->ai_socktype: " << rp->ai_socktype
                    << ", rp->ai_protocol: " << rp->ai_protocol
                    << ", rp->ai_addr: " << rp->ai_addr
                    << ", rp->ai_addrlen: " << rp->ai_addrlen
                    << ", errno: " << std::to_string(errno)
                    << std::endl;
            bindFailed++;
        }
        else
        {
            if(fd==-1)
            {
                std::cerr << "Leave without bind but s!=0" << std::endl;
                return false;
            }

            int flags = fcntl(fd, F_GETFL, 0);
            if(flags == -1)
            {
                std::cerr << "fcntl get flags error" << std::endl;
                return false;
            }
            flags |= O_NONBLOCK;
            int s = fcntl(fd, F_SETFL, flags);
            if(s == -1)
            {
                std::cerr << "fcntl set flags error" << std::endl;
                return false;
            }

            s = listen(fd, SOMAXCONN);
            if(s == -1)
            {
                ::close(s);
                std::cerr << "Unable to listen" << std::endl;
                return false;
            }

            epoll_event event;
            event.data.ptr = this;
            #ifdef DEBUGFASTCGI
            std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #endif
            event.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP | EPOLLHUP | EPOLLERR;
            if((uint64_t)event.data.ptr<100)
            {
                std::cerr << "EPOLL_CTL_ADD: " << event.data.ptr << " " << __FILE__ << ":" << __LINE__ << " (abort)" << std::endl;
                abort();
            }
            s = epoll_ctl(epollfd,EPOLL_CTL_ADD, fd, &event);
            if(s == -1)
            {
                ::close(s);
                std::cerr << "epoll_ctl error" << std::endl;
                return false;
            }

            std::cout
                    << "correctly bind: familly: " << rp->ai_family
                    << ", rp->ai_socktype: " << rp->ai_socktype
                    << ", rp->ai_protocol: " << rp->ai_protocol
                    << ", rp->ai_addr: " << rp->ai_addr
                    << ", rp->ai_addrlen: " << rp->ai_addrlen
                    << ", port: " << port
                    << ", rp->ai_flags: " << rp->ai_flags
                    //<< ", rp->ai_canonname: " << rp->ai_canonname-> corrupt the output
                    << std::endl;
            char hbuf[NI_MAXHOST];
            if(!getnameinfo(rp->ai_addr, rp->ai_addrlen, hbuf, sizeof(hbuf),NULL, 0, NI_NAMEREQD))
                std::cout << "getnameinfo: " << hbuf << std::endl;
            bindSuccess++;
        }
        rp = rp->ai_next;
    }
    freeaddrinfo (result);
    return bindSuccess>0;
}

void ServerTCP::parseEvent(const epoll_event &)
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
            delete client;
        }
    }
}
#endif
