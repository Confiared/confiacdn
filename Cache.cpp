#include "Cache.hpp"
#include "Backend.hpp"
#include "Client.hpp"
#include <unistd.h>
#include <iostream>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

std::unordered_map<int,Cache::FDSave> Cache::FDList;

bool Cache::enable=true;
uint32_t Cache::http200Time=24*3600;
/*uint32_t Cache::maxiumSizeToBeSmallFile=4096;
uint64_t Cache::maxiumSmallFileCacheSize=0;//diable by default (to be safe if on ram disk)
uint64_t Cache::smallFileCacheSize=0;*/

//use pread, pwrite

/*Format, insert/drop at middle with sequential scan:
 * 64Bits: access time
 * 64Bits: last modification time check (Modification based on ETag)
 * 16Bits: http code
 * 48Bits: frontend content Etag, Base64 Random bytes at Creation or Modification
 * 8Bits: Etag backend size in Bytes
 * XBytes: backend content (see Etag backend size)
 * Http Headers ended with \n\n
 * Http body
*/

Cache::Cache(const int &fd, void *client)
{
    this->kind=EpollObject::Kind::Kind_Cache;
    this->fd=fd;
    this->client=client;
    /*
    //while receive write to cache
    //when finish
        //unset curl to all future listener
        //Close all listener
    */
}

Cache::~Cache()
{
    close();
}

ssize_t Cache::size() const
{
    struct stat sb;
    if(fstat(fd,&sb)!=0)
        return -1;
    else
        return sb.st_size;
}

void Cache::parseEvent(const epoll_event &event)
{
    (void)event;
    if(!(event.events & EPOLLIN))
        if(client!=nullptr)
            static_cast<Client *>(client)->continueRead();
    #ifdef DEBUGFASTCGI
    std::cout << this << " Cache event.events: " << event.events << std::endl;
    #endif
    if(!(event.events & EPOLLHUP))
        close();
}

void Cache::close()
{
    #ifdef DEBUGFILEOPEN
    std::cerr << "Cache::close(), fd: " << fd << std::endl;
    #endif
    if(fd!=-1)
    {
        Cache::closeFD(fd);
        epoll_ctl(epollfd,EPOLL_CTL_DEL, fd, NULL);
        #ifdef DEBUGFASTCGI
        std::cerr << "close() fd: " << fd << " " << this << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #endif
        ::close(fd);
        fd=-1;
    }
}

uint64_t Cache::access_time() const
{
    uint64_t time=0;
    #ifdef PREADPWRITE
    if(::pread(fd,&time,sizeof(time),0)==sizeof(time))
        return time;
    else
        std::cerr << "Unable to pread, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
#else
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Cache::access_time(): " << fd << std::endl;
    #endif
    if(lseek(fd, 0, SEEK_SET)!=-1)
    {
        if(::read(fd, &time, sizeof(time))==sizeof(time))
            return time;
        else
            std::cerr << "Unable to read, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
    }
    else
        std::cerr << "Unable to fseek " << 0 << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
#endif
    return 0;
}

uint64_t Cache::last_modification_time_check() const
{
    uint64_t time=0;
    #ifdef PREADPWRITE
    if(::pread(fd,&time,sizeof(time),sizeof(uint64_t))==sizeof(time))
        return time;
    else
        std::cerr << "Unable to pread, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
#else
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Cache::last_modification_time_check(): " << fd << std::endl;
    #endif
    if(lseek(fd, sizeof(uint64_t), SEEK_SET)!=-1)
    {
        if(::read(fd, &time, sizeof(time))==sizeof(time))
            return time;
        else
            std::cerr << "Unable to read, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
    }
    else
        std::cerr << "Unable to fseek " << sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
#endif
    return 0;
}

std::string Cache::ETagFrontend() const
{
    char randomIndex[6];
    #ifdef PREADPWRITE
    if(::pread(fd,randomIndex,sizeof(randomIndex),2*sizeof(uint64_t)+sizeof(uint16_t))!=sizeof(randomIndex))
    {
        std::cerr << "Unable to pread, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return std::string();
    }
#else
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Cache::ETagFrontend(): " << fd << std::endl;
    #endif
    if(lseek(fd, 2*sizeof(uint64_t)+sizeof(uint16_t), SEEK_SET)==-1)
    {
        std::cerr << "Unable to fseek" << 2*sizeof(uint64_t)+sizeof(uint16_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return std::string();
    }
    if(::read(fd, randomIndex,sizeof(randomIndex))!=sizeof(randomIndex))
    {
        std::cerr << "Unable to read, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return std::string();
    }
    #endif
    const std::string &etag=std::string(randomIndex,sizeof(randomIndex));
    #ifdef DEBUGFASTCGI
    if(etag.find('\0')!=std::string::npos)
    {
        std::cerr << "etag contain \\0 abort" << __FILE__ << ":" << __LINE__ << std::endl;
        return std::string();
    }
    #endif
    return etag;
}

std::string Cache::ETagBackend() const
{
    uint8_t etagBackendSize=0;
    #ifdef PREADPWRITE
    if(::pread(fd,&etagBackendSize,sizeof(etagBackendSize),3*sizeof(uint64_t))==sizeof(etagBackendSize))
#else
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Cache::ETagBackend(): " << fd << std::endl;
    #endif
    if(lseek(fd, 3*sizeof(uint64_t), SEEK_SET)==-1)
    {
        std::cerr << "Unable to fseek" << 3*sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return std::string();
    }
    if(::read(fd, &etagBackendSize,sizeof(etagBackendSize))!=sizeof(etagBackendSize))
    {
        std::cerr << "Unable to read, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return std::string();
    }
#endif
    {
        char buffer[etagBackendSize];
        #ifdef PREADPWRITE
        if(::pread(fd,buffer,etagBackendSize,3*sizeof(uint64_t)+sizeof(uint8_t))==etagBackendSize)
        {
            std::cerr << "Unable to pread, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return std::string();
        }
#else
        #ifdef DEBUGFASTCGI
        std::cerr << __FILE__ << ":" << __LINE__ << " Cache::ETagBackend(): " << fd << std::endl;
        #endif
        if(lseek(fd, 3*sizeof(uint64_t)+sizeof(uint8_t), SEEK_SET)==-1)
        {
            std::cerr << "Unable to fseek" << 3*sizeof(uint64_t)+sizeof(uint8_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return std::string();
        }
        if(::read(fd, buffer,etagBackendSize)!=etagBackendSize)
        {
            std::cerr << "Unable to read, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return std::string();
        }
#endif
        const std::string &etag=std::string(buffer,etagBackendSize);
        #ifdef DEBUGFASTCGI
        if(etag.find('\0')!=std::string::npos)
        {
            std::cerr << "etag contain \\0 abort" << __FILE__ << ":" << __LINE__ << std::endl;
            return std::string();
        }
        #endif
        return etag;
    }
}

uint16_t Cache::http_code() const
{
    uint16_t code=0;
    #ifdef PREADPWRITE
    if(::pread(fd,&time,sizeof(code),2*sizeof(uint64_t))==sizeof(time))
        return time;
    else
        std::cerr << "Unable to pread, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
#else
    #ifdef DEBUGFASTCGI
    std::cerr << __FILE__ << ":" << __LINE__ << " Cache::http_code(): " << fd << std::endl;
    #endif
    if(lseek(fd, 2*sizeof(uint64_t), SEEK_SET)!=-1)
    {
        if(::read(fd, &code, sizeof(code))==sizeof(code))
            return code;
        else
        {
            std::cerr << "Unable to read, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            #ifdef DEBUGFASTCGI
            abort();
            #endif
        }
    }
    else
    {
        std::cerr << "Unable to fseek" << 2*sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        #ifdef DEBUGFASTCGI
        abort();
        #endif
    }
#endif
    return 500;
}

bool Cache::set_access_time(const uint64_t &time)
{
    #ifdef PREADPWRITE
    if(::pwrite(fd,&time,sizeof(time),0)!=sizeof(time))
    {
        std::cerr << "Unable to write last_modification_time_check" << std::endl;
        return false;
    }
    #else
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::set_access_time(): " << fd << std::endl;
    #endif
    if(lseek(fd, 0, SEEK_SET)!=-1)
    {
        if(fd==-1)
            return false;
        if(::write(fd, &time,sizeof(time))!=sizeof(time))
        {
            std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Unable to fseek" << 0 << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
    #endif
    return true;
}

bool Cache::set_last_modification_time_check(const uint64_t &time)
{
    #ifdef PREADPWRITE
    if(::pwrite(fd,&time,sizeof(time),sizeof(uint64_t))!=sizeof(time))
    {
        std::cerr << "Unable to write last_modification_time_check" << std::endl;
        return false;
    }
    #else
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::set_access_time(): " << fd << std::endl;
    #endif
    if(lseek(fd, sizeof(uint64_t), SEEK_SET)!=-1)
    {
        if(fd==-1)
            return false;
        if(::write(fd, &time,sizeof(time))!=sizeof(time))
        {
            std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Unable to fseek" << sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
    #endif
    return true;
}

bool Cache::set_ETagFrontend(const std::string &etag)
{
    #ifdef PREADPWRITE
    if((size_t)::pwrite(fd,etag.data(),etag.size(),2*sizeof(uint64_t)+sizeof(uint16_t))!=etag.size())
    {
        std::cerr << "Unable to write last_modification_time_check" << std::endl;
        return false;
    }
    #else
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::set_ETagFrontend(): " << fd << std::endl;
    #endif
    if(lseek(fd, 2*sizeof(uint64_t)+sizeof(uint16_t), SEEK_SET)!=-1)
    {
        if(fd==-1)
            return false;
        if(::write(fd, etag.data(),etag.size())!=(ssize_t)etag.size())
        {
            std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Unable to fseek" << 2*sizeof(uint64_t)+sizeof(uint16_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
    #endif
    return true;
}

bool Cache::set_ETagBackend(const std::string &etag)//at end seek to content pos
{
    if(etag.size()>255)
    {
        char c=0x00;
        #ifdef PREADPWRITE
        if(::pwrite(fd,&c,sizeof(c),3*sizeof(uint64_t))!=sizeof(c))
        {
            std::cerr << "Unable to write last_modification_time_check" << std::endl;
            return false;
        }
        #else
        #ifdef DEBUGFASTCGI
        //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::set_ETagBackend(): " << fd << std::endl;
        #endif
        if(lseek(fd, 3*sizeof(uint64_t), SEEK_SET)!=-1)
        {
            if(fd==-1)
                return false;
            if(::write(fd, &c,sizeof(c))!=sizeof(c))
            {
                std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return false;
            }
        }
        else
        {
            std::cerr << "Unable to fseek" << 3*sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return false;
        }
        #endif
    }
    else
    {
        char c=etag.size();
        #ifdef PREADPWRITE
        if(::pwrite(fd,&c,sizeof(c),3*sizeof(uint64_t))!=sizeof(c))
        {
            std::cerr << "Unable to write last_modification_time_check" << std::endl;
            return false;
        }
#else
        #ifdef DEBUGFASTCGI
        //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::set_ETagBackend(): " << fd << std::endl;
        #endif
        if(lseek(fd, 3*sizeof(uint64_t), SEEK_SET)==-1)
        {
            std::cerr << "Unable to fseek" << 3*sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return false;
        }
        if(fd==-1)
            return false;
        if(::write(fd, &c,sizeof(c))!=sizeof(c))
        {
            std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
            return false;
        }
#endif
        if(c>0)
        {
            #ifdef PREADPWRITE
            if((size_t)::pwrite(fd,etag.data(),etag.size(),3*sizeof(uint64_t)+sizeof(uint8_t))!=etag.size())
            {
                std::cerr << "Unable to write last_modification_time_check" << std::endl;
                return false;
            }
#else
            if(fd==-1)
                return false;
            if(::write(fd, etag.data(),etag.size())!=(ssize_t)etag.size())
            {
                std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
                return false;
            }
#endif
        }
    }
    return true;
}

bool Cache::set_http_code(const uint16_t &http_code)
{
    #ifdef PREADPWRITE
    if(::pwrite(fd,&http_code,sizeof(http_code),2*sizeof(uint64_t))!=sizeof(http_code))
    {
        std::cerr << "Unable to write last_modification_time_check" << std::endl;
        return false;
    }
#else
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::set_http_code(): " << fd << std::endl;
    #endif
    if(lseek(fd, 2*sizeof(uint64_t), SEEK_SET)==-1)
    {
        std::cerr << "Unable to fseek" << 2*sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
    if(fd==-1)
        return false;
    if(::write(fd, &http_code,sizeof(http_code))!=sizeof(http_code))
    {
        std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
#endif
    return true;
}

/*void Cache::setAsync()
{
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
}*/

bool Cache::seekToContentPos()
{
    uint8_t etagBackendSize=0;
    errno=0;
    #ifdef PREADPWRITE
    const size_t &returnVal=::pread(fd,&etagBackendSize,sizeof(etagBackendSize),3*sizeof(uint64_t));
#else
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::seekToContentPos(): " << fd << std::endl;
    #endif
    if(lseek(fd, 3*sizeof(uint64_t), SEEK_SET)==-1)
    {
        std::cerr << "Unable to fseek" << 3*sizeof(uint64_t) << ", errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
    const size_t &returnVal=::read(fd, &etagBackendSize,sizeof(etagBackendSize));
    if(returnVal!=sizeof(etagBackendSize))
    {
        std::cerr << "Unable to write, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
        return false;
    }
#endif
    if(returnVal==sizeof(etagBackendSize))
    {
        const off_t &pos=3*sizeof(uint64_t)+sizeof(uint8_t)+etagBackendSize;
        #ifdef DEBUGFASTCGI
        //std::cerr << __FILE__ << ":" << __LINE__ << " Cache::seekToContentPos(): " << fd << std::endl;
        #endif
        const off_t &s=lseek(fd,pos,SEEK_SET);
        if(s==-1)
        {
            std::cerr << "Unable to seek setContentPos" << std::endl;
            return false;
        }
        //std::cout << "seek to:" << pos << std::endl;
        return true;
    }
    else
        std::cerr << "Unable to pread, errno: " << errno << " " << __FILE__ << ":" << __LINE__ << std::endl;
    return false;
}

ssize_t Cache::write(const char * const data,const size_t &size)
{
    errno=0;
    if(fd==-1)
        return -1;
    ssize_t r=::write(fd,data,size);
    return r;
}

ssize_t Cache::read(char * data,const size_t &size)
{
    #ifdef DEBUGFASTCGI
    //std::cerr << __FILE__ << ":" << __LINE__ << " read fd: " << fd << std::endl;
    #endif
    errno=0;
    const ssize_t s=::read(fd,data,size);
    #ifdef DEBUGFASTCGI
    if(errno!=0)
        std::cerr << __FILE__ << ":" << __LINE__ << " read errno: " << errno << std::endl;
    #endif
    return s;
}

uint32_t Cache::timeToCache(uint16_t http_code)
{
    switch(http_code)
    {
        case 200:
            return Cache::http200Time/CACHETIMEDIVIDER;
            //return 600;
        break;
        default:
            return 60/CACHETIMEDIVIDER;
        break;
    }
}

//why this method?
void Cache::newFD(const int &fd,void * pointer,const EpollObject::Kind &kind)
{
    if(fd<0)
    {
        std::cerr << "ERROR Cache::newFD(" << fd << "," << pointer << "," << std::to_string((int)kind) << ")" << std::endl;
        return;
    }
    #ifdef DEBUGFILEOPEN
    //std::cerr << "Cache::newFD(" << fd << "," << pointer << "," << std::to_string((int)kind) << ")" << std::endl;
    #endif
    //work around bug FD leak or bad FD stuff from this software I think
    if(FDList.find(fd)!=FDList.cend())
    {
        const FDSave &entry=FDList.at(fd);
        switch (entry.kind) {
        case EpollObject::Kind::Kind_Backend:
            std::cerr << "WorkAround bug Backend fd: " << fd << " " << entry.pointer << std::endl;
            static_cast<Backend *>(entry.pointer)->workAroundBug();
            static_cast<Backend *>(entry.pointer)->close();
            break;
        case EpollObject::Kind::Kind_Cache:
            std::cerr << "WorkAround bug Cache fd: " << fd << " " << entry.pointer << std::endl;
            static_cast<Backend *>(entry.pointer)->workAroundBug();
            static_cast<Cache *>(entry.pointer)->close();
            break;
        case EpollObject::Kind::Kind_Client:
            std::cerr << "WorkAround bug Client fd: " << fd << " " << entry.pointer << std::endl;
            static_cast<Backend *>(entry.pointer)->workAroundBug();
            static_cast<Client *>(entry.pointer)->disconnect();
            break;
        case EpollObject::Kind::Kind_Dns:
            std::cerr << "WorkAround bug Dns fd: " << fd << " " << entry.pointer << std::endl;
            break;
        case EpollObject::Kind::Kind_Server:
            std::cerr << "WorkAround bug Server fd: " << fd << " " << entry.pointer << std::endl;
            break;
        case EpollObject::Kind::Kind_ServerTCP:
            std::cerr << "WorkAround bug ServerTCP fd: " << fd << " " << entry.pointer << std::endl;
            break;
        case EpollObject::Kind::Kind_Timer:
            std::cerr << "WorkAround bug Timer fd: " << fd << " " << entry.pointer << std::endl;
            break;
        default:
            break;
        }
    }
    FDSave entry;
    entry.kind=kind;
    entry.pointer=pointer;
    FDList[fd]=entry;
}

void Cache::closeFD(const int &fd)
{
    if(fd<0)
        return;
    #ifdef DEBUGFILEOPEN
    //std::cerr << "Cache::closeFD(" << fd << ")" << std::endl;
    #endif
    FDList.erase(fd);
}
