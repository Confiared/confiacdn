#include "CleanOldCache.hpp"
#include "../Backend.hpp"
#include "Common.hpp"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

CleanOldCache::CleanOldCache() :
    lastCleanTime(0),
    d(NULL)
{
}

/// \todo be more agressive when partition is full, remove smaller by Bytes/time from last access?
//exec each 1s to remove each 1s to remove
void CleanOldCache::exec()
{
    #ifndef CURL
    const uint64_t &currentTime=Common::msFrom1970()/1000;
    //check each 1h
    if((lastCleanTime+3600)>currentTime)
    {
        if(lastCleanTime>currentTime)
        {
            //fix time drift
            lastCleanTime=currentTime;
        }
        return;
    }
    if(d!=NULL)
    {
        struct dirent *dir;
        if ((dir = readdir(d)) != NULL)
        {
            if(dir->d_name[0]!='.')
            {
                struct stat sb;
                if(stat(dir->d_name, &sb) != -1)
                {
                    //remove file not read from CDN since lot of time (each CDN read should do a write to modify access time store into file)
                    if(sb.st_size<1000000)
                    {
                        if((uint64_t)sb.st_mtim.tv_sec<(currentTime-7*24*3600))
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << "remove old cache: " << dir->d_name << " " << sb.st_mtim.tv_sec << "<" << currentTime << std::endl;
                            #endif
                            ::unlink(dir->d_name);
                        }
                    }
                    else
                    {
                        if((uint64_t)sb.st_mtim.tv_sec<(currentTime-31*24*3600))
                        {
                            #ifdef DEBUGFASTCGI
                            std::cerr << "remove old cache: " << dir->d_name << " " << sb.st_mtim.tv_sec << "<" << currentTime << std::endl;
                            #endif
                            ::unlink(dir->d_name);
                        }
                    }
                }
            }
        }
        else
        {
            closedir(d);
            d=NULL;
            lastCleanTime=currentTime;
        }
    }
    else
        d = opendir(".");
    #endif
}
