#ifndef CleanOldCache_H
#define CleanOldCache_H

#include "../Timer.hpp"
#include <dirent.h>

class CleanOldCache : public Timer
{
public:
    CleanOldCache();
    void exec();
private:
    uint64_t lastCleanTime;
    DIR *d;
};

#endif // CleanOldCache_H
