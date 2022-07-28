#include "DNSCache.hpp"
#include "../Dns.hpp"
#include <iostream>

DNSCache::DNSCache()
{
}

void DNSCache::exec()
{
    //std::cout << "Clean DNS cache" << std::endl;
    Dns::dns->cleanCache();
}
