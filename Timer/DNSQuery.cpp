#include "DNSQuery.hpp"
#include "../Dns.hpp"

DNSQuery::DNSQuery()
{
}

void DNSQuery::exec()
{
    Dns::dns->checkQueries();
}
