#include "CheckTimeout.hpp"
#include "../Http.hpp"
#include "../Https.hpp"
#include "../Backend.hpp"
#include "../Client.hpp"

CheckTimeout::CheckTimeout()
{
}

void CheckTimeout::exec()
{
    for( const auto &n : Backend::addressToHttp )
        for( Backend * p : n.second->busy )
        {
            if(p!=nullptr)
            {
                #ifdef DEBUGFASTCGI
                /*non sens, can just be disconnected, check data coerancy taking care if connected or not
                if(!p->isValid())
                {
                    std::cerr << (void *)p << " !p->isValid() into busy list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }*/
                /*can be busy but client/http disconnected
                 * if(p->http==nullptr)
                {
                    std::cerr << (void *)p << " p->http==null into busy list, error http (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }*/
                if(p->backendList!=n.second)
                {
                    std::cerr << (void *)p << " p->backendList(" << p->backendList << ")!=n.second(" << n.second << "), link backend error (abort)" << std::endl;
                    abort();
                }
                #endif
                p->detectTimeout();
            }
        }
    for( const auto &n : Backend::addressToHttps )
        for( Backend * p : n.second->busy )
        {
            if(p!=nullptr)
            {
                #ifdef DEBUGFASTCGI
                /*non sens, can just be disconnected, check data coerancy taking care if connected or not
                if(!p->isValid())
                {
                    std::cerr << (void *)p << " !p->isValid() into busy list, error https (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }*/
                /*can be busy but client/http disconnected
                if(p->http==nullptr)
                {
                    std::cerr << (void *)p << " p->http==null into busy list, error https (abort)" << ": " << __FILE__ << ":" << __LINE__ << std::endl;
                    abort();
                }*/
                if(p->backendList!=n.second)
                {
                    std::cerr << (void *)p << " p->backendList(" << p->backendList << ")!=n.second(" << n.second << "), link backend error (abort)" << std::endl;
                    abort();
                }
                #endif
                p->detectTimeout();
            }
        }
    //std::vector<Client *> removeFromClientList;
    for( const auto &n : Client::clients )
    {
        if(n!=nullptr)
        {
            if(n->isValid())
                n->detectTimeout();
            else
            {
                #ifdef DEBUGFASTCGI
                std::cerr << "CheckTimeout::exec() client not valid, disconnect: " << (void *)n << " fd: " << n->getFD() << std::endl;
                #endif
                n->disconnect();
                Client::clientToDelete.insert(n);
                //removeFromClientList.push_back(n);
            }
        }
    }
    /*for( const auto &n : removeFromClientList )
        Client::clients.erase(n); -> generate error of coerancy
            can be not Backend::isValid() after this because Backend::close()  do fd=-1 and Backend::isValid() check this
*/
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Http::pathToHttp;
        for( const auto &n : pathToHttp )
        {
            if(n.second!=nullptr)
                n.second->detectTimeout();
        }
    }
    {
        std::unordered_map<std::string/* example: 29E7336BDEA3327B */,Http *> pathToHttp=Https::pathToHttps;
        for( const auto &n : pathToHttp )
        {
            if(n.second!=nullptr)
                n.second->detectTimeout();
        }
    }
}
