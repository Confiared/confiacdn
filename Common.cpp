#include "Common.hpp"

static const char* const lut = "0123456789ABCDEF";

Common::Common()
{
}

uint8_t Common::hexToDecUnit(const char& c, bool &ok)
{
    if(c<48)
    {
        ok=false;
        return 0;
    }
    if(c<=57)
    {
        ok=true;
        return c-48;
    }
    if(c<65)
    {
        ok=false;
        return 0;
    }
    if(c<=70)
    {
        ok=true;
        return c-65+10;
    }
    if(c<97)
    {
        ok=false;
        return 0;
    }
    if(c<=102)
    {
        ok=true;
        return c-(uint8_t)97+10;
    }
    ok=false;
    return 0;
}

std::string Common::hexaToBinary(const std::string &hexa)
{
    if(hexa.size()%2!=0)
        return std::string();
    std::string r;
    r.resize(hexa.size()/2);
    unsigned int index=0;
    while(index<r.size())
    {
        bool ok=true;
        const uint8_t c1=hexToDecUnit(hexa.at(index*2),ok);
        if(!ok)
            return std::string();
        const uint8_t c2=hexToDecUnit(hexa.at(index*2+1),ok);
        if(!ok)
            return std::string();
        r[index]=c1*16+c2;
        index++;
    }
    return r;
}

uint64_t Common::hexaTo64Bits(const std::string &hexa)
{
    char * pEnd=nullptr;
    const char * d=hexa.c_str();
    return strtoull(d,&pEnd,16);
}

std::string Common::binarytoHexa(const char * const data, const uint32_t &size)
{
    std::string output;
    //output.reserve(2*size);
    for(size_t i=0;i<size;++i)
    {
        const unsigned char c = data[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

void Common::binarytoHexaC64Bits(const char * const source, char * const destination)
{
    for(size_t i=0;i<8;++i)
    {
        const unsigned char c = source[i];
        destination[i*2]=lut[c >> 4];
        destination[i*2+1]=lut[c & 15];
    }
}

void Common::binarytoHexaC32Bits(const char * const source, char * const destination)
{
    for(size_t i=0;i<4;++i)
    {
        const unsigned char c = source[i];
        destination[i*2]=lut[c >> 4];
        destination[i*2+1]=lut[c & 15];
    }
}
