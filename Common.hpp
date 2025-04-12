#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <stdint.h>

class Common
{
public:
    Common();
    static inline uint8_t hexToDecUnit(const char& c, bool &ok);
    static std::string hexaToBinary(const std::string &hexa);
    static std::string binarytoHexa(const char * const data, const uint32_t &size);
    static void binarytoHexaC64Bits(const char * const source, char * const destination);
    static void binarytoHexaC32Bits(const char * const source, char * const destination);
    static uint64_t hexaTo64Bits(const std::string &hexa);
    static uint64_t msFrom1970();
};

#endif // COMMON_H
