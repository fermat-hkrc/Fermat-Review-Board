#ifndef DHCP_NETWORK_ORDER_POC_SECUREC_H
#define DHCP_NETWORK_ORDER_POC_SECUREC_H

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdarg>
using errno_t = int;
constexpr errno_t EOK = 0;
constexpr errno_t SECUREC_RANGE_ERROR = 34;

inline errno_t memcpy_s(void *destination, std::size_t destinationSize, const void *source, std::size_t count)
{
    if (destination == nullptr || source == nullptr || count > destinationSize) return SECUREC_RANGE_ERROR;
    std::memcpy(destination, source, count);
    return EOK;
}
inline errno_t memset_s(void *destination, std::size_t destinationSize, int value, std::size_t count)
{
    if (destination == nullptr || count > destinationSize) return SECUREC_RANGE_ERROR;
    std::memset(destination, value, count);
    return EOK;
}
inline int sprintf_s(char *destination, std::size_t destinationSize, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    const int ret = std::vsnprintf(destination, destinationSize, format, args);
    va_end(args);
    return ret;
}
#endif
