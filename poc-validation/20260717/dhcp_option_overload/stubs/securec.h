#ifndef DHCP_OPTION_POC_SECUREC_H
#define DHCP_OPTION_POC_SECUREC_H

#include <cstddef>
#include <cstring>
using errno_t = int;
constexpr errno_t EOK = 0;
constexpr errno_t SECUREC_RANGE_ERROR = 34;

inline errno_t memcpy_s(void *destination, std::size_t destinationSize, const void *source, std::size_t count)
{
    if (destination == nullptr || source == nullptr || count > destinationSize) {
        return SECUREC_RANGE_ERROR;
    }
    std::memcpy(destination, source, count);
    return EOK;
}
#endif
