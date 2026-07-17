#ifndef DHCP_POC_SECUREC_H
#define DHCP_POC_SECUREC_H

#include <cstddef>
#include <cstring>

using errno_t = int;
constexpr errno_t EOK = 0;
constexpr errno_t SECUREC_RANGE_ERROR = 34;

inline errno_t strcpy_s(char *destination, std::size_t destinationSize, const char *source)
{
    if (destination == nullptr || source == nullptr || destinationSize == 0) {
        return SECUREC_RANGE_ERROR;
    }
    const std::size_t length = std::strlen(source);
    if (length >= destinationSize) {
        destination[0] = '\0';
        return SECUREC_RANGE_ERROR;
    }
    std::memcpy(destination, source, length + 1);
    return EOK;
}

inline errno_t strncpy_s(char *destination, std::size_t destinationSize, const char *source, std::size_t count)
{
    if (destination == nullptr || source == nullptr || destinationSize == 0 || count >= destinationSize) {
        if (destination != nullptr && destinationSize != 0) {
            destination[0] = '\0';
        }
        return SECUREC_RANGE_ERROR;
    }
    std::memcpy(destination, source, count);
    destination[count] = '\0';
    return EOK;
}

#endif
