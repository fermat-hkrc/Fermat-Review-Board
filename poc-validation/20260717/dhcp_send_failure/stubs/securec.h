#ifndef DHCP_SEND_FAILURE_POC_SECUREC_H
#define DHCP_SEND_FAILURE_POC_SECUREC_H

#include <cstring>

#define EOK 0

static inline int memset_s(void *dest, size_t destMax, int value, size_t count)
{
    if (dest == nullptr || count > destMax) return -1;
    std::memset(dest, value, count);
    return EOK;
}

static inline int memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == nullptr || src == nullptr || count > destMax) return -1;
    std::memcpy(dest, src, count);
    return EOK;
}

static inline int strncpy_s(char *dest, size_t destMax, const char *src, size_t count)
{
    if (dest == nullptr || src == nullptr || count >= destMax) return -1;
    std::memcpy(dest, src, count);
    dest[count] = '\0';
    return EOK;
}

#endif
