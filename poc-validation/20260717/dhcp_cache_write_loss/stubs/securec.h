#ifndef DHCP_CACHE_POC_SECUREC_H
#define DHCP_CACHE_POC_SECUREC_H
#include <cstring>
#define EOK 0
static inline int strcpy_s(char *dest, size_t destMax, const char *src)
{
    if (dest == nullptr || src == nullptr || std::strlen(src) + 1 > destMax) return -1;
    std::strcpy(dest, src);
    return EOK;
}
#endif
