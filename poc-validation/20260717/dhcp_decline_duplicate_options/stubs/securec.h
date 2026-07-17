#ifndef DHCP_DECLINE_POC_SECUREC_H
#define DHCP_DECLINE_POC_SECUREC_H

#include <cstdarg>
#include <cstdio>
#include <cstring>

#define EOK 0

extern "C" int GetParameter(const char *, const char *, char *, int);

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

static inline int strncat_s(char *dest, size_t destMax, const char *src, size_t count)
{
    if (dest == nullptr || src == nullptr) return -1;
    const size_t current = std::strlen(dest);
    if (current + count >= destMax) return -1;
    std::memcpy(dest + current, src, count);
    dest[current + count] = '\0';
    return EOK;
}

static inline int snprintf_s(char *dest, size_t destMax, size_t count, const char *format, ...)
{
    if (dest == nullptr || format == nullptr || count >= destMax) return -1;
    va_list args;
    va_start(args, format);
    const int result = std::vsnprintf(dest, count + 1, format, args);
    va_end(args);
    return result;
}

#endif
