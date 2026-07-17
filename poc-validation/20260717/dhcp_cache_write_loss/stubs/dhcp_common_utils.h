#ifndef DHCP_CACHE_POC_COMMON_UTILS_H
#define DHCP_CACHE_POC_COMMON_UTILS_H
#include <string>
namespace OHOS::DHCP {
constexpr int DECIMAL_NOTATION = 10;
int CheckDataLegal(const std::string &data, int base = DECIMAL_NOTATION);
bool IsValidPath(const std::string &filePath);
}
#endif
