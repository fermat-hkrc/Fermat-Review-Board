#ifndef DHCP_DECLINE_POC_HILOG_H
#define DHCP_DECLINE_POC_HILOG_H

#include <cstdint>

enum LogType { LOG_CORE = 0 };
namespace OHOS::HiviewDFX {
struct HiLogLabel { LogType type; std::uint32_t domain; const char *tag; };
class HiLog {
public:
    template <typename... Args> static int Debug(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Info(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Warn(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Error(const HiLogLabel &, const char *, Args...) { return 0; }
};
}

#endif
