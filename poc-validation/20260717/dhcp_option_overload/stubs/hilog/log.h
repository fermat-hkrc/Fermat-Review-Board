#ifndef DHCP_OPTION_POC_HILOG_LOG_H
#define DHCP_OPTION_POC_HILOG_LOG_H

#include <cstdint>
enum LogType { LOG_APP = 0, LOG_CORE = 1 };
namespace OHOS::HiviewDFX {
struct HiLogLabel { LogType type; std::uint32_t domain; const char *tag; };
class HiLog {
public:
    template <typename... Args> static int Debug(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Info(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Warn(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Error(const HiLogLabel &, const char *, Args...) { return 0; }
    template <typename... Args> static int Fatal(const HiLogLabel &, const char *, Args...) { return 0; }
};
}
#endif
