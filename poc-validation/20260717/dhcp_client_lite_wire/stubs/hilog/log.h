#ifndef DHCP_LITE_WIRE_HILOG_H
#define DHCP_LITE_WIRE_HILOG_H
#include <cstdint>
enum LogType { LOG_CORE = 0 };
namespace OHOS::HiviewDFX {
struct HiLogLabel { LogType type; std::uint32_t domain; const char *tag; };
class HiLog {
public:
    template <typename... A> static int Debug(const HiLogLabel &, const char *, A...) { return 0; }
    template <typename... A> static int Info(const HiLogLabel &, const char *, A...) { return 0; }
    template <typename... A> static int Warn(const HiLogLabel &, const char *, A...) { return 0; }
    template <typename... A> static int Error(const HiLogLabel &, const char *, A...) { return 0; }
};
}
#endif
