#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#define private public
#include "/home/cupcup/data/openharmony-data/repos/communication_dhcp/services/dhcp_client/include/dhcp_client_state_machine.h"
#undef private

#include "/home/cupcup/data/openharmony-data/repos/communication_dhcp/services/dhcp_client/src/dhcp_client_state_machine.cpp"

namespace OHOS::DHCP {
class DhcpThread::DhcpThreadImpl {};

DhcpThread::DhcpThread(const std::string&) : ptr_(nullptr) {}
DhcpThread::~DhcpThread() = default;

std::string IntIpv4ToAnonymizeStr(uint32_t)
{
    return "0.0.0.0";
}

int64_t GetElapsedSecondsSinceBoot()
{
    return 0;
}
}

namespace {
DhcpPacket capturedPacket {};
bool packetCaptured = false;
}

bool MacChConToMacStr(const unsigned char *, size_t, char *value, size_t valueLength)
{
    if (value == nullptr || valueLength < 2) return false;
    value[0] = '0';
    value[1] = '\0';
    return true;
}

extern "C" int SendToDhcpPacket(const struct DhcpPacket *packet, uint32_t, uint32_t, int, const uint8_t *)
{
    capturedPacket = *packet;
    packetCaptured = true;
    return 0;
}

extern "C" int GetParameter(const char *, const char *, char *, int)
{
    return 0;
}

extern "C" int RunDeclineScenario()
{
    OHOS::DHCP::DhcpClientStateMachine state("test0");
    for (size_t index = 0; index < MAC_ADDR_LEN; ++index) {
        state.m_cltCnf.ifaceMac[index] = static_cast<unsigned char>(index + 1);
    }
    state.m_cltCnf.ifaceIndex = 1;
    return state.DhcpDecline(0x10203040, 0x0a000002, 0x0a000001);
}

extern "C" int CountCapturedOption(uint8_t requestedCode)
{
    if (!packetCaptured) return -1;
    int count = 0;
    for (int index = 0; index < DHCP_OPT_SIZE;) {
        const uint8_t code = capturedPacket.options[index];
        if (code == END_OPTION) break;
        if (code == PAD_OPTION) {
            ++index;
            continue;
        }
        if (index + DHCP_OPT_LEN_INDEX >= DHCP_OPT_SIZE) return -1;
        const uint8_t length = capturedPacket.options[index + DHCP_OPT_LEN_INDEX];
        if (code == requestedCode) ++count;
        index += DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + length;
    }
    return count;
}
