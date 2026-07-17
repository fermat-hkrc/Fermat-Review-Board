// Exercises the public production success callback.  build.sh uses a fixed
// auto-variable initialization pattern only to make the omitted initialization
// observable; the callback and conversion implementation remain production code.
#include <cstdio>
#include <string>

#include "dhcp_event.h"

namespace {
void ReceiveDhcpResult(int status, const char *ifname, DhcpResult *result)
{
    const volatile std::uint32_t dnsCount = result->dnsList.dnsNumber;
    std::printf("callback status=%d ifname=%s dnsCount=%u\n", status, ifname, dnsCount);
}
}

int main()
{
    DhcpClientCallBack callback;
    const ClientCallBack appCallback { ReceiveDhcpResult, nullptr };
    callback.RegisterCallBack("wlan0", &appCallback);

    OHOS::DHCP::DhcpResult result;
    result.vectorDnsAddr.emplace_back("8.8.8.8");
    callback.OnIpSuccessChanged(0, "wlan0", result);
    return 0;
}
