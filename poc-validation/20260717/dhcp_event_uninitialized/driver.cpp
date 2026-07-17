// The driver deliberately calls the public callback implementation.  It does
// not include or reproduce any production function body.
#include <cstdio>
#include <string>

#include "dhcp_event.h"

namespace {
void ReceiveDhcpResult(int status, const char *ifname, DhcpResult *result)
{
    // Reading this field is the observable application-side operation.  MSan
    // must report the first read before this print succeeds.
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

    // Real entry point: a successful DHCP lease notification reaches the
    // production copy routine and then the registered application callback.
    callback.OnIpSuccessChanged(0, "wlan0", result);
    return 0;
}
