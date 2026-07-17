// The proxy and stub are both production translation units.  The in-process
// transport supplies only parcel framing and invokes the real stub.
#include <cstdio>
#include <cstring>
#include <memory>

#include "dhcp_server_callback_proxy.h"
#include "dhcp_server_callback_stub.h"

namespace OHOS::DHCP {
class RecordingCallback final : public IDhcpServerCallBack {
public:
    void OnServerStatusChanged(int) override {}
    void OnServerLeasesChanged(const std::string &, std::vector<std::string> &) override { ++leasesCalls; }
    void OnServerSerExitChanged(const std::string &) override { ++exitCalls; }
    void OnServerSuccess(const std::string &ifname, std::vector<DhcpStationInfo> &stations) override
    {
        called = true;
        observedIfname = ifname;
        observedCount = stations.size();
    }
    bool called = false;
    std::string observedIfname;
    size_t observedCount = 0;
    int leasesCalls = 0;
    int exitCalls = 0;
};
}

int main()
{
    using namespace OHOS::DHCP;
    auto sink = std::make_shared<RecordingCallback>();
    auto stub = std::make_shared<DhcpServreCallBackStub>();
    stub->RegisterCallBack(sink);
    DhcpServerCallbackProxy proxy(stub);

    DhcpStationInfo station {};
    std::strcpy(station.deviceName, "device");
    std::strcpy(station.macAddr, "00:11:22:33:44:55");
    std::strcpy(station.ipAddr, "192.0.2.10");
    std::vector<DhcpStationInfo> stations { station };

    proxy.OnServerSuccess("wlan0", stations);
    std::vector<std::string> leases { "lease" };
    proxy.OnServerLeasesChanged("wlan0", leases);
    proxy.OnServerSerExitChanged("wlan0");
    std::printf("success_callback=%d ifname='%s' station_count=%zu expected_ifname='wlan0' expected_count=1 \
leases_delivered=%d exit_delivered=%d expected_each=1\n", sink->called ? 1 : 0, sink->observedIfname.c_str(),
        sink->observedCount, sink->leasesCalls, sink->exitCalls);
    return sink->called && sink->observedIfname == "wlan0" && sink->observedCount == 1 &&
        sink->leasesCalls == 1 && sink->exitCalls == 1 ? 1 : 0;
}
