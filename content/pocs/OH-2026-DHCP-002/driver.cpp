// The production proxy and production stub are compiled separately.
// This driver supplies only an in-process parcel endpoint and records
// what the registered callback receives.
#include <cstdio>
#include <cstring>
#include <memory>

#include "dhcp_server_callback_proxy.h"
#include "dhcp_server_callback_stub.h"

namespace OHOS::DHCP {
class RecordingCallback final : public IDhcpServerCallBack {
public:
    void OnServerStatusChanged(int) override {}
    void OnServerLeasesChanged(const std::string&, std::vector<std::string>&) override {}
    void OnServerSerExitChanged(const std::string&) override {}
    void OnServerSuccess(const std::string& ifname, std::vector<DhcpStationInfo>& stations) override
    {
        called = true;
        observedIfname = ifname;
        observedCount = stations.size();
    }

    bool called = false;
    std::string observedIfname;
    size_t observedCount = 0;
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
    std::printf(
        "success_callback=%d ifname='%s' station_count=%zu expected_ifname='wlan0' expected_count=1\n",
        sink->called ? 1 : 0, sink->observedIfname.c_str(), sink->observedCount);

    return sink->called && sink->observedIfname == "wlan0" && sink->observedCount == 1 ? 1 : 0;
}
