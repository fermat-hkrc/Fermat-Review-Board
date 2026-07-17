// Calls production Lite proxy and production Lite server stub through the
// small in-process transport below.  The server records actual start calls.
#include <cstdio>
#include <memory>

#define private public
#include "dhcp_client_proxy.h"
#undef private
#include "dhcp_client_stub_lite.h"
#include "dhcp_manager_service_ipc_interface_code.h"

namespace OHOS::DHCP {
class TestServerStub final : public DhcpClientStub {
public:
    ErrCode RegisterDhcpClientCallBack(const std::string &, const std::shared_ptr<IDhcpClientCallBack> &) override
    { return DHCP_E_SUCCESS; }
    ErrCode StartDhcpClient(const RouterConfig &) override { ++startCalls; return DHCP_E_SUCCESS; }
    ErrCode DealWifiDhcpCache(int32_t, const IpCacheInfo &) override { return DHCP_E_SUCCESS; }
    ErrCode StopDhcpClient(const std::string &, bool, bool) override { return DHCP_E_SUCCESS; }
    ErrCode StopClientSa() override { return DHCP_E_SUCCESS; }
    bool IsRemoteDied() override { return false; }
    int startCalls = 0;
};
}

namespace {
OHOS::DHCP::TestServerStub *g_server = nullptr;

int Invoke(IClientProxy *remote, int funcId, IpcIo *request, void *owner,
    int (*notify)(void *, int, IpcIo *))
{
    (void)remote;
    IpcIo reply;
    IpcIoInit(&reply, nullptr, 0, 0);
    g_server->OnRemoteRequest(static_cast<uint32_t>(funcId), request, &reply);
    notify(owner, 0, &reply);
    return 0;
}
}

int main()
{
    using namespace OHOS::DHCP;
    TestServerStub server;
    g_server = &server;
    IClientProxy remote { Invoke };
    DhcpClientProxy proxy;
    proxy.remote_ = &remote;

    RouterConfig config {};
    config.ifname = "wlan0";
    config.bssid = "00:11:22:33:44:55";
    const ErrCode result = proxy.StartDhcpClient(config);
    std::printf("proxy_result=%d server_start_calls=%d expected_result=0 expected_calls=1\n",
        static_cast<int>(result), server.startCalls);
    return result == DHCP_E_SUCCESS && server.startCalls == 1 ? 1 : 0;
}
