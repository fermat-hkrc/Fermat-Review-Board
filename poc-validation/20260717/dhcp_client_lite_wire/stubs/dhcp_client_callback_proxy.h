#ifndef DHCP_LITE_WIRE_CALLBACK_PROXY_H
#define DHCP_LITE_WIRE_CALLBACK_PROXY_H
#include "i_dhcp_client_callback.h"
namespace OHOS::DHCP {
class DhcpClientCallbackProxy final : public IDhcpClientCallBack {
public:
    explicit DhcpClientCallbackProxy(SvcIdentity *) {}
    void OnIpSuccessChanged(int, const std::string &, DhcpResult &) override {}
    void OnIpFailChanged(int, const std::string &, const std::string &) override {}
};
}
#endif
