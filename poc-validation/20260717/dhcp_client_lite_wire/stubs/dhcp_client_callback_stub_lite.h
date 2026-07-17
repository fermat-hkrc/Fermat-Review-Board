#ifndef DHCP_LITE_WIRE_CALLBACK_STUB_H
#define DHCP_LITE_WIRE_CALLBACK_STUB_H
#include <memory>
#include "i_dhcp_client_callback.h"
namespace OHOS::DHCP {
class DhcpClientCallBackStub {
public:
    int OnRemoteRequest(uint32_t, IpcIo *) { return 0; }
    void RegisterCallBack(const std::shared_ptr<IDhcpClientCallBack> &) {}
};
}
#endif
