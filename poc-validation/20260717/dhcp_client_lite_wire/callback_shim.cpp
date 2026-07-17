// Platform callback transport is outside this request path.  These minimal
// definitions satisfy the production proxy's static callback object while the
// exercised StartDhcpClient path uses the production proxy and server stub.
#include "/home/cupcup/data/openharmony-data/repos/communication_dhcp/frameworks/native/src/dhcp_client_callback_stub_lite.h"
#include "dhcp_client_proxy.h"

namespace OHOS::DHCP {
DhcpClientCallBackStub::DhcpClientCallBackStub() : callback_(nullptr), mRemoteDied(false) {}
DhcpClientCallBackStub::~DhcpClientCallBackStub() = default;
int DhcpClientCallBackStub::OnRemoteRequest(uint32_t, IpcIo *) { return DHCP_E_SUCCESS; }
void DhcpClientCallBackStub::RegisterCallBack(const std::shared_ptr<IDhcpClientCallBack> &callback) { callback_ = callback; }
bool DhcpClientCallBackStub::IsRemoteDied() const { return mRemoteDied; }
void DhcpClientCallBackStub::SetRemoteDied(bool value) { mRemoteDied = value; }
void DhcpClientCallBackStub::OnIpSuccessChanged(int, const std::string &, DhcpResult &) {}
void DhcpClientCallBackStub::OnIpFailChanged(int, const std::string &, const std::string &) {}
int DhcpClientCallBackStub::OnRemoteInterfaceToken(uint32_t, IpcIo *) { return DHCP_E_SUCCESS; }
int DhcpClientCallBackStub::RemoteOnIpSuccessChanged(uint32_t, IpcIo *) { return DHCP_E_SUCCESS; }
int DhcpClientCallBackStub::RemoteOnIpFailChanged(uint32_t, IpcIo *) { return DHCP_E_SUCCESS; }

bool DhcpClientProxy::IsRemoteDied() { return remoteDied_; }
ErrCode DhcpClientProxy::StopClientSa() { return DHCP_E_SUCCESS; }
}
