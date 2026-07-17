#ifndef NFC_POC_CALLBACK_HPP
#define NFC_POC_CALLBACK_HPP
#include "platform_stub.hpp"
namespace OHOS::NFC {
class INfcTagCallback : public OHOS::IRemoteBroker {
public:
    virtual ~INfcTagCallback() = default;
    virtual OHOS::sptr<OHOS::IRemoteObject> AsObject() { return nullptr; }
};
}
#endif
