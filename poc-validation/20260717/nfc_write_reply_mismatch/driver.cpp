// This driver calls the production proxy, which calls the production stub
// through a minimal in-process IPC transport.  It does not reproduce either
// production method body.
#include <cstdio>
#include <string>

#include "nfc_tag_proxy.h"
#include "nfc_tag_stub.h"

namespace OHOS::NFC {
class TestTagService final : public NfcTagStub {
public:
    ErrCode Init() override { return NFC_SUCCESS; }
    ErrCode Uninit() override { return NFC_SUCCESS; }
    ErrCode ReadNdefTag(std::string &) override { return NFC_SUCCESS; }
    ErrCode WriteNdefTag(const std::string &) override { return NFC_SUCCESS; }
    ErrCode ReadNdefData(std::vector<uint8_t> &) override { return NFC_SUCCESS; }
    ErrCode WriteNdefData(const std::vector<uint8_t> &) override { return NFC_SUCCESS; }
    ErrCode RegListener(const sptr<INfcTagCallback> &) override { return NFC_SUCCESS; }
    ErrCode UnregListener(const sptr<INfcTagCallback> &) override { return NFC_SUCCESS; }
};
}

int main()
{
    auto service = std::make_shared<OHOS::NFC::TestTagService>();
    OHOS::NFC::NfcTagProxy proxy(service);
    const auto result = proxy.WriteNdefTag("abc");
    std::printf("service_result=%d proxy_result=%d expected=%d\n", OHOS::NFC::NFC_SUCCESS,
        static_cast<int>(result), OHOS::NFC::NFC_SUCCESS);
    return result == OHOS::NFC::NFC_SUCCESS ? 1 : 0;
}
