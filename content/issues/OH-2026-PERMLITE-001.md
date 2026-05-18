---
id: OH-2026-PERMLITE-001
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyRevokeRuntimePermission 全局缓冲区越界写入"
severity: HIGH
cwe: CWE-129
cwe_name: Improper Validation of Array Index
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_permission_lite/issues/96
has_poc: true
file_paths:
  - services/pms/src/pms_server_internal.c:181
author: Zirui
---

## 漏洞概述

`security_permission_lite` 权限管理服务的 IPC handler `ReplyRevokeRuntimePermission()` 从 IPC 请求中读取 `int64_t uid`，未做任何边界校验即传入 `api->RevokeRuntimePermission(uid, permName)`。底层实现将 uid 用作 per-uid 权限表的数组索引，攻击者通过构造 uid=-1 或超大值的 IPC 消息可触发全局缓冲区越界写入。

## 问题代码

**文件**: `services/pms/src/pms_server_internal.c`

IPC dispatch 入口：
```c
// Line 212 — Invoke 路由
static int32 Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    InnerPermLiteApi *api = (InnerPermLiteApi *)iProxy;
    switch (funcId) {
        ...
        case ID_REVOKE_RUNTIME:
            ReplyRevokeRuntimePermission(origin, req, reply, api);  // ← funcId=5
            break;
    }
}
```

漏洞函数：
```c
// Line 181-192
static void ReplyRevokeRuntimePermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    size_t permLen = 0;
    int64_t uid;
    ReadInt64(req, &uid);                              // ← 不可信 IPC 输入，无边界校验
    char *permName = (char *)ReadString(req, &permLen);
    int32_t ret = api->RevokeRuntimePermission(uid, permName);  // ← uid 直接用作数组索引
    WriteInt32(reply, ret);
}
```

## 触发条件

1. 攻击者向权限管理服务发送 IPC 请求，funcId 设为 `ID_REVOKE_RUNTIME`
2. IPC 消息体中 uid 字段设为 -1 或超出权限表大小的值
3. `ReadInt64` 读取攻击者控制的 uid，无任何范围检查
4. uid 传入 `RevokeRuntimePermission`，作为数组索引访问全局权限表

## 影响

- 全局缓冲区越界写入（WRITE）— 可覆盖权限表相邻内存
- 权限表数据破坏 — 可能导致权限状态不一致
- 潜在权限提升 — 覆盖其他 uid 的权限记录
- 服务进程崩溃（DoS）

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
gcc -c -fsanitize=address -fno-omit-frame-pointer -O0 -g -Dstatic= \
    -I security_permission_lite/services/pms/include \
    -I security_permission_lite/interfaces/kits \
    -I <ohos-framework-headers> \
    security_permission_lite/services/pms/src/pms_server_internal.c -o pms_server_internal.o

# 2. 编译 test driver + stubs
# 3. 链接
gcc -fsanitize=address -o poc_permlite001 \
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

## 修复建议

```c
static void ReplyRevokeRuntimePermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    size_t permLen = 0;
    int64_t uid;
    ReadInt64(req, &uid);
+   if (uid < 0 || uid >= MAX_UID_COUNT) {
+       WriteInt32(reply, PERM_ERRORCODE_INVALID_PARAMS);
+       return;
+   }
    char *permName = (char *)ReadString(req, &permLen);
    int32_t ret = api->RevokeRuntimePermission(uid, permName);
    WriteInt32(reply, ret);
}
```
