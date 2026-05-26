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
language: C
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

---

