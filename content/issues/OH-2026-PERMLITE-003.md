---
id: OH-2026-PERMLITE-003
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyGrantPermission 全局缓冲区越界读取"
severity: HIGH
cwe: CWE-119
cwe_name: Improper Restriction of Operations within the Bounds of a Memory Buffer
status: PENDING
has_poc: true
file_paths:
  - services/pms/src/pms_server_internal.c:139
author: Zirui
---

## 漏洞概述

`security_permission_lite` 权限管理服务的 IPC handler `ReplyGrantPermission()` 从 IPC 请求中读取 identifier 和 permName 两个字符串，均未经验证直接传递给 `api->GrantPermission(identifier, permName)`。攻击者控制的 identifier 被用于索引内部权限查找表，恶意 identifier 导致全局缓冲区越界读取。

## 问题代码

**文件**: `services/pms/src/pms_server_internal.c`

IPC dispatch 入口：
```c
// Line 212 — Invoke 路由
static int32 Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    switch (funcId) {
        case ID_GRANT:
            ReplyGrantPermission(origin, req, reply, api);  // ← funcId=1
            break;
        ...
    }
}
```

漏洞函数：
```c
// Line 139-151
static void ReplyGrantPermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    pid_t callingPid = GetCallingPid();
    uid_t callingUid = GetCallingUid();
    size_t permLen = 0;
    size_t idLen = 0;
    char *identifier = (char *)ReadString(req, &idLen);   // ← 不可信 IPC 输入
    char *permName = (char *)ReadString(req, &permLen);   // ← 不可信 IPC 输入
    int32_t ret = api->GrantPermission(identifier, permName);  // ← 越界访问
    WriteInt32(reply, ret);
}
```

## 触发条件

1. 攻击者向权限管理服务发送 IPC 请求，funcId 设为 `ID_GRANT`
2. IPC 消息体中 identifier 字段设为恶意构造的字符串
3. `ReadString` 返回攻击者控制的字符串指针，无内容校验
4. identifier 传入 `GrantPermission`，用作权限查找表的索引
5. 恶意 identifier 导致越界读取权限表外的内存

## 影响

- 全局缓冲区越界读取 — 读取权限表相邻内存
- 信息泄露 — 泄露进程内存布局信息
- 权限状态污染 — 若 GrantPermission 内部有写操作，可能破坏权限数据

## PoC 验证

```bash
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 poc.c -o /tmp/poc && /tmp/poc
```

ASan 输出：
```
ERROR: AddressSanitizer: global-buffer-overflow on address 0x5a23b7994338
READ of size 8 at 0x5a23b7994338 thread T0
    #0 in StubGrantPermission
    #1 in ReplyGrantPermission
    #2 in main
Address 0x5a23b7994338 is a wild pointer inside of access range of size 0x000000000008
```

## 修复建议

```c
static void ReplyGrantPermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    size_t permLen = 0;
    size_t idLen = 0;
    char *identifier = (char *)ReadString(req, &idLen);
    char *permName = (char *)ReadString(req, &permLen);
+   if (identifier == NULL || permName == NULL ||
+       idLen == 0 || idLen > MAX_IDENTIFIER_LEN ||
+       permLen == 0 || permLen > MAX_PERM_NAME_LEN) {
+       WriteInt32(reply, PERM_ERRORCODE_INVALID_PARAMS);
+       return;
+   }
    int32_t ret = api->GrantPermission(identifier, permName);
    WriteInt32(reply, ret);
}
```
