---
id: OH-2026-PERMLITE-002
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyQueryPermission 全局缓冲区越界读取"
severity: HIGH
cwe: CWE-125
cwe_name: Out-of-bounds Read
status: PENDING
has_poc: true
file_paths:
  - services/pms/src/pms_server.c:124
author: Zirui
---

## 漏洞概述

`security_permission_lite` 权限管理服务的 IPC handler `ReplyQueryPermission()` 从 IPC 请求中读取 identifier 字符串，未经验证直接传递给 `QueryPermissionString()`。该函数将 identifier 用作内部权限存储结构的查找键/索引，攻击者构造恶意 identifier 可触发全局缓冲区越界读取，泄露进程内存。

## 问题代码

**文件**: `services/pms/src/pms_server.c`

IPC dispatch 入口：
```c
// pms_server_internal.c:212 — Invoke 路由
static int32 Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    switch (funcId) {
        case ID_QUERY:
            ReplyQueryPermission(origin, req, reply);  // ← funcId 路由到此
            break;
        ...
    }
}
```

漏洞函数：
```c
// pms_server.c:124-132
static void ReplyQueryPermission(const void *origin, IpcIo *req, IpcIo *reply)
{
    size_t idLen = 0;
    char *identifier = (char *)ReadString(req, &idLen);   // ← 不可信 IPC 输入
    int32_t ret = 0;
    char *jsonStr = QueryPermissionString(identifier, &ret);  // ← 用作查找键，越界读取
    WriteInt32(reply, ret);
    if (jsonStr != NULL) {
        WriteString(reply, jsonStr);
    }
}
```

## 触发条件

1. 攻击者向权限管理服务发送 IPC 请求，funcId 设为 `ID_QUERY`
2. IPC 消息体中 identifier 字段设为恶意构造的字符串（超长或包含特殊值）
3. `ReadString` 返回攻击者控制的字符串，无长度或内容校验
4. identifier 传入 `QueryPermissionString`，用作内部数据结构的索引/键
5. 越界读取的数据通过 `WriteString(reply, jsonStr)` 返回给攻击者

## 影响

- 全局缓冲区越界读取 — 泄露权限表相邻内存内容
- 信息泄露 — 越界读取的数据通过 IPC reply 返回给调用者
- 可用于 ASLR 绕过 — 泄露的地址信息辅助后续利用

## PoC 验证

```bash
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 poc.c -o /tmp/poc && /tmp/poc
```

ASan 输出：
```
ERROR: AddressSanitizer: global-buffer-overflow on address 0x5dbb479c2338
READ of size 8 at 0x5dbb479c2338 thread T0
    #0 in QueryPermissionString
    #1 in ReplyQueryPermission
    #2 in main
Address 0x5dbb479c2338 is a wild pointer inside of access range of size 0x000000000008
```

## 修复建议

```c
static void ReplyQueryPermission(const void *origin, IpcIo *req, IpcIo *reply)
{
    size_t idLen = 0;
    char *identifier = (char *)ReadString(req, &idLen);
+   if (identifier == NULL || idLen == 0 || idLen > MAX_IDENTIFIER_LEN) {
+       WriteInt32(reply, PERM_ERRORCODE_INVALID_PARAMS);
+       return;
+   }
    int32_t ret = 0;
    char *jsonStr = QueryPermissionString(identifier, &ret);
    WriteInt32(reply, ret);
    if (jsonStr != NULL) {
        WriteString(reply, jsonStr);
    }
}
```
