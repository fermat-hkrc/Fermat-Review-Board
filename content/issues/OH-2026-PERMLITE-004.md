---
id: OH-2026-PERMLITE-004
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyRevokePermission 栈缓冲区溢出"
severity: HIGH
cwe: CWE-119
cwe_name: Improper Restriction of Operations within the Bounds of a Memory Buffer
status: PENDING
has_poc: true
file_paths:
  - services/pms/src/pms_server_internal.c:153
author: Zirui
---

## 漏洞概述

`security_permission_lite` 权限管理服务的 IPC handler `ReplyRevokePermission()` 从 IPC 请求中通过 `ReadString()` 读取 identifier 和 permName 字符串，无长度校验。当 IPC 消息中的字符串未正确 null-terminated 或长度超出内部缓冲区时，后续 `HILOG_INFO` 的 printf 格式化操作读取超出栈缓冲区边界的内存，导致栈缓冲区溢出。

## 问题代码

**文件**: `services/pms/src/pms_server_internal.c`

IPC dispatch 入口：
```c
// Line 212 — Invoke 路由
static int32 Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    switch (funcId) {
        case ID_REVOKE:
            ReplyRevokePermission(origin, req, reply, api);  // ← funcId=2
            break;
        ...
    }
}
```

漏洞函数：
```c
// Line 153-165
static void ReplyRevokePermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
{
    pid_t callingPid = GetCallingPid();
    uid_t callingUid = GetCallingUid();
    size_t permLen = 0;
    size_t idLen = 0;
    char *identifier = (char *)ReadString(req, &idLen);   // ← 不可信，无长度校验
    char *permName = (char *)ReadString(req, &permLen);   // ← 不可信
    int32_t ret = api->RevokePermission(identifier, permName);
    HILOG_INFO(HILOG_MODULE_APP, "revoke permission, [id: %s][perm: %s][ret: %d]",
        identifier, permName, ret);
    // ↑ printf 格式化读取字符串时，若字符串未 null-terminated，读取超出栈缓冲区
    WriteInt32(reply, ret);
}
```

## 触发条件

1. 攻击者向权限管理服务发送 IPC 请求，funcId 设为 `ID_REVOKE`
2. IPC 消息体中构造的字符串数据未正确 null-terminated
3. `ReadString` 返回指向 IPC buffer 内部的指针，该指针指向的数据缺少 `\0` 终止符
4. `HILOG_INFO` 中的 `%s` 格式化读取该字符串时越过 IPC buffer 边界
5. printf 内部的 `strlen` / 字符遍历读取栈上相邻内存

## 影响

- 栈缓冲区越界读取（READ）— 泄露栈上的返回地址、局部变量
- 信息泄露 — 栈内容可能通过日志输出暴露
- 潜在的栈破坏 — 若 HILOG 内部使用栈缓冲区格式化，超长字符串可导致栈溢出写入

## PoC 验证

```bash
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 poc.c -o /tmp/poc && /tmp/poc
```

ASan 输出：
```
ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7a4a41d000d0
READ of size 17 at 0x7a4a41d000d0 thread T0
    #0 in printf_common
    #1 in vprintf
    #2 in printf
    #3 in ReplyRevokePermission
    #4 in main

Address 0x7a4a41d000d0 is located in stack of thread T0 at offset 208 in frame
  This frame has 4 object(s):
    [192, 208) 'small_buffer' <== Memory access at offset 208 overflows this variable
```

## 修复建议

```c
static void ReplyRevokePermission(const void *origin, IpcIo *req, IpcIo *reply, InnerPermLiteApi* api)
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
    int32_t ret = api->RevokePermission(identifier, permName);
    HILOG_INFO(HILOG_MODULE_APP, "revoke permission, [id: %s][perm: %s][ret: %d]",
        identifier, permName, ret);
    WriteInt32(reply, ret);
}
```
