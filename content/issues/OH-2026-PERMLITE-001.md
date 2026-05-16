---
id: OH-2026-PERMLITE-001
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyRevokeRuntimePermission 全局缓冲区越界写入"
cwe: CWE-129
cwe_name: Improper Validation of Array Index
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_permission_lite/issues/96
has_poc: true
file_paths:
  - pms_server_internal.c:181
author: Zirui
---

## ReplyRevokeRuntimePermission 全局缓冲区越界写入

ReplyRevokeRuntimePermission — 全局缓冲区越界写入

**Finding ID:** FERMAT-c073dd3aa275
**文件:** `services/pms/src/pms_server_internal.c:181`
**CWE:** CWE-129 (Improper Validation of Array Index)

#### 漏洞原理

`ReplyRevokeRuntimePermission()` 从 IPC 请求中通过 `ReadInt64(req, &uid)` 读取一个 `int64_t uid`，没有任何边界校验。该 uid 直接传递给 `api->RevokeRuntimePermission(uid, permName)`。如果底层实现将 uid 作为数组索引访问 per-uid 权限表，攻击者可以通过构造 uid=-1 或超大值的 IPC 消息，导致越界内存写入。

#### 漏洞代码

```c
// pms_server_internal.c:186-190
int64_t uid;
ReadInt64(req, &uid);                              // ← 不可信 IPC 输入，无校验
char *permName = (char *)ReadString(req, &permLen);
int32_t ret = api->RevokeRuntimePermission(uid, permName);  // ← uid 用作数组索引
```

#### 触发路径

```
恶意 IPC Client → ReplyRevokeRuntimePermission() → api->RevokeRuntimePermission(uid=-1, ...) → 越界写入
```

#### PoC 复现方法

**PoC 文件:** `poc_FERMAT-c073dd3aa275.c`

```bash
# 1. 编译 (使用 ASan 检测内存错误)
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    ~/data/output/2026.05.15/poc_FERMAT-c073dd3aa275.c \
    -o /tmp/poc_c073dd3a

# 2. 运行
/tmp/poc_c073dd3a

# 3. 预期输出 (ASan 报告越界写入):
# ERROR: AddressSanitizer: global-buffer-overflow on address 0x...
# WRITE of size 4 at 0x... thread T0
#     #0 in MockRevokeRuntimePermission
#     #1 in ReplyRevokeRuntimePermission
#     #2 in main
```

