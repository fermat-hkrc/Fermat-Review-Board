---
id: OH-2026-PERMLITE-003
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyGrantPermission 全局缓冲区越界读取"
cwe: CWE-119
cwe_name: Improper Restriction of Operations within the Bounds of a Memory Buffer
status: PENDING
has_poc: true
file_paths:
  - pms_server_internal.c:139
author: Zirui
---

## ReplyGrantPermission 全局缓冲区越界读取

ReplyGrantPermission — 全局缓冲区越界读取

**Finding ID:** FERMAT-f6c924a892f9
**文件:** `services/pms/src/pms_server_internal.c:139`
**CWE:** CWE-119/CWE-129 (Buffer Overflow / Improper Validation of Array Index)

#### 漏洞原理

`ReplyGrantPermission()` 从 IPC 请求中读取 identifier 和 permName 字符串，未经验证直接传递给 `api->GrantPermission(identifier, permName)`。攻击者控制的 identifier 被用于索引内部权限查找表，当提供恶意 identifier 时导致越界读取。

#### 漏洞代码

```c
// pms_server_internal.c:146-148
char *identifier = (char *)ReadString(req, &idLen);   // ← 不可信
char *permName = (char *)ReadString(req, &permLen);   // ← 不可信
int32_t ret = api->GrantPermission(identifier, permName);  // ← 越界访问
```

#### 触发路径

```
恶意 IPC Client → ReplyGrantPermission() → api->GrantPermission(恶意id, perm) → 越界读取
```

#### PoC 复现方法

**PoC 文件:** `poc_FERMAT-f6c924a892f9.c`

```bash
# 1. 编译
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    ~/data/output/2026.05.15/poc_FERMAT-f6c924a892f9.c \
    -o /tmp/poc_f6c924a8

# 2. 运行
/tmp/poc_f6c924a8

# 3. 预期输出:
# ERROR: AddressSanitizer: global-buffer-overflow on address 0x...
# READ of size 8 at 0x... thread T0
#     #0 in StubGrantPermission
#     #1 in ReplyGrantPermission
#     #2 in main
```

