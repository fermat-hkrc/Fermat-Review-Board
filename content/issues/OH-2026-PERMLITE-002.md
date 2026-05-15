---
id: OH-2026-PERMLITE-002
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyQueryPermission 全局缓冲区越界读取"
cwe: CWE-125
cwe_name: Out-of-bounds Read
status: PENDING
has_poc: true
file_paths:
  - pms_server.c:124
author: Zirui
---

## ReplyQueryPermission 全局缓冲区越界读取

ReplyQueryPermission — 全局缓冲区越界读取

**Finding ID:** FERMAT-55fb84d6f77c
**文件:** `services/pms/src/pms_server.c:124`
**CWE:** CWE-125 (Out-of-bounds Read)

#### 漏洞原理

`ReplyQueryPermission()` 从 IPC 请求中通过 `ReadString(req, &idLen)` 读取 identifier 字符串，未经验证直接传递给 `QueryPermissionString(identifier, &ret)`。攻击者控制的 identifier 被用作内部权限存储结构的查找键/索引，导致越界读取。

#### 漏洞代码

```c
// pms_server.c:131-132
char *identifier = (char *)ReadString(req, &idLen);   // ← 不可信 IPC 输入
char *jsonStr = QueryPermissionString(identifier, &ret);  // ← 用作查找键/索引，越界读取
```

#### 触发路径

```
恶意 IPC Client → ReplyQueryPermission() → QueryPermissionString(恶意identifier) → 越界读取
```

#### PoC 复现方法

**PoC 文件:** `poc_FERMAT-55fb84d6f77c.c`

```bash
# 1. 编译
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    ~/data/output/2026.05.15/poc_FERMAT-55fb84d6f77c.c \
    -o /tmp/poc_55fb84d6

# 2. 运行
/tmp/poc_55fb84d6

# 3. 预期输出:
# ERROR: AddressSanitizer: global-buffer-overflow on address 0x...
# READ of size 8 at 0x... thread T0
#     #0 in QueryPermissionString
#     #1 in ReplyQueryPermission
#     #2 in main
```

