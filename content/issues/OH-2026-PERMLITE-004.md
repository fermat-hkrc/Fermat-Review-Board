---
id: OH-2026-PERMLITE-004
date: "2026-05-15"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ReplyRevokePermission 栈缓冲区溢出"
cwe: CWE-119
cwe_name: Improper Restriction of Operations within the Bounds of a Memory Buffer
status: PENDING
has_poc: true
file_paths:
  - pms_server_internal.c:153
author: Zirui
---

## ReplyRevokePermission 栈缓冲区溢出

ReplyRevokePermission — 栈缓冲区溢出

**Finding ID:** FERMAT-621d175e1782
**文件:** `services/pms/src/pms_server_internal.c:153`
**CWE:** CWE-119/CWE-129 (Buffer Overflow / Improper Validation of Array Index)

#### 漏洞原理

`ReplyRevokePermission()` 从 IPC 请求中通过 `ReadString()` 读取 identifier 和 permName，没有长度校验。当构造的 IPC 消息提供的字符串长度超过内部缓冲区时，`HILOG_INFO` 的 printf 格式化操作会读取超出栈缓冲区边界的内存，导致栈缓冲区溢出。

#### 漏洞代码

```c
// pms_server_internal.c:160-163
char *identifier = (char *)ReadString(req, &idLen);   // ← 不可信，无长度校验
char *permName = (char *)ReadString(req, &permLen);   // ← 不可信
int32_t ret = api->RevokePermission(identifier, permName);
HILOG_INFO(..., "revoke permission, [id: %s][perm: %s][ret: %d]", identifier, permName, ret);
// ↑ printf 读取超出缓冲区边界（字符串未正确 null-terminated）
```

#### 触发路径

```
恶意 IPC Client → ReplyRevokePermission() → HILOG_INFO(... identifier ...) → 栈缓冲区溢出
```

#### PoC 复现方法

**PoC 文件:** `poc_FERMAT-621d175e1782.c`

```bash
# 1. 编译
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    ~/data/output/2026.05.15/poc_FERMAT-621d175e1782.c \
    -o /tmp/poc_621d1758

# 2. 运行
/tmp/poc_621d1758

# 3. 预期输出:
# ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
# READ of size 17 at 0x... thread T0
#     #0 in printf_common
#     #3 in ReplyRevokePermission
#     #4 in main
# Memory access at offset 208 overflows variable 'small_buffer'
```

---

## 快速批量验证脚本

一键编译并运行所有 4 个 PoC:

```bash
#!/bin/bash
# 快速验证所有 PoC
# 用法: bash ~/data/output/2026.05.15/verify_all.sh

DIR=~/data/output/2026.05.15
PASS=0
FAIL=0

for poc in "$DIR"/poc_FERMAT-*.c; do
    name=$(basename "$poc" .c)
    echo "━━━ $name ━━━"
    gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 "$poc" -o "/tmp/$name" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "  COMPILE FAILED"
        FAIL=$((FAIL+1))
        continue
    fi
    output=$("/tmp/$name" 2>&1)
    if echo "$output" | grep -q "AddressSanitizer"; then
        echo "  TRIGGERED: $(echo "$output" | grep 'SUMMARY:' | sed 's/SUMMARY: //')"
        PASS=$((PASS+1))
    else
        echo "  NOT TRIGGERED"
        FAIL=$((FAIL+1))
    fi
    echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RESULT: $PASS/$((PASS+FAIL)) PoCs triggered"
```

---

## 未确认的发现 (6个, PoC 未触发)

以下发现在 PoC 验证阶段未能触发崩溃，视为误报已过滤:

| Finding ID | 文件 | 描述 |
|-----------|------|------|
| FERMAT-b1769da8ea7c | pms_server_internal.c:124 | ReplyCheckPermission — uid 无边界校验 |
| FERMAT-d9f2393c9454 | pms_server_internal.c:167 | ReplyGrantRuntimePermission — uid 无边界校验 |
| FERMAT-05cd2056523c | pms_server_internal.c:195 | ReplyUpdatePermissionFlags — 无边界校验 |
| FERMAT-69b468663f0d | pms_impl.c:85 | TOCTOU race: stat() + open() |
| FERMAT-4f9dcd8b0517 | perm_client.c:206 | malloc 返回值未检查 |
| FERMAT-70f036c8dbcf | perm_client.c:269 | IPC 污点数据流入 malloc |

---

## 文件清单

| 文件 | 说明 |
|------|------|
| `README.md` | 本报告 |
| `results.json` | 完整扫描结果 (L3 分析) |
| `verification_report.json` | PoC 验证详细报告 (含源码) |
| `scan_progress.json` | 扫描进度快照 |
| `poc_FERMAT-c073dd3aa275.c` | PoC: ReplyRevokeRuntimePermission OOB write |
| `poc_FERMAT-55fb84d6f77c.c` | PoC: ReplyQueryPermission OOB read |
| `poc_FERMAT-f6c924a892f9.c` | PoC: ReplyGrantPermission OOB read |
| `poc_FERMAT-621d175e1782.c` | PoC: ReplyRevokePermission stack overflow |
| `verify_all.sh` | 一键批量验证脚本 |

---

## 环境要求

- GCC (支持 `-fsanitize=address`)
- Linux x86_64
- 无需目标仓库源码即可独立编译运行 PoC (PoC 内含所有必要的 stub)
