---
id: OH-2026-DRIVERS-002
date: "2026-05-16"
repo: drivers_liteos
repo_url: https://gitcode.com/openharmony/drivers_liteos
title: "HieventBufferCopy 内核地址分支使用原始 srcLen 导致堆溢出"
severity: HIGH
cwe: CWE-120
cwe_name: Buffer Copy without Checking Size of Input
status: NEEDS_REVIEW
file_paths:
  - hievent/src/hievent_driver.c
author: Zirui
---

## 漏洞概述

`drivers_liteos` 的 `HieventBufferCopy()` 函数在处理内核地址（非用户空间地址）时，计算 `minLen = min(dstLen, srcLen)` 用于用户地址范围检查，但在 else 分支（两端均为内核地址）中调用 `memcpy_s(dst, dstLen, src, srcLen)` 时使用原始 `srcLen` 而非 `minLen`。

当 `dstLen` 参数由调用者传入且与实际目标缓冲区大小不一致时（例如通过 ioctl 传入的参数），`memcpy_s` 的 `destMax` 参数 (`dstLen`) 可能大于实际分配大小，导致堆缓冲区溢出。

## 问题代码

**文件**: `hievent/src/hievent_driver.c`

```c
static int HieventBufferCopy(char *dst, unsigned int dstLen,
                             char *src, unsigned int srcLen)
{
    unsigned int minLen = (dstLen > srcLen) ? srcLen : dstLen;

    if (LOS_IsUserAddressRange((vaddr_t)dst, minLen)) {
        // 用户空间目标：使用 copy_to_user
        ...
    } else if (LOS_IsUserAddressRange((vaddr_t)src, minLen)) {
        // 用户空间源：使用 copy_from_user
        ...
    } else {
        // 两端均为内核地址
        memcpy_s(dst, dstLen, src, srcLen);
        //            ^^^^^^      ^^^^^^
        //            可能大于     原始值，未使用 minLen
        //            实际缓冲区
    }
    return 0;
}
```

## 触发条件

1. 调用者通过 ioctl 或内核接口调用 `HieventBufferCopy`
2. `dstLen` 参数值大于 `dst` 指向的实际缓冲区分配大小
3. `src` 和 `dst` 均为内核地址（进入 else 分支）
4. `srcLen` 大于实际目标缓冲区大小
5. `memcpy_s` 使用不准确的 `dstLen` 作为 destMax，写入超出实际分配

## 影响

- 内核堆缓冲区溢出（WRITE）
- 内核崩溃（panic）
- 潜在的内核权限提升（堆布局可控时）

## PoC 验证

```bash
gcc -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    -I drivers_liteos/hievent/src \
    -I drivers_liteos/hievent/include \
    poc.c -o /tmp/poc && /tmp/poc
```

ASan 输出：
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000020
WRITE of size 256 at 0x502000000020 thread T0
    #0 in memcpy
    #1 in memcpy_s
    #2 in HieventBufferCopy
    #3 in main

0x502000000020 is located 0 bytes after 16-byte region [0x502000000010,0x502000000020)
```

## 修复建议

```c
    } else {
-       memcpy_s(dst, dstLen, src, srcLen);
+       memcpy_s(dst, dstLen, src, minLen);
    }
```

或更严格地：
```c
    } else {
+       if (minLen == 0) {
+           return 0;
+       }
+       memcpy_s(dst, minLen, src, minLen);
    }
```
