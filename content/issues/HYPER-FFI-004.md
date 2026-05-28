---
id: HYPER-FFI-004
date: "2026-05-26"
repo: hyper
repo_url: https://github.com/hyperium/hyper
title: hyper_error_print 缺少 NULL 指针检查
severity: MEDIUM
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: PENDING
component: ffi
language: Rust
file_paths:
  - src/ffi/error.rs
author: Zirui
has_poc: true
---

## 漏洞概述

`hyper_error_print()` FFI 函数未检查输入的 `hyper_error` 指针是否为 NULL，直接解引用导致程序崩溃。

**注意**: 此漏洞仅影响 hyper 的不稳定 C API 层（需要 `--cfg hyper_unstable_ffi`），普通 Rust 用户不受影响。

## 根本原因

**位置**: `src/ffi/error.rs:91`

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_error_print(
    err: *const hyper_error,
    dst: *mut u8,
    dst_len: usize,
) -> usize {
    let err = &*err;  // ← 直接解引用，无 NULL 检查
    let msg = err.0.to_string();
    let bytes = msg.as_bytes();
    let n = std::cmp::min(dst_len, bytes.len());
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n);
    n
}
```

**问题**:

1. 未检查 `err` 是否为 NULL
2. 直接 `&*err` 解引用 NULL 指针
3. 导致 SIGSEGV 或 SIGABRT

## 影响

- **拒绝服务**: 程序崩溃
- **调试困难**: 错误处理函数本身崩溃，掩盖原始错误

## 触发条件

1. 使用 hyper 的 C FFI API
2. 调用 `hyper_error_print(NULL, dst, len)`
3. 触发 NULL 指针解引用

## 修复建议

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_error_print(
    err: *const hyper_error,
    dst: *mut u8,
    dst_len: usize,
) -> usize {
    if err.is_null() || dst.is_null() || dst_len == 0 {
        return 0;
    }
    let err = &*err;
    let msg = err.0.to_string();
    let bytes = msg.as_bytes();
    let n = std::cmp::min(dst_len, bytes.len());
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n);
    n
}
```

## 参考

- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
