---
id: HYPER-FFI-002
date: "2026-05-26"
repo: hyper
repo_url: https://github.com/hyperium/hyper
title: hyper_buf_copy 缺少 NULL 指针检查
severity: HIGH
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: PENDING
component: ffi
language: Rust
file_paths:
  - src/ffi/body.rs
author: fermat-hkrc
has_poc: true
---

## 漏洞概述

`hyper_buf_copy()` FFI 函数未检查输入的 `hyper_buf` 指针是否为 NULL，直接解引用导致程序崩溃。

**注意**: 此漏洞仅影响 hyper 的不稳定 C API 层（需要 `--cfg hyper_unstable_ffi`），普通 Rust 用户不受影响。

## 根本原因

**位置**: `src/ffi/body.rs:262`

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_buf_copy(buf: *const hyper_buf, dst: *mut u8, len: usize) -> usize {
    let buf = &*buf;  // ← 直接解引用，无 NULL 检查
    let src = buf.bytes();
    let n = std::cmp::min(len, src.len());
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, n);
    n
}
```

**问题**:

1. 未检查 `buf` 是否为 NULL
2. 直接 `&*buf` 解引用 NULL 指针
3. 导致 SIGSEGV 或 SIGABRT

## 影响

- **拒绝服务**: 程序崩溃
- **安全边界**: FFI 边界应该防御性地处理 C 代码的错误输入

## 触发条件

1. 使用 hyper 的 C FFI API
2. 调用 `hyper_buf_copy(NULL, dst, len)`
3. 触发 NULL 指针解引用

## 修复建议

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_buf_copy(buf: *const hyper_buf, dst: *mut u8, len: usize) -> usize {
    if buf.is_null() || dst.is_null() {
        return 0;
    }
    let buf = &*buf;
    let src = buf.bytes();
    let n = std::cmp::min(len, src.len());
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, n);
    n
}
```

## 参考

- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
