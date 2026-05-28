---
id: HYPER-FFI-003
date: "2026-05-26"
repo: hyper
repo_url: https://github.com/hyperium/hyper
title: hyper_request_set_method 缺少 NULL 指针检查
severity: MEDIUM
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: PENDING
component: ffi
language: Rust
file_paths:
  - src/ffi/http_types.rs
author: Zirui
---

## 漏洞概述

`hyper_request_set_method()` FFI 函数未检查输入的 `method` 字符串指针是否为 NULL，直接传递给 `std::slice::from_raw_parts()` 导致未定义行为。

**注意**: 此漏洞仅影响 hyper 的不稳定 C API 层（需要 `--cfg hyper_unstable_ffi`），普通 Rust 用户不受影响。

## 根本原因

**位置**: `src/ffi/http_types.rs:108`

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_request_set_method(
    req: *mut hyper_request,
    method: *const u8,
    method_len: usize,
) -> hyper_code {
    let bytes = std::slice::from_raw_parts(method, method_len);  // ← 无 NULL 检查
    match http::Method::from_bytes(bytes) {
        Ok(m) => {
            (*req).0.method_mut().clone_from(&m);
            hyper_code::HYPERE_OK
        }
        Err(_) => hyper_code::HYPERE_INVALID_ARG,
    }
}
```

**问题**:

1. 未检查 `method` 是否为 NULL
2. `std::slice::from_raw_parts(NULL, len)` 是未定义行为
3. 即使 `method_len` 为 0，从 NULL 创建切片仍然是 UB

## 影响

- **未定义行为**: 可能导致程序崩溃或内存损坏
- **拒绝服务**: 程序异常终止

## 触发条件

1. 使用 hyper 的 C FFI API
2. 调用 `hyper_request_set_method(req, NULL, len)`
3. 触发未定义行为

## 修复建议

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_request_set_method(
    req: *mut hyper_request,
    method: *const u8,
    method_len: usize,
) -> hyper_code {
    if req.is_null() || method.is_null() {
        return hyper_code::HYPERE_INVALID_ARG;
    }
    let bytes = std::slice::from_raw_parts(method, method_len);
    match http::Method::from_bytes(bytes) {
        Ok(m) => {
            (*req).0.method_mut().clone_from(&m);
            hyper_code::HYPERE_OK
        }
        Err(_) => hyper_code::HYPERE_INVALID_ARG,
    }
}
```

## 参考

- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- [Rust std::slice::from_raw_parts safety requirements](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
