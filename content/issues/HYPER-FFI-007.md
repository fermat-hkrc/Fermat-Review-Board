---
id: HYPER-FFI-007
date: "2026-05-26"
repo: hyper
repo_url: https://github.com/hyperium/hyper
title: hyper_request_set_uri_parts 长度参数未验证导致越界读取
severity: MEDIUM
cwe: CWE-125
cwe_name: Out-of-bounds Read
status: PENDING
component: ffi
language: Rust
file_paths:
  - src/ffi/http_types.rs
author: Zirui
has_poc: true
---

## 漏洞概述

`hyper_request_set_uri_parts()` FFI 函数接受多个字符串指针和长度参数，但未验证长度参数的有效性，可能导致越界读取。

**注意**: 此漏洞仅影响 hyper 的不稳定 C API 层（需要 `--cfg hyper_unstable_ffi`），普通 Rust 用户不受影响。

## 根本原因

**位置**: `src/ffi/http_types.rs:181`

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_request_set_uri_parts(
    req: *mut hyper_request,
    scheme: *const u8,
    scheme_len: usize,
    authority: *const u8,
    authority_len: usize,
    path_and_query: *const u8,
    path_and_query_len: usize,
) -> hyper_code {
    let scheme_bytes = std::slice::from_raw_parts(scheme, scheme_len);
    let authority_bytes = std::slice::from_raw_parts(authority, authority_len);
    let pq_bytes = std::slice::from_raw_parts(path_and_query, path_and_query_len);
    // ... 后续处理
}
```

**问题**:

1. 未检查任何指针是否为 NULL
2. 未验证长度参数是否合理
3. 如果长度参数过大，`from_raw_parts()` 会创建越界切片
4. 后续代码读取切片时会越界访问内存

## 影响

- **越界读取**: 读取超出实际字符串长度的内存
- **信息泄漏**: 可能泄漏相邻内存中的敏感数据
- **未定义行为**: 可能导致程序崩溃

## 触发条件

1. 使用 hyper 的 C FFI API
2. 调用 `hyper_request_set_uri_parts()` 时传入过大的长度参数
3. 或传入 NULL 指针但非零长度
4. 触发越界读取

## 修复建议

```rust
#[no_mangle]
pub unsafe extern "C" fn hyper_request_set_uri_parts(
    req: *mut hyper_request,
    scheme: *const u8,
    scheme_len: usize,
    authority: *const u8,
    authority_len: usize,
    path_and_query: *const u8,
    path_and_query_len: usize,
) -> hyper_code {
    if req.is_null() {
        return hyper_code::HYPERE_INVALID_ARG;
    }
    
    // 检查 NULL 指针和长度一致性
    if (scheme.is_null() && scheme_len != 0) ||
       (authority.is_null() && authority_len != 0) ||
       (path_and_query.is_null() && path_and_query_len != 0) {
        return hyper_code::HYPERE_INVALID_ARG;
    }
    
    let scheme_bytes = if scheme.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(scheme, scheme_len)
    };
    
    let authority_bytes = if authority.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(authority, authority_len)
    };
    
    let pq_bytes = if path_and_query.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(path_and_query, path_and_query_len)
    };
    
    // ... 后续处理
}
```

## 参考

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CWE-805: Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html)
- [Rust std::slice::from_raw_parts safety requirements](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
