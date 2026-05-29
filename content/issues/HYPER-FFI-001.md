---
id: HYPER-FFI-001
date: "2026-05-28"
repo: hyper
repo_url: https://github.com/hyperium/hyper
title: FFI read 回调返回值未验证导致缓冲区溢出
severity: HIGH
cwe: CWE-120
cwe_name: Buffer Copy without Checking Size of Input
status: CLOSED
issue_url: https://github.com/hyperium/hyper/issues/4084
component: ffi
language: Rust
file_paths:
  - src/ffi/io.rs
author: Zirui
has_poc: true
---

## 漏洞概述

hyper 的 C FFI 层在处理用户提供的 read 回调时，未验证回调返回值是否超过缓冲区长度，直接调用 `buf.advance(ok)` 可能导致缓冲区越界。

**注意**: 此漏洞仅影响 hyper 的不稳定 C API 层（需要 `--cfg hyper_unstable_ffi`），普通 Rust 用户不受影响。

## 根本原因

**位置**: `src/ffi/io.rs:162`

```rust
match (self.read)(self.userdata, hyper_context::wrap(cx), buf_ptr, buf_len) {
    ok => {
        // We have to trust that the user's read callback actually
        // filled in that many bytes... :(
        unsafe { buf.advance(ok) };  // ← 无边界检查
        Poll::Ready(Ok(()))
    }
}
```

**问题**:

1. C 回调返回值 `ok` 可能大于 `buf_len`
2. 直接调用 `buf.advance(ok)` 不检查边界
3. 注释明确承认"必须信任用户回调"，但未添加防御性检查

## 影响

- **缓冲区溢出**: 如果 C 回调返回值大于缓冲区长度，导致越界读取
- **内存损坏**: 可能覆盖相邻内存区域
- **远程代码执行**: 在特定场景下可能被利用执行任意代码

## 触发条件

1. 使用 hyper 的 C FFI API
2. 注册恶意或有缺陷的 read 回调函数
3. 回调返回值大于提供的缓冲区长度
4. 触发缓冲区溢出

## 修复建议

```rust
match (self.read)(self.userdata, hyper_context::wrap(cx), buf_ptr, buf_len) {
    ok if ok <= buf_len => {
        unsafe { buf.advance(ok) };
        Poll::Ready(Ok(()))
    }
    invalid => {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("read callback returned {} but buffer size is {}", invalid, buf_len)
        )))
    }
}
```

## 参考

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-805: Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html)

---

## 开发者回复（已拒绝）

> **seanmonstar (seanmonstar)** — 2026-05-29
>
> This is not a vulnerability. The documentation for `hyper_io_set_read` already makes it very clear that returning a value larger than the buf is illegal: "It is undefined behavior to try to access the bytes in the buf pointer, unless you have already written them yourself. It is also undefined behavior to return that more bytes have been written than actually set on the buf."
