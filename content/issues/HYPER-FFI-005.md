---
id: HYPER-FFI-005
date: "2026-05-26"
repo: hyper
repo_url: https://github.com/hyperium/hyper
title: FFI read 回调返回值可能导致越界读取
severity: HIGH
cwe: CWE-125
cwe_name: Out-of-bounds Read
status: PENDING
component: ffi
language: Rust
file_paths:
  - src/ffi/io.rs
author: Zirui
---

## 漏洞概述

hyper 的 C FFI 层在处理用户提供的 read 回调时，如果回调返回值超过缓冲区长度，会导致后续代码读取未初始化或越界内存。

**注意**: 此漏洞仅影响 hyper 的不稳定 C API 层（需要 `--cfg hyper_unstable_ffi`），普通 Rust 用户不受影响。

## 根本原因

**位置**: `src/ffi/io.rs:150-166`

```rust
impl hyper::rt::Read for UserBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let buf_ptr = unsafe { buf.as_mut().as_mut_ptr() };
        let buf_len = unsafe { buf.as_mut().len() };

        match (self.read)(self.userdata, hyper_context::wrap(cx), buf_ptr, buf_len) {
            ok => {
                unsafe { buf.advance(ok) };  // ← 如果 ok > buf_len，越界
                Poll::Ready(Ok(()))
            }
        }
    }
}
```

**问题**:

1. C 回调返回值 `ok` 未验证是否 <= `buf_len`
2. `buf.advance(ok)` 会标记 `ok` 字节为已初始化
3. 如果 `ok > buf_len`，后续代码会读取越界内存

## 影响

- **越界读取**: 读取缓冲区外的内存
- **信息泄漏**: 可能泄漏敏感数据
- **未定义行为**: 可能导致程序崩溃

## 触发条件

1. 使用 hyper 的 C FFI API
2. 注册恶意或有缺陷的 read 回调函数
3. 回调返回值大于提供的缓冲区长度
4. 后续代码读取越界内存

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

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CWE-805: Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html)
