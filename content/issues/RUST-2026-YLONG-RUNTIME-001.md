---
id: RUST-2026-YLONG-RUNTIME-001
date: "2026-05-26"
repo: commonlibrary_rust_ylong_runtime
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_runtime
title: TcpListener bind 失败时文件描述符双重关闭
severity: HIGH
cwe: CWE-675
cwe_name: Duplicate Operations on Resource
status: CLOSED
component: ylong_io
language: Rust
file_paths:
  - ylong_io/src/tcp/listener.rs
author: Zirui
issue_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_runtime/issues/170
has_poc: true
---

## 漏洞概述

`TcpListener::bind()` 在 `listen()` 系统调用失败时会导致文件描述符被双重关闭。第一次关闭发生在 `Socket` 的 `Drop` 实现中，第二次关闭发生在 `from_std_listener()` 内部的错误处理路径。

## 根本原因

**位置**: `ylong_io/src/tcp/listener.rs:40`

```rust
pub fn bind(addr: SocketAddr) -> io::Result<Self> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;  // ← 如果失败，socket 被 drop，fd 被关闭
    Ok(Self::from_std_listener(socket.into())?)  // ← 可能再次关闭同一个 fd
}
```

**问题**:

1. `socket.listen(128)?` 失败时，`socket` 变量超出作用域被 drop
2. `Socket` 的 `Drop` 实现会调用 `close(fd)`
3. 但 `socket.into()` 已经将 fd 转移到 `std::net::TcpListener`
4. 如果 `from_std_listener()` 内部失败，可能再次关闭已经关闭的 fd

## 影响

- **文件描述符混淆**: 双重关闭的 fd 可能已被其他线程重用，导致关闭错误的文件
- **资源泄漏**: 如果 fd 被重用为关键资源（socket、文件），可能导致数据损坏
- **安全风险**: 在多线程环境下，可能导致 TOCTOU 竞态条件

## 触发条件

1. 调用 `TcpListener::bind()` 绑定到特定地址
2. `bind()` 成功但 `listen()` 失败（例如：端口已被占用、权限不足）
3. 文件描述符被双重关闭

## 修复建议

```rust
pub fn bind(addr: SocketAddr) -> io::Result<Self> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    let std_listener = socket.into();
    Self::from_std_listener(std_listener)
}
```

或者使用 `ManuallyDrop` 防止双重关闭：

```rust
use std::mem::ManuallyDrop;

pub fn bind(addr: SocketAddr) -> io::Result<Self> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    let socket = ManuallyDrop::new(socket);
    Ok(Self::from_std_listener(ManuallyDrop::into_inner(socket).into())?)
}
```

## 上游处理记录

- **提单**: [commonlibrary_rust_ylong_runtime#170](https://gitcode.com/openharmony/commonlibrary_rust_ylong_runtime/issues/170)
- **上游状态**: 已关闭（已拒绝）

---

## 开发者回复（已拒绝）

> **huaxin05** — 2026-05
>
> 未找到对应源码

## 参考

- [CWE-675: Multiple Operations on Resource in Single-Operation Context](https://cwe.mitre.org/data/definitions/675.html)
- [CWE-672: Operation on a Resource after Expiration or Release](https://cwe.mitre.org/data/definitions/672.html)
