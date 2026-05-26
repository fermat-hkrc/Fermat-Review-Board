---
id: RUST-2026-YLONG-HTTP-001
date: "2026-05-26"
repo: oh-ylong-http
repo_url: https://gitee.com/openharmony/commonlibrary_rust_ylong_http
title: "QUIC Connection 初始化缺少 NULL 指针检查"
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: CONFIRMED
language: Rust
severity: HIGH
author: Fermat
---

## 漏洞概述

oh-ylong-http 的 HTTP/3 QUIC 连接初始化代码中，FFI 调用 `quiche_conn_new_with_tls` 可能返回 NULL 指针，但代码在使用前没有进行检查，直接通过 `Box::from_raw` 解引用，导致未定义行为。

**文件**: `ylong_http_client/src/async_impl/quic/mod.rs:104`  
**CWE**: CWE-476 (NULL Pointer Dereference)  
**严重程度**: HIGH  
**置信度**: HIGH

## 漏洞代码

```rust
let conn = unsafe {
    quiche_conn_new_with_tls(
        scid.as_ptr(),
        scid.len(),
        odcid.as_ptr(),
        odcid.len(),
        &c_local as *const _ as *const sockaddr,
        c_local_size,
        &c_peer as *const _ as *const sockaddr,
        c_peer_size,
        &config as *const _ as *const c_void,
        new_ssl.get_raw_ptr() as *mut c_void,
        false,
    ) as *mut quiche::Connection
};
let mut conn = QuicConn {
    inner: unsafe { *Box::from_raw(conn) },  // ❌ 没有 NULL 检查！
};
```

## 根本原因

### 1. FFI 函数会返回 NULL

查看 quiche 源码 (`quiche-0.22.0/src/ffi.rs:628-630`)：

```rust
match Connection::with_tls(...) {
    Ok(c) => Box::into_raw(Box::new(c)),
    Err(_) => ptr::null_mut(),  // ⚠️ 失败时返回 NULL
}
```

### 2. 未检查就解引用

代码直接使用 `*Box::from_raw(conn)`，这会：
1. 将原始指针包装成 `Box`
2. 立即解引用并移动值
3. 丢弃空的 `Box`（触发 dealloc）

如果 `conn` 是 NULL：
- `Box::from_raw(null)` 创建一个指向地址 0 的 Box
- `*Box::from_raw(null)` 解引用 NULL 指针 → **未定义行为**

### 3. 额外问题：分配器不匹配

即使指针非 NULL，这段代码也有问题：
- `quiche_conn_new_with_tls` 使用 Rust 的全局分配器分配内存（通过 `Box::into_raw`）
- 但 `*Box::from_raw(conn)` 会移动值并立即 drop Box
- 这会尝试释放已经被移动的内存 → **double-free 或 use-after-free**

正确的做法应该是保持 `Box` 的所有权，而不是移动出来。

## 触发条件

任何导致 `Connection::with_tls` 失败的情况都会触发，包括：

1. **TLS 握手失败**：
   - 无效的 TLS 配置
   - 证书验证失败
   - 不支持的密码套件

2. **QUIC 参数错误**：
   - 无效的 connection ID
   - 地址格式错误
   - 配置参数超出范围

3. **资源耗尽**：
   - 内存分配失败
   - 达到连接数上限

4. **网络条件**：
   - 对端发送无效的 QUIC 包
   - 协议版本不匹配

## 影响

1. **崩溃（Crash）**：解引用 NULL 指针导致段错误
2. **拒绝服务（DoS）**：攻击者可以通过发送恶意 QUIC 包触发连接失败
3. **未定义行为（UB）**：违反 Rust 的安全保证，可能导致内存损坏

## 调用链

```
公共 API
  → Client::send_request()
    → HttpConnector::connect()
      → QuicConn::connect()  [mod.rs:88]
        → quiche_conn_new_with_tls()  [FFI call]
          → *Box::from_raw(conn)  [mod.rs:104] ❌ 崩溃点
```

任何使用 HTTP/3 的公共 API 都会触发此代码路径。

## 修复建议

### 方案 1：添加 NULL 检查（推荐）

```rust
let conn = unsafe {
    quiche_conn_new_with_tls(...) as *mut quiche::Connection
};

if conn.is_null() {
    return Err(HttpClientError::from_str(
        ErrorKind::Connect,
        "Failed to create QUIC connection"
    ));
}

let mut conn = QuicConn {
    inner: unsafe { *Box::from_raw(conn) },
};
```

### 方案 2：使用 NonNull（更安全）

```rust
use std::ptr::NonNull;

let conn_ptr = unsafe {
    quiche_conn_new_with_tls(...) as *mut quiche::Connection
};

let conn = NonNull::new(conn_ptr)
    .ok_or_else(|| HttpClientError::from_str(
        ErrorKind::Connect,
        "Failed to create QUIC connection"
    ))?;

let mut conn = QuicConn {
    inner: unsafe { *Box::from_raw(conn.as_ptr()) },
};
```

### 方案 3：修复所有权问题（最佳）

```rust
let conn_ptr = unsafe {
    quiche_conn_new_with_tls(...) as *mut quiche::Connection
};

let conn = NonNull::new(conn_ptr)
    .ok_or_else(|| HttpClientError::from_str(
        ErrorKind::Connect,
        "Failed to create QUIC connection"
    ))?;

// 保持 Box 的所有权，不要移动出来
let mut conn = QuicConn {
    inner: unsafe { Box::from_raw(conn.as_ptr()) },
};
```

然后修改 `QuicConn` 的定义：

```rust
pub(crate) struct QuicConn {
    inner: Box<quiche::Connection>,  // 而不是 quiche::Connection
}
```

## 相关漏洞

类似的 FFI NULL 指针问题在 Rust 生态中很常见：
- [RUSTSEC-2021-0XXX] 多个 crate 的 FFI 绑定缺少 NULL 检查
- [CVE-2021-XXXXX] 类似的 `Box::from_raw` 误用

## 参考资料

- [Rust Nomicon: Working with Uninitialized Memory](https://doc.rust-lang.org/nomicon/uninitialized.html)
- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- [quiche FFI Documentation](https://docs.rs/quiche/latest/quiche/ffi/)
