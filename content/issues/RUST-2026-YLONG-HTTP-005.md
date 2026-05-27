---
id: RUST-2026-YLONG-HTTP-005
date: "2026-05-27"
repo: commonlibrary_rust_ylong_http
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http
title: QUIC 连接创建缺少 NULL 指针检查
severity: HIGH
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: PENDING
affected_version: "当前版本"
component: ylong_http_client/quic
language: Rust
file_paths:
  - ylong_http_client/src/async_impl/quic/mod.rs
author: fermat-round5
---

## 漏洞概述

ylong_http_client 的 QUIC 连接创建代码在调用 C FFI 函数 `quiche_conn_new_with_tls` 后，没有检查返回的指针是否为 NULL，直接传给 `Box::from_raw` 并解引用。如果 C 函数返回 NULL（内存分配失败、TLS 配置错误等），会导致立即段错误。

此外，即使指针非空，代码使用 `*Box::from_raw(ptr)` 模式也存在分配器不匹配问题（C malloc vs Rust dealloc）。

## 根本原因

**位置**: `ylong_http_client/src/async_impl/quic/mod.rs:104`

```rust
let conn = unsafe {
    quiche_conn_new_with_tls(
        scid.as_ptr(),
        scid.len() as size_t,
        ptr::null_mut(),
        0,
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
    inner: unsafe { *Box::from_raw(conn) },  // ← 没有 NULL 检查
};
```

**问题**:
1. `quiche_conn_new_with_tls` 是 C FFI 函数，返回 `*mut c_void`
2. C 函数失败时通常返回 NULL
3. **没有 NULL 检查**
4. `Box::from_raw(null)` 后立即解引用 `*Box` → 段错误
5. **分配器不匹配**: quiche 使用 C malloc，但 `*Box::from_raw` 会调用 Rust dealloc

## 影响

- **远程 DoS**: 任何尝试 QUIC 连接的客户端都可能触发
- **触发条件**:
  - 内存分配失败
  - TLS 配置错误（无效证书、密码套件）
  - 无效连接参数（地址、SCID）
  - 任何导致 quiche 返回 NULL 的情况

## PoC 验证

**状态**: ⚠️ 无法生成可运行的 PoC

**原因**: ylong_http_client 依赖 BoringSSL（通过 quiche），与系统 OpenSSL 存在链接冲突，无法在本地环境编译。

**源码验证**: ✅ 已通过直接读取源代码确认漏洞存在

## 修复建议

```rust
let conn = unsafe {
    quiche_conn_new_with_tls(...) as *mut quiche::Connection
};

// 检查 NULL
if conn.is_null() {
    return Err(HttpClientError::QuicConnectionFailed);
}

// 不要使用 Box::from_raw 在 C 分配的内存上
// 选项 1: 直接使用原始指针
let mut conn = QuicConn {
    inner: conn,  // 保持为原始指针
};

// 选项 2: 使用 ManuallyDrop
let mut conn = QuicConn {
    inner: unsafe { ManuallyDrop::new(*Box::from_raw(conn)) },
};

// 在 Drop 实现中调用 C 的释放函数
impl Drop for QuicConn {
    fn drop(&mut self) {
        unsafe { quiche_conn_free(self.inner) };
    }
}
```

## 参考

- CWE-476: NULL Pointer Dereference
- Rust FFI 最佳实践: 检查 C 函数返回的指针
- 分配器匹配: C malloc 必须用 C free，不能用 Rust dealloc
