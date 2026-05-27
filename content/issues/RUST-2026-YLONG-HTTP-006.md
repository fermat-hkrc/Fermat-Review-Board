---
id: RUST-2026-YLONG-HTTP-006
date: "2026-05-27"
repo: commonlibrary_rust_ylong_http
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http
title: OpenSSL 证书公钥提取缺少 NULL 指针检查
severity: HIGH
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: PENDING
affected_version: "当前版本"
component: ylong_http_client/ssl
language: Rust
file_paths:
  - ylong_http_client/src/util/c_openssl/ssl/stream.rs
author: fermat-round5
---

## 漏洞概述

ylong_http_client 的证书 pinning 验证代码在调用 OpenSSL 的 `X509_get_X509_PUBKEY` 提取证书公钥后，没有检查返回的指针是否为 NULL，直接传给 `i2d_X509_PUBKEY`。如果证书格式错误导致 OpenSSL 返回 NULL，会导致崩溃。

## 根本原因

**位置**: `ylong_http_client/src/util/c_openssl/ssl/stream.rs:307-309`

```rust
fn verify_pinned_pubkey(pinned_key: &str, certificate: *mut C_X509) -> Result<(), SslError> {
    let pubkey = unsafe { X509_get_X509_PUBKEY(certificate) };
    
    // Get the length of the serialized data
    let buf_size = unsafe { i2d_X509_PUBKEY(pubkey, ptr::null_mut()) };
    // ↑ 没有检查 pubkey 是否为 NULL
    
    if buf_size < 1 {
        unsafe { X509_free(certificate) };
        return Err(SslError { ... });
    }
    // ...
}
```

**问题**:
1. `X509_get_X509_PUBKEY` 是 OpenSSL C 函数
2. 根据 OpenSSL 文档，证书格式错误时可以返回 NULL
3. **没有 NULL 检查**
4. 直接将 `pubkey` 传给 `i2d_X509_PUBKEY`
5. OpenSSL 的 `i2d_X509_PUBKEY(NULL, ...)` 会解引用 NULL → 崩溃

## 影响

- **远程 DoS**: HTTPS 连接时可被攻击者触发
- **触发条件**:
  - 恶意服务器发送畸形 X.509 证书
  - 证书缺少公钥字段或 DER 编码损坏
  - OpenSSL 解析失败返回 NULL
- **前提条件**: 客户端启用证书 pinning

## 触发条件

1. 攻击者搭建 HTTPS 服务器，发送畸形证书
2. 客户端启用证书 pinning 并连接
3. TLS 握手到达 verify_pinned_pubkey
4. X509_get_X509_PUBKEY 返回 NULL
5. i2d_X509_PUBKEY(NULL, ...) 崩溃

## 修复建议

```rust
fn verify_pinned_pubkey(pinned_key: &str, certificate: *mut C_X509) -> Result<(), SslError> {
    let pubkey = unsafe { X509_get_X509_PUBKEY(certificate) };
    
    // 检查 NULL
    if pubkey.is_null() {
        unsafe { X509_free(certificate) };
        return Err(SslError {
            code: SslErrorCode::SSL,
            internal: Some(InternalError::InvalidCertificate),
        });
    }
    
    // Get the length of the serialized data
    let buf_size = unsafe { i2d_X509_PUBKEY(pubkey, ptr::null_mut()) };
    
    if buf_size < 1 {
        unsafe { X509_free(certificate) };
        return Err(SslError { ... });
    }
    // ...
}
```

## 参考

- OpenSSL 文档: `X509_get_X509_PUBKEY` 可以返回 NULL
- CWE-476: NULL Pointer Dereference
- Rust FFI 最佳实践: 检查 C 函数返回的指针
