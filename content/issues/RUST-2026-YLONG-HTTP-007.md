---
id: RUST-2026-YLONG-HTTP-007
date: "2026-05-27"
repo: commonlibrary_rust_ylong_http
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http
title: OpenSSL FFI 调用中的指针类型错误和别名违规
severity: MEDIUM
cwe: CWE-843
cwe_name: Access of Resource Using Incompatible Type
status: PENDING
affected_version: "当前版本"
component: ylong_http_client/ssl
language: Rust
file_paths:
  - ylong_http_client/src/util/c_openssl/ssl/stream.rs
author: Zirui
---

## 漏洞概述

ylong_http_client 的证书 pinning 验证代码在调用 OpenSSL 的 `i2d_X509_PUBKEY` 序列化公钥时，存在三个独立的错误：
1. 使用 `as_ptr()` (返回 `*const u8`) 而非 `as_mut_ptr()` (返回 `*mut u8`)
2. 对临时值取可变引用 (`&mut key.as_ptr()`)
3. 不可变绑定 (`let key`) 但通过 FFI 被写入（别名违规）

这些错误可能导致编译器优化错误，使证书 pinning 验证失效。

## 根本原因

**位置**: `ylong_http_client/src/util/c_openssl/ssl/stream.rs:318-320`

```rust
let key = vec![0u8; buf_size as usize];  // 不可变绑定

// The actual serialization
let serialized_data_size = unsafe { 
    i2d_X509_PUBKEY(pubkey, &mut key.as_ptr())  // ← 三重错误
};
```

**问题 1: const 指针传给需要 mut 的 FFI**
- `key.as_ptr()` 返回 `*const u8`
- OpenSSL `i2d_X509_PUBKEY` 需要 `*mut *mut u8`（会写入数据）
- 应该使用 `key.as_mut_ptr()` 返回 `*mut u8`

**问题 2: 可变引用指向临时值**
- `&mut key.as_ptr()` 创建临时 `*const u8` 在栈上
- 对临时值取可变引用：`&mut (*const u8)`
- 临时值在表达式结束后立即销毁
- OpenSSL 收到指向已释放栈内存的指针

**问题 3: 别名违规**
- `key` 声明为不可变（`let key`，不是 `let mut key`）
- OpenSSL 通过指针写入 Vec 的缓冲区
- 违反 Rust 的别名规则（不可变引用 + 突变）
- 编译器可能基于不可变性假设进行优化

## 影响

- **证书 pinning 失效**: 编译器可能优化掉写入，`key` 保持全零
- **结果**: SHA-256 哈希计算在全零数据上，而非实际公钥
- **安全影响**:
  - 可能无法检测 MITM 攻击
  - 或错误拒绝有效证书
- **潜在内存损坏**: 取决于编译器优化

## 为什么实践中可能"工作"

在机器层面，OpenSSL 不知道 Rust 的 const/mut 区别，它只是写入内存地址。Vec 的缓冲区是堆分配的可写内存，所以写入会成功。但这是 Rust 抽象机器中的未定义行为，未来的编译器版本或优化级别可能会破坏它。

## 修复建议

```rust
// 正确的 FFI 模式
let mut key = vec![0u8; buf_size as usize];  // mut 绑定
let mut ptr = key.as_mut_ptr();              // *mut u8

let serialized_data_size = unsafe { 
    i2d_X509_PUBKEY(pubkey, &mut ptr)        // 正确的 FFI 调用
};

if buf_size != serialized_data_size || serialized_data_size <= 0 {
    unsafe { X509_free(certificate) };
    return Err(SslError { ... });
}

// 现在 key 包含实际的序列化公钥
```

## 参考

- OpenSSL `i2d_X509_PUBKEY` 文档: 需要 `*mut *mut u8`
- Rust 别名规则: 不可变引用不能与突变共存
- CWE-843: Access of Resource Using Incompatible Type
- CWE-824: Access of Uninitialized Pointer
