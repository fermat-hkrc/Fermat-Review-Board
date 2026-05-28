---
id: RUST-2026-YLONG-HTTP-003
date: "2026-05-27"
repo: commonlibrary_rust_ylong_http
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http
title: HPACK 解码器缺少 UTF-8 验证导致 Panic
severity: HIGH
cwe: CWE-20
cwe_name: Improper Input Validation
status: SUBMITTED
affected_version: "当前版本"
component: ylong_http/h2/hpack
language: Rust
file_paths:
  - ylong_http/src/h2/hpack/decoder.rs
author: Zirui
issue_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http/issues/200
has_poc: true
---

## 漏洞概述

ylong_http 的 HTTP/2 HPACK 解码器在处理 literal header name 和 value 时，直接使用 `String::from_utf8_unchecked()` 而不进行 UTF-8 验证。攻击者可以通过发送包含无效 UTF-8 字节的 HEADERS 帧触发未定义行为，导致 panic 或潜在的内存损坏。

## 根本原因

**位置**: `ylong_http/src/h2/hpack/decoder.rs:192-194`

```rust
fn get_header_by_name_and_value(
    &mut self,
    name: Name,
    value: Vec<u8>,
) -> Result<(Header, String), H2Error> {
    let h = match name {
        Name::Index(index) => { /* ... */ }
        Name::Literal(octets) => Header::Other(unsafe { 
            String::from_utf8_unchecked(octets)  // ← 无 UTF-8 验证
        }),
    };
    let v = unsafe { String::from_utf8_unchecked(value) };  // ← 无 UTF-8 验证
    Ok((h, v))
}
```

**问题**:
1. `Name::Literal(Vec<u8>)` 来自 HPACK 字符串解码（Huffman 或原始字节）
2. HPACK 解码器可以产生任意字节序列
3. **没有 UTF-8 验证**
4. 直接创建 `String`，违反 Rust 的类型不变式

## 影响

- **远程 DoS**: 恶意 HTTP/2 peer 发送无效 UTF-8 导致 panic
- **未定义行为**: 无效 String 在后续操作中可能导致：
  - 越界读取（字符边界计算错误）
  - 内存损坏
  - 数据泄露

## 触发条件

1. 攻击者建立 HTTP/2 连接
2. 发送 HEADERS 帧，包含 HPACK literal header
3. Header name/value 包含无效 UTF-8 字节（如 `[0x80, 0x81, 0x82]`）
4. `String::from_utf8_unchecked` 创建无效 String
5. 下游代码访问无效 String → panic 或 UB

## 修复建议

```rust
fn get_header_by_name_and_value(
    &mut self,
    name: Name,
    value: Vec<u8>,
) -> Result<(Header, String), H2Error> {
    let h = match name {
        Name::Index(index) => { /* ... */ }
        Name::Literal(octets) => {
            let name_str = String::from_utf8(octets)
                .map_err(|_| H2Error::ConnectionError(ErrorCode::ProtocolError))?;
            Header::Other(name_str)
        }
    };
    let v = String::from_utf8(value)
        .map_err(|_| H2Error::ConnectionError(ErrorCode::ProtocolError))?;
    Ok((h, v))
}
```

## 参考

- RFC 7540 §8.1.2: HTTP/2 header fields must be valid
- Rust String invariant: must contain valid UTF-8
- CWE-20: Improper Input Validation
