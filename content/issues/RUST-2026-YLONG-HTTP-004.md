---
id: RUST-2026-YLONG-HTTP-004
date: "2026-05-27"
repo: commonlibrary_rust_ylong_http
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http
title: HTTP/1.1 响应解码器接受扩展 ASCII 导致无效 String
severity: MEDIUM
cwe: CWE-20
cwe_name: Improper Input Validation
status: SUBMITTED
affected_version: "当前版本"
component: ylong_http/h1/response
language: Rust
file_paths:
  - ylong_http/src/h1/response/decoder.rs
author: Zirui
issue_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http/issues/200
has_poc: true
---

## 漏洞概述

ylong_http 的 HTTP/1.1 响应解码器允许 header value 包含扩展 ASCII 字节（0x80-0xFF），这些字节符合 RFC 7230 的 obs-text 规范，但不是有效的 UTF-8。解码器随后使用 `String::from_utf8_unchecked()` 创建 String，违反了 Rust 的类型不变式。

## 根本原因

**位置**: `ylong_http/src/h1/response/decoder.rs:616-617`

```rust
fn header_insert(
    header_name: Vec<u8>,
    header_value: Vec<u8>,
    mut headers: Headers,
) -> Result<Option<Headers>, HttpError> {
    let name = unsafe { String::from_utf8_unchecked(header_name) };
    let value = unsafe { String::from_utf8_unchecked(header_value) };
    // ...
}
```

**上游验证** (`ylong_http/src/util/header_bytes.rs`):

```rust
pub(crate) static HEADER_VALUE_BYTES: [bool; 256] = {
    // 允许 0x09 (tab), 0x20-0x7E (ASCII), 0x80-0xFF (扩展 ASCII)
    // 0x80-0xFF 符合 RFC 7230 obs-text，但不是有效 UTF-8
};
```

**问题**:
1. `get_header_value()` 验证字节是否在 `HEADER_VALUE_BYTES` 中
2. 字节 0x80-0xFF 被允许（RFC 7230 obs-text）
3. 但这些字节**不是有效 UTF-8**
4. `String::from_utf8_unchecked` 创建无效 String

## 影响

- **未定义行为**: 无效 String 在后续操作中可能导致：
  - 字符串操作错误（`.to_lowercase()`, `.chars()`, 切片）
  - 越界读取
  - 数据损坏
- **需要恶意服务器**: 攻击者需要控制 HTTP 服务器
- **实践中罕见**: 大多数服务器使用纯 ASCII

## 触发条件

1. 攻击者搭建恶意 HTTP 服务器
2. 客户端连接并发送请求
3. 服务器返回包含扩展 ASCII 的 header value（如 `X-Custom: test\x80\x81\x82value`）
4. 字节通过 HTTP 验证（RFC 7230 合规）
5. `String::from_utf8_unchecked` 创建无效 String
6. 后续 String 操作可能触发 UB

## 缓解因素

- **Header name 安全**: `HEADER_NAME_BYTES` 只允许 ASCII (0x21-0x7E)，全部是有效 UTF-8
- **需要恶意服务器**: 不是协议违规，需要攻击者控制服务器
- **实践中罕见**: 现代服务器很少使用扩展 ASCII

## 修复建议

**选项 1: 拒绝扩展 ASCII**
```rust
fn get_header_value(buffer: &[u8]) -> TokenResult {
    for (i, b) in buffer.iter().enumerate() {
        if *b == b'\r' || *b == b'\n' {
            return Ok(TokenStatus::Complete((&buffer[..i], &buffer[i..])));
        } else if *b > 0x7F {  // 拒绝扩展 ASCII
            return Err(ErrorKind::H1(H1Error::InvalidResponse).into());
        } else if !HEADER_VALUE_BYTES[*b as usize] {
            return Err(ErrorKind::H1(H1Error::InvalidResponse).into());
        }
    }
    Ok(TokenStatus::Partial(buffer))
}
```

**选项 2: 使用 lossy 转换**
```rust
fn header_insert(
    header_name: Vec<u8>,
    header_value: Vec<u8>,
    mut headers: Headers,
) -> Result<Option<Headers>, HttpError> {
    let name = unsafe { String::from_utf8_unchecked(header_name) };  // name 是安全的
    let value = String::from_utf8_lossy(&header_value).into_owned();  // lossy 转换
    // ...
}
```

**选项 3: 保持为字节**
```rust
// 不转换为 String，保持为 HeaderValue (内部是 bytes)
```

## 参考

- RFC 7230 §3.2: Header field values (obs-text 允许 0x80-0xFF)
- Rust String invariant: must contain valid UTF-8
- CWE-20: Improper Input Validation
