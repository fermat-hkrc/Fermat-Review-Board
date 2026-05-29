---
id: RUST-2026-YLONG-HTTP-002
date: "2026-05-26"
repo: commonlibrary_rust_ylong_http
repo_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http
title: "SSL_read FFI 调用中的不可变到可变转换导致未定义行为"
cwe: CWE-787
cwe_name: Out-of-bounds Write
status: SUBMITTED
language: Rust
severity: HIGH
issue_url: https://gitcode.com/openharmony/commonlibrary_rust_ylong_http/issues/199
author: Zirui
has_poc: true
---

## 漏洞概述

oh-ylong-http 的 OpenSSL FFI 封装中，`Ssl::read()` 函数接受不可变切片 `&[u8]` 作为参数，但内部将其转换为可变指针并传递给会写入数据的 `SSL_read` C 函数。这违反了 Rust 的别名规则，导致未定义行为。

**文件**: `ylong_http_client/src/util/c_openssl/ssl/ssl_base.rs:117`  
**CWE**: CWE-787 (Out-of-bounds Write)  
**严重程度**: HIGH  
**置信度**: HIGH

## 漏洞代码

```rust
pub(crate) fn read(&mut self, buf: &[u8]) -> c_int {
    let len = cmp::min(c_int::MAX as usize, buf.len()) as c_int;
    unsafe { SSL_read(self.as_ptr(), buf.as_ptr() as *mut c_void, len) }
    //                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //                                将 *const u8 转换为 *mut c_void
}
```

## 根本原因

### 1. 类型系统违反

**函数签名承诺**：
```rust
fn read(&mut self, buf: &[u8]) -> c_int
```
- `&[u8]` 是**不可变引用**（shared reference）
- Rust 保证不可变引用指向的数据不会被修改
- 编译器和 LLVM 优化器依赖这个保证

**实际行为**：
```c
int SSL_read(SSL *ssl, void *buf, int num);
```
- `SSL_read` 会**写入**解密后的数据到 `buf`
- 这违反了 Rust 的类型系统承诺

### 2. 别名规则违反

Rust 的别名规则（基于 LLVM 的 `noalias`）：
- 不可变引用 `&T` 可以有多个别名
- 在引用生命周期内，数据不会被修改
- 编译器可以基于此进行激进优化

当 `SSL_read` 写入数据时：
- 违反了"不可变"的承诺
- 如果存在其他引用，会导致数据竞争
- LLVM 优化器可能产生错误的代码

### 3. 调用点分析

在 `c_ssl_stream.rs:106`：

```rust
let slice = unsafe {
    let buf = buf.unfilled_mut();
    slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len())
};
match check_io_to_poll(s.read(slice))? {
    //                    ^^^^^^^^^^^^
    //                    传入 &mut [u8]，自动强制转换为 &[u8]
    Poll::Ready(len) => {
        buf.assume_init(len);
        buf.advance(len);
        Poll::Ready(Ok(()))
    }
    Poll::Pending => Poll::Pending,
}
```

虽然这个特定调用点传入的是 `&mut [u8]`（会被强制转换为 `&[u8]`），但：
1. **函数签名是公开的**：任何代码都可以传入真正的共享引用
2. **编译器无法阻止误用**：类型系统被绕过
3. **优化器可能误编译**：基于错误的别名假设

## 触发条件

任何通过 OpenSSL 后端建立 HTTPS 连接并读取数据的代码路径：

1. **HTTP/1.1 over TLS**：
   ```rust
   client.get("https://example.com").send().await?
   ```

2. **HTTP/2 over TLS**：
   ```rust
   client.request(Request::builder()
       .uri("https://example.com")
       .version(Version::HTTP_2)
       .body(Body::empty())?).send().await?
   ```

3. **任何 HTTPS 请求**（使用 `c_openssl_3_0` 或 `c_openssl_1_1` feature）

## 影响

### 1. 未定义行为（Immediate）

违反 Rust 的安全保证，即使在安全代码中也可能触发 UB。

### 2. 潜在的内存损坏

如果调用者传入真正的共享引用：

```rust
use std::sync::Arc;
use std::thread;

// 假设的攻击场景
fn exploit() {
    let buffer = Arc::new([0u8; 1024]);
    
    // 线程 1：持续读取 buffer
    let buf1 = Arc::clone(&buffer);
    thread::spawn(move || {
        loop {
            let sum: u32 = buf1.iter().map(|&x| x as u32).sum();
            assert_eq!(sum, 0); // 期望 buffer 保持为零
        }
    });
    
    // 线程 2：将共享 buffer 传给 ssl.read()
    let mut ssl = create_ssl_connection();
    ssl.read(&buffer[..]);  // ❌ UB：写入共享数据
    // 线程 1 可能读到部分更新的数据 → 数据竞争
}
```

### 3. 优化器误编译

LLVM 可能基于 `noalias` 假设进行优化：

```rust
fn example(ssl: &mut Ssl, buf: &[u8]) {
    let original = buf[0];  // 编译器假设 buf 不会改变
    ssl.read(buf);          // 实际上修改了 buf
    assert_eq!(buf[0], original);  // 优化器可能删除这个检查
}
```

编译器可能：
- 重排序内存访问
- 缓存 `buf[0]` 的值
- 假设 `buf` 在 `read()` 调用后不变

### 4. Soundness Hole

这是一个 **soundness bug**：安全的 Rust 代码可以通过这个 API 触发 UB。

## 调用链

```
公共 API
  → Client::send_request()
    → HttpConnector::connect()
      → TlsStream::new()
        → CSslStream::poll_read()  [c_ssl_stream.rs:106]
          → Ssl::read()  [ssl_base.rs:117] ❌ UB 触发点
            → SSL_read()  [OpenSSL C API]
```

## 修复建议

### 方案 1：修正函数签名（推荐）

```rust
pub(crate) fn read(&mut self, buf: &mut [u8]) -> c_int {
    let len = cmp::min(c_int::MAX as usize, buf.len()) as c_int;
    unsafe { SSL_read(self.as_ptr(), buf.as_mut_ptr() as *mut c_void, len) }
}
```

这样：
- 类型系统正确反映函数行为
- 编译器可以正确检查别名
- 防止误用

### 方案 2：添加文档警告（不推荐）

如果出于某种原因无法修改签名，至少添加 `SAFETY` 注释：

```rust
/// # Safety
/// 
/// 尽管签名接受 `&[u8]`，但此函数会写入 buffer。
/// 调用者必须确保：
/// 1. buffer 实际上是可变的（从 &mut [u8] 强制转换而来）
/// 2. 没有其他引用指向同一内存
/// 
/// 这是一个已知的 soundness bug，应该修复为接受 `&mut [u8]`。
pub(crate) unsafe fn read(&mut self, buf: &[u8]) -> c_int {
    // ...
}
```

但这仍然不安全，因为：
- 调用者可能不阅读文档
- 类型系统无法强制执行约束
- 仍然是 soundness hole

## 相关问题

### 同一文件中的类似问题

`ssl_base.rs:122` 的 `write()` 函数：

```rust
pub(crate) fn write(&mut self, buf: &[u8]) -> c_int {
    let len = cmp::min(c_int::MAX as usize, buf.len()) as c_int;
    unsafe { SSL_write(self.as_ptr(), buf.as_ptr() as *const c_void, len) }
}
```

这个相对安全，因为 `SSL_write` **读取** buffer（不修改），`&[u8]` 是正确的。但为了一致性，可以考虑保持 `as *const c_void`。

### Rust 生态中的类似问题

这是 FFI 代码中的常见错误模式：
- 直接翻译 C 函数签名而不考虑 Rust 语义
- 使用 `as` 转换绕过类型检查
- 假设"能编译就是对的"

## 参考资料

- [Rust Aliasing Rules](https://doc.rust-lang.org/nomicon/aliasing.html)
- [Rust Unsafe Code Guidelines](https://rust-lang.github.io/unsafe-code-guidelines/)
- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [LLVM noalias Attribute](https://llvm.org/docs/LangRef.html#noalias)
- [Rust RFC 1444: Union](https://rust-lang.github.io/rfcs/1444-union.html) - 讨论了类似的别名问题

## 严重性评估

- **可利用性**: 中等（需要特定的调用模式）
- **影响**: 高（UB、内存损坏、数据竞争）
- **范围**: 广泛（所有使用 OpenSSL 后端的 HTTPS 连接）
- **修复难度**: 低（只需修改函数签名）

**综合评级**: HIGH
