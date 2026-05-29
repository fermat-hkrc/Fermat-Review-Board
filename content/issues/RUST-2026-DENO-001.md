---
id: RUST-2026-DENO-001
date: "2026-05-28"
repo: deno
repo_url: https://github.com/denoland/deno
title: "Unsound Send implementation in SendPtr<T>"
cwe: CWE-662
cwe_name: Improper Synchronization
status: UNDER_REVIEW
language: Rust
severity: CRITICAL
issue_url: https://github.com/denoland/deno/issues/34453
author: Fermat
---

## 漏洞概述

Deno 的 NAPI 实现中，`SendPtr<T>` 类型无条件实现了 `Send` 和 `Sync`，即使 `T` 不是 `Send` 或 `Sync`。这允许非线程安全的类型通过原始指针跨线程传递，违反 Rust 的内存安全保证。

**严重程度**: CRITICAL  
**置信度**: HIGH  
**影响范围**: NAPI 回调中的跨线程指针传递

## 受影响的代码

**文件**: [`ext/napi/util.rs#L16-L17`](https://github.com/denoland/deno/blob/main/ext/napi/util.rs#L16-L17)

```rust
#[repr(transparent)]
pub(crate) struct SendPtr<T>(pub *const T);

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}
```

## 问题分析

`SendPtr<T>` 的 `Send`/`Sync` 实现没有要求 `T: Send` 或 `T: Sync`。这意味着：

1. 非 `Send` 类型（如 `Cell`, `Rc`, `RefCell`）可以被包装在 `SendPtr` 中
2. 包装后的指针可以跨线程发送
3. 在另一个线程中解引用指针访问非线程安全的类型，导致 UB

## 实际使用场景

在 NAPI 回调中，`SendPtr` 用于跨线程传递原始指针：

```rust
// ext/napi/js_native_api.rs:4012-4021
let env_send = SendPtr(env as *mut Env);
let data_send = SendPtr(finalize_data);
let hint_send = SendPtr(finalize_hint);
sender.spawn(move |_scope| unsafe {
    finalize_cb(
        env_send.take() as _,
        data_send.take() as *mut c_void,
        hint_send.take() as *mut c_void,
    );
});
```

如果 `finalize_data` 或 `finalize_hint` 指向非 `Send` 类型，会导致数据竞争。

## PoC

```rust
use std::cell::Cell;
use std::thread;

#[repr(transparent)]
struct SendPtr<T>(pub *const T);

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

fn main() {
    let cell = Box::new(Cell::new(42));
    let ptr = SendPtr(Box::into_raw(cell) as *const Cell<i32>);
    
    thread::spawn(move || {
        unsafe {
            let cell_ref = &*ptr.0;
            cell_ref.set(100); // UB: Cell 在另一个线程被访问
        }
    }).join().unwrap();
}
```

## 修复建议

添加适当的 trait bounds：

```rust
unsafe impl<T: Send> Send for SendPtr<T> {}
unsafe impl<T: Sync> Sync for SendPtr<T> {}
```

## 影响评估

- **严重性**: CRITICAL - 允许绕过 Rust 的线程安全检查
- **可利用性**: HIGH - 在 NAPI 代码中实际使用
- **影响范围**: 所有使用 NAPI 的 Deno 扩展

## 开发者回复 (2026-05-28)

**bartlomieju** 认为这不是 bug，理由：

1. `SendPtr<T>` 只用于 `c_void` 和内部句柄类型
2. NAPI 是 C ABI，`void*` 本身是 `Send` 的
3. 如果 addon 作者在 `void*` 后面放 `Rc<T>`，那是违反 NAPI 合约，不是 Rust 类型系统应该管的

**nathanwhit** 提出修复方案：将字段私有化，构造函数标记为 `unsafe`，要求调用者保证安全性。

**状态**: UNDER_REVIEW - 开发者认为这是设计如此，不是 bug
