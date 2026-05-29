---
id: RUST-2026-DENO-002
date: "2026-05-28"
repo: deno
repo_url: https://github.com/denoland/deno
title: "Unsound Send implementation in RawArena<T>"
cwe: CWE-662
cwe_name: Improper Synchronization
status: CONFIRMED_REAL
language: Rust
severity: HIGH
issue_url: https://github.com/denoland/deno/issues/34454
author: Fermat
---

## 漏洞概述

Deno 的 arena 分配器 `RawArena<T>` 无条件实现了 `Send`，即使 `T` 不是 `Send`。这允许包含非 `Send` 类型的 arena 被移动到另一个线程，当 arena 被 drop 时，非 `Send` 类型会在错误的线程中被 drop，违反其线程安全不变式。

**严重程度**: HIGH  
**置信度**: HIGH  
**影响范围**: 所有使用 `RawArena` 的代码

## 受影响的代码

**文件**: [`libs/core/arena/raw_arena.rs#L63`](https://github.com/denoland/deno/blob/main/libs/core/arena/raw_arena.rs#L63)

```rust
pub struct RawArena<T> {
  max: Cell<NonNull<RawArenaEntry<T>>>,
  next: Cell<NonNull<RawArenaEntry<T>>>,
  // ...
}

/// The [`RawArena`] is [`Send`], but not [`Sync`].
unsafe impl<T> Send for RawArena<T> {}
```

## 问题分析

虽然 `RawArena` 本身使用 `Cell`（不是 `Sync`），但问题在于：

1. `RawArena<T>` 可以被移动到另一个线程（因为它是 `Send`）
2. 当 arena 被 drop 时，它会 drop 所有存储的 `T` 值
3. 如果 `T` 不是 `Send`，在错误的线程 drop 它会违反其安全不变式

例如，`Rc<U>` 使用非原子引用计数，必须在创建它的线程中 drop。

## PoC

```rust
use std::thread;
use std::rc::Rc;

struct RawArena<T> {
    data: Vec<T>,
}

unsafe impl<T> Send for RawArena<T> {}

impl<T> Drop for RawArena<T> {
    fn drop(&mut self) {
        println!("Dropping arena in thread: {:?}", thread::current().id());
    }
}

fn main() {
    println!("Main thread: {:?}", thread::current().id());
    
    let mut arena = RawArena { data: Vec::new() };
    arena.data.push(Rc::new(42)); // Rc 不是 Send
    
    thread::spawn(move || {
        println!("Spawned thread: {:?}", thread::current().id());
        drop(arena); // Rc 在错误的线程被 drop - UB!
    }).join().unwrap();
}
```

**输出:**
```
Main thread: ThreadId(1)
Spawned thread: ThreadId(2)
Dropping arena in thread: ThreadId(2)
```

`Rc` 在 ThreadId(1) 创建，但在 ThreadId(2) 被 drop，这是 UB。

## 实际影响

任何存储在 `RawArena` 中的非 `Send` 类型都会在 arena 被 drop 的线程中被 drop，而不一定是创建它的线程。这违反了非 `Send` 类型的安全不变式。

## 修复建议

添加 `T: Send` bound：

```rust
unsafe impl<T: Send> Send for RawArena<T> {}
```

## 影响评估

- **严重性**: HIGH - 违反类型系统的线程安全保证
- **可利用性**: MEDIUM - 需要在 arena 中存储非 Send 类型
- **影响范围**: 所有使用 `RawArena` 的 Deno 核心代码

## 开发者回复 (2026-05-28)

**bartlomieju** 认可了这个问题：

1. **Soundness hole 是真实的**: `RawArena<T>` 拥有 `T` 值并在 drop 时释放它们，如果 `T: !Send` 且 arena 被移动到另一个线程，drop 会在错误的线程运行 - 这是真正的 UB
2. **实践中安全**: `RawArena` 是内部构建块，所有消费者（`ArenaShared`, `ArenaSharedAtomic`, `ArenaUnique`）都包装了它并提供同步，从不暴露裸的 `RawArena<T>`
3. **应该修复**: 添加 `unsafe impl<T: Send> Send for RawArena<T>` 是正确的做法，让类型系统强制执行包装器已经假设的约束

**状态**: CONFIRMED_REAL - 开发者认可问题，欢迎 PR 修复
