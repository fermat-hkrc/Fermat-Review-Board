---
id: RUST-2026-DENO-003
date: "2026-05-28"
repo: deno
repo_url: https://github.com/denoland/deno
title: "Unsound Send implementation in ArenaSharedAtomic<T>"
cwe: CWE-662
cwe_name: Improper Synchronization
status: CONFIRMED_REAL
language: Rust
severity: HIGH
issue_url: https://github.com/denoland/deno/issues/34455
author: Wensheng
---

## 漏洞概述

Deno 的原子共享 arena `ArenaSharedAtomic<T>` 无条件实现了 `Send`，即使 `T` 不是 `Send`。与 `RawArena<T>` 类似，这允许包含非 `Send` 类型的 arena 被移动到另一个线程，导致非 `Send` 类型在错误的线程中被 drop。

**严重程度**: HIGH  
**置信度**: HIGH  
**影响范围**: 所有使用 `ArenaSharedAtomic` 的代码

## 受影响的代码

**文件**: [`libs/core/arena/shared_atomic_arena.rs#L229`](https://github.com/denoland/deno/blob/main/libs/core/arena/shared_atomic_arena.rs#L229)

```rust
pub struct ArenaSharedAtomic<T> {
  ptr: NonNull<ArenaSharedAtomicData<T>>,
}

unsafe impl<T> Send for ArenaSharedAtomic<T> {}

// The arena itself may not be shared so that we can guarantee all [`RawArena`]
// access happens on the owning thread.
static_assertions::assert_impl_any!(ArenaSharedAtomic<()>: Send);
static_assertions::assert_not_impl_any!(ArenaSharedAtomic<()>: Sync);
```

## 问题分析

虽然注释说明设计意图是"保证所有 `RawArena` 访问发生在拥有线程"，但无条件的 `Send` 实现仍然允许：

1. Arena 被移动到另一个线程
2. 当 arena 被 drop 时，所有 `T` 值在该线程被 drop
3. 如果 `T` 不是 `Send`，这违反其线程安全不变式

值得注意的是，测试代码使用了 `RefCell<usize>`：

```rust
// libs/core/arena/shared_atomic_arena.rs:517
#[test]
fn test_raw() {
    let arena: ArenaSharedAtomic<RefCell<usize>> =
      ArenaSharedAtomic::with_capacity(16);
    // ...
}
```

`RefCell` 不是 `Send`，这表明可能是有意设计。但如果 arena 被移动到另一个线程并在那里 drop，`RefCell` 会在错误的线程被 drop。

## PoC

```rust
use std::thread;
use std::rc::Rc;

struct ArenaSharedAtomic<T> {
    data: Vec<T>,
}

unsafe impl<T> Send for ArenaSharedAtomic<T> {}

impl<T> Drop for ArenaSharedAtomic<T> {
    fn drop(&mut self) {
        println!("Dropping arena in thread: {:?}", thread::current().id());
    }
}

fn main() {
    println!("Main thread: {:?}", thread::current().id());
    
    let mut arena = ArenaSharedAtomic { data: Vec::new() };
    arena.data.push(Rc::new(42));
    
    thread::spawn(move || {
        println!("Arena in thread: {:?}", thread::current().id());
        drop(arena); // Rc 在错误的线程被 drop - UB!
    }).join().unwrap();
}
```

**输出:**
```
Main thread: ThreadId(1)
Arena in thread: ThreadId(2)
Dropping arena in thread: ThreadId(2)
```

## 实际影响

任何存储在 `ArenaSharedAtomic` 中的非 `Send` 类型都会在 arena 被 drop 的线程中被 drop。测试代码使用 `RefCell` 表明这可能是有意的使用模式，但仍然是不安全的。

## 修复建议

添加 `T: Send` bound：

```rust
unsafe impl<T: Send> Send for ArenaSharedAtomic<T> {}
```

**注意**: 这可能会破坏现有代码，如果 Deno 有意使用非 `Send` 类型（如测试中的 `RefCell`）。如果是这样，需要重新考虑设计，确保非 `Send` 类型永远不会在错误的线程被 drop。

## 影响评估

- **严重性**: HIGH - 违反类型系统的线程安全保证
- **可利用性**: MEDIUM - 测试代码显示可能的使用场景
- **影响范围**: 所有使用 `ArenaSharedAtomic` 的 Deno 核心代码

## 开发者回复 (2026-05-28)

**bartlomieju** 认可了这个问题：

1. **与 #34454 同类 bug**: `ArenaSharedAtomic<T>` 包装 `RawArena<ArenaArcData<T>>`，在 drop 时释放所有 `T` 值。Mutex 保护访问，但不保护 `T::drop` 运行的线程
2. **PoC 有效**: 展示了从 worker 线程分配并从另一个线程读取的违规行为
3. **澄清误解**:
   - 测试中的 `RefCell<usize>` 完全在单线程运行，不是跨线程使用的证据
   - `PhantomData<Mutex<T>>` 方案不可行，因为 `Mutex<T>: Send` 本身要求 `T: Send`
4. **正确修复**: `unsafe impl<T: Send> Send for ArenaSharedAtomic<T>`

**状态**: CONFIRMED_REAL - 开发者认可问题，欢迎 PR 修复
