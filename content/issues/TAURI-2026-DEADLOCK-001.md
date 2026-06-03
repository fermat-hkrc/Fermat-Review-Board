---
id: TAURI-2026-DEADLOCK-001
date: "2026-06-03"
repo: tauri
repo_url: https://github.com/tauri-apps/tauri
title: "[bug] Re-entrant deadlock in fs::Scope: once() always deadlocks (emit() invokes listeners while holding the event_listeners mutex)"
cwe: CWE-667
cwe_name: Improper Locking
severity: MEDIUM
status: SUBMITTED
language: Rust
issue_url: https://github.com/tauri-apps/tauri/issues/15468
affected_version: "2.11.2"
component: tauri/scope/fs
file_paths:
  - crates/tauri/src/scope/fs.rs
author: Toan
has_poc: true
---

## Summary

`tauri::scope::fs::Scope` 在**持有 `event_listeners` 互斥锁的情况下**调用事件监听器,而它自身的多个公开方法(`once`、`listen`、`unlisten`)会在监听器回调内部再次锁同一把非重入的 `std::sync::Mutex`,造成自死锁。

最直接的一例**完全不需要用户犯错**:公开的 `once()` 方法在其事件第一次触发时就因构造方式必然死锁。

## Vulnerable Code

`crates/tauri/src/scope/fs.rs`(v2.11.2,当前 `dev` 同样存在):

```rust
fn emit(&self, event: Event) {
    let listeners = self.event_listeners.lock().unwrap(); // 锁在整个循环期间持有
    let handlers = listeners.values();
    for listener in handlers {
        listener(&event);                                 // 持锁运行用户/库代码
    }
}

pub fn once<F: FnOnce(&Event) + Send + 'static>(&self, f: F) -> ScopeEventId {
    let listerners = self.event_listeners.clone();        // 克隆 Arc -> 同一把锁
    let handler = std::cell::Cell::new(Some(f));
    let id = self.next_event_id();
    self.listen_with_id(id, move |event| {
        listerners.lock().unwrap().remove(&id);           // emit() 持锁时再次加锁 -> 死锁
        let handler = handler.take().expect("...");
        handler(event)
    });
    id
}
```

`allow_file` / `allow_directory` / `forbid_file` / `forbid_directory` 都会调用 `self.emit(...)`,因此注册一个路径就会触发监听器。`std::sync::Mutex` 非重入,同一线程第二次加锁永久挂起。

## Trigger Conditions

仅用公开 API(内置 `tauri::test` mock runtime + 公开 `Scope` 方法):

### Case A — `once()` 自死锁(无需用户重入)

```rust
let app = tauri::test::mock_app();
let scope = app.asset_protocol_scope();
scope.once(|_event| {});            // 公开 API 注册一次性监听器,用户闭包为空
let _ = scope.allow_file("/tmp/x"); // emit() 持锁 -> 调 once 包装器 -> 再次锁 -> 死锁
```

在 `allow_file` 处挂起,用户的 `once` 闭包甚至都不会执行。

### Case B — `listen()` 回调内触碰 scope

```rust
let scope2 = scope.clone();
scope.listen(move |_event| { let _ = scope2.listen(|_| {}); });
let _ = scope.allow_file("/tmp/x"); // 死锁
```

对照组:监听器不触碰 scope 时正常返回 —— 确认死锁专属于重入加锁。

## Impact

- **挂起(拒绝服务)**:可由普通监听器代码触发。
- `once()` 按现状**完全不可用** —— 任何使用 asset-protocol scope `once()` 的应用一旦事件触发即死锁。
- `listen()` 监听器若在回调中增删监听器或调整 allow/forbid 列表,同样死锁。
- 同类"持锁调用监听器"模式也存在于 `tauri-runtime-wry` 的 `handle_event_loop`(`window_event_listeners` / `webview_event_listeners`)。

## Suggested Fix

在调用回调前释放 `event_listeners` 锁:

```rust
fn emit(&self, event: Event) {
    let handlers: Vec<_> = {
        let listeners = self.event_listeners.lock().unwrap();
        listeners.values().cloned().collect()   // 把 Box<dyn Fn> 改为 Arc<dyn Fn>
    };
    for handler in handlers {
        handler(&event);
    }
}
```

并让 `once` 在锁外移除自身 id。

## Notes

`listen` / `once` / `unlisten` 的文档注释均未提及重入/死锁,也没有任何禁止在监听器回调中访问 scope 的契约。该项目历史上一贯将此类"回调中持锁重入"死锁当作 bug 修复(如 `on_menu_event` 等)。通过静态分析锁守卫与回调交互发现。
