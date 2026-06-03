## Describe the bug

`tauri::scope::fs::Scope` invokes its event listeners **while holding the
`event_listeners` mutex**, and several of its own public methods
(`once`, `listen`, `unlisten`) re-lock that same non-reentrant
`std::sync::Mutex` from inside a listener callback. This produces a
self-deadlock.

The most direct case needs **no user mistake at all** — the public `once()`
method deadlocks by construction the first time its event fires.

`crates/tauri/src/scope/fs.rs` (v2.11.2, also present on current `dev`):

```rust
fn emit(&self, event: Event) {
    let listeners = self.event_listeners.lock().unwrap(); // guard held across the loop
    let handlers = listeners.values();
    for listener in handlers {
        listener(&event);                                 // user/library code runs with lock held
    }
}

pub fn once<F: FnOnce(&Event) + Send + 'static>(&self, f: F) -> ScopeEventId {
    let listerners = self.event_listeners.clone();        // clones the Arc -> SAME mutex
    let handler = std::cell::Cell::new(Some(f));
    let id = self.next_event_id();
    self.listen_with_id(id, move |event| {
        listerners.lock().unwrap().remove(&id);           // re-lock while emit() holds it -> DEADLOCK
        let handler = handler.take().expect("...");
        handler(event)
    });
    id
}

pub fn listen<F: Fn(&Event) + Send + 'static>(&self, f: F) -> ScopeEventId {
    // ...
    self.event_listeners.lock().unwrap().insert(id, Box::new(f)); // re-locks
}

pub fn unlisten(&self, id: ScopeEventId) {
    self.event_listeners.lock().unwrap().remove(&id);             // re-locks
}
```

`allow_file` / `allow_directory` / `forbid_file` / `forbid_directory` all call
`self.emit(...)`, so registering a path is what fires the listeners.
`std::sync::Mutex` is not reentrant, so the second lock attempt on the same
thread hangs forever.

The `listen` / `once` / `unlisten` doc comments contain no mention of
re-entrancy, and there is no documented contract forbidding scope access from a
listener callback.

## Reproduction

Public API only (the built-in `tauri::test` mock runtime + public `Scope`
methods).

`Cargo.toml`:

```toml
[dependencies]
tauri = { version = "2.11", default-features = false, features = ["test", "protocol-asset", "wry"] }
```

### Case A — `once()` self-deadlock (no user re-entry)

```rust
use std::time::Duration;
use tauri::Manager;

fn main() {
    let app = tauri::test::mock_app();
    let scope = app.asset_protocol_scope();

    // Register a one-shot listener via the public API. The user closure is empty.
    scope.once(|_event| {});

    // Watchdog proves the hang.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(5));
        eprintln!("DEADLOCK");
        std::process::exit(101);
    });

    // allow_file -> emit() locks event_listeners -> calls the once() wrapper ->
    //   wrapper does event_listeners.lock().remove(id) -> second lock -> DEADLOCK
    let _ = scope.allow_file("/tmp/anything");
}
```

This hangs in `allow_file`; the user's `once` closure never even runs.

### Case B — `listen()` callback that touches the scope

```rust
let scope2 = scope.clone();
scope.listen(move |_event| {
    let _ = scope2.listen(|_| {});   // or scope2.unlisten(..), allow_file(..), etc.
});
let _ = scope.allow_file("/tmp/anything");   // deadlocks
```

A control variant whose listener does not touch the scope completes normally,
confirming the deadlock is specifically the re-entrant lock.

## Expected behavior

`once()` should not deadlock, and invoking a listener that interacts with the
same scope should not deadlock. The standard fix is to release the
`event_listeners` guard before invoking handlers, e.g.:

```rust
fn emit(&self, event: Event) {
    let handlers: Vec<_> = {
        let listeners = self.event_listeners.lock().unwrap();
        listeners.values().cloned().collect()   // store Arc<dyn Fn> instead of Box<dyn Fn>
    };
    for handler in handlers {
        handler(&event);
    }
}
```

(or otherwise drop the guard before the callback loop, and have `once` remove
its id outside the locked region).

## Full `tauri info` output

```text
[✔] Environment
    - OS: Linux (rolling) x86_64
    - rustc: 1.96.0 stable
    - cargo: 1.96.0

[-] Packages
    - tauri [RUST]: 2.11.2  (path dep on crates/tauri @ dev, commit 25a6835)

Note: reproduced as a standalone Rust binary path-depending on crates/tauri
with features ["test", "protocol-asset", "wry"]; no JS/CLI project involved.
```

## Stack trace

```text
The thread hangs (does not panic) inside `Scope::allow_file -> Scope::emit`,
parked on the second `event_listeners.lock()` performed by the `once()` wrapper
listener while `emit()` still holds that same std::sync::Mutex guard on the same
thread. A 5s watchdog thread observes the hang and exits 101.
```

## Additional context

The same "invoke listener while holding the listeners mutex" pattern also exists
in `tauri-runtime-wry`'s `handle_event_loop` for `window_event_listeners` /
`webview_event_listeners`. This is the same class of re-entrant-callback
deadlock the project has fixed before (e.g. in `on_menu_event`). Found via
static analysis of lock-guard / callback interactions.
