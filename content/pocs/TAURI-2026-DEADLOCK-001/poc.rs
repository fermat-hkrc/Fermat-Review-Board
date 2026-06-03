//! Even simpler: tauri's OWN `Scope::once` deadlocks when the event fires.
//! once() registers a wrapper listener that calls `event_listeners.lock().remove(id)`
//! from inside the callback — but emit() already holds that lock.
use std::time::Duration;
use tauri::Manager;

fn main() {
    let app = tauri::test::mock_app();
    let scope = app.asset_protocol_scope();

    // Public API: register a one-shot listener.
    scope.once(|_event| {
        // user body never even runs — the once() wrapper deadlocks first.
    });

    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(5));
        eprintln!("DEADLOCK CONFIRMED via Scope::once(): the once() wrapper calls \
                   event_listeners.lock().remove(id) while emit() holds that same lock.");
        std::process::exit(101);
    });

    eprintln!("calling allow_file -> emit -> once-wrapper -> lock again ...");
    let _ = scope.allow_file("/tmp/poc_trigger");
    eprintln!("returned normally (NOT expected)");
}
