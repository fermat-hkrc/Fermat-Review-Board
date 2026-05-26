//! PoC for RUST-2026-YLONG-HTTP-002: SSL_read FFI aliasing violation
//!
//! CWE-787: SslRef::read(&mut self, buf: &[u8]) accepts an IMMUTABLE reference
//! but passes it to SSL_read which WRITES into the buffer.
//! This violates Rust's aliasing rules — UB.
//!
//! Full execution path:
//!   Client::request()
//!     → HttpConnector::connect()                [connector.rs:120]
//!       → SslStream::new(tcp, ssl)              [connector.rs:136]
//!     → conn.read(buf)                          [http1.rs:86]
//!       → SslStream::read(&mut [u8])            [stream.rs:189]
//!         → ssl_read(buf: &[u8])                [stream.rs:191]  ← &mut coerced to &
//!           → SslRef::read(buf: &[u8])          [ssl_base.rs:117]
//!             → SSL_read(..., buf.as_ptr() as *mut c_void, ...)  ❌ UB

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use ylong_http_client::sync_impl::{Body, Client};
use ylong_http_client::Request;

fn main() {
    println!("=== PoC: RUST-2026-YLONG-HTTP-002 ===");
    println!("CWE-787: SSL_read writes through immutable reference (&[u8])");
    println!();

    // Start local TLS server
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let port = listener.local_addr().unwrap().port();
    println!("[*] Local TLS server on 127.0.0.1:{}", port);

    let server = thread::spawn(move || {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("certs/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("certs/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let (stream, _) = listener.accept().expect("accept failed");
        let mut ssl = acceptor.accept(stream).expect("TLS accept failed");

        let mut req = [0u8; 4096];
        let _ = ssl.read(&mut req);

        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!";
        ssl.write_all(resp.as_bytes()).unwrap();
        ssl.shutdown().ok();
    });

    // Build HTTPS client (skip cert verification for self-signed)
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .tls_built_in_root_certs(false)
        .build()
        .expect("client build failed");

    let url = format!("https://127.0.0.1:{}", port);
    let request = Request::get(url.as_str())
        .body("".as_bytes())
        .expect("request build failed");

    println!("[*] Sending HTTPS request...");
    let mut response = client.request(request).expect("request failed");
    println!("[+] Status: {}", response.status().as_u16());

    // Read response body — THIS triggers the full call chain:
    //   SslStream::ssl_read(buf: &[u8])
    //     → SslRef::read(buf: &[u8])
    //       → SSL_read(..., buf.as_ptr() as *mut c_void, len)
    //         SSL_read WRITES decrypted data through the *mut derived from &[u8]
    //         This is UNDEFINED BEHAVIOR: writing through an immutable reference
    println!("[*] Reading response body (triggers vulnerable SslRef::read)...");
    let mut buf = [0u8; 4096];
    let n = response.body_mut().data(&mut buf).expect("body read failed");

    let body = String::from_utf8_lossy(&buf[..n]);
    println!("[+] Body: {}", body);

    server.join().unwrap();

    println!();
    println!("=== Vulnerability Evidence ===");
    println!("The response was successfully read, but the read went through:");
    println!("  ssl_base.rs:117  fn read(&mut self, buf: &[u8]) -> c_int");
    println!("  ssl_base.rs:117    unsafe {{ SSL_read(..., buf.as_ptr() as *mut c_void, len) }}");
    println!();
    println!("  &[u8]  = immutable shared reference (Rust promises: no writes)");
    println!("  SSL_read = C function that WRITES decrypted data into buffer");
    println!("  buf.as_ptr() as *mut c_void = casting const to mutable = UB");
    println!();
    println!("  Fix: change `buf: &[u8]` to `buf: &mut [u8]` and use `buf.as_mut_ptr()`");
}
