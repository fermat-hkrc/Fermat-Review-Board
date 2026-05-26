---
id: PBT-KUASAR-2026-KERNEL-002
date: "2026-05-19"
repo: kuasar
repo_url: https://github.com/kuasar-io/kuasar
title: "checked_compute_delta intermediate sum overflows i64 — clock synchronization fails for large timestamps"
cwe: CWE-190
cwe_name: Integer Overflow or Wraparound
severity: HIGH
status: CONFIRMED_REAL
language: Rust
issue_url: https://github.com/kuasar-io/kuasar/issues/244
affected_version: "*"
component: vmm/sandbox
file_paths:
  - vmm/sandbox/src/client.rs
author: Toan
---

## Summary

`checked_compute_delta` in `vmm/sandbox/src/client.rs:369` fails when timestamps are large, even though the mathematical result fits in `i64`. The intermediate sum `delta_client + delta_server` overflows before division by 2, causing an `Err` that breaks host-VM clock synchronization.

## Vulnerable Code

```rust
// vmm/sandbox/src/client.rs:369
fn checked_compute_delta(
    client_ts_send: i64,
    client_ts_recv: i64,
    server_ts_send: i64,
    server_ts_recv: i64,
) -> Result<i64> {
    let delta_client = client_ts_recv - client_ts_send; // can overflow
    let delta_server = server_ts_recv - server_ts_send;
    // ...
    let sum = delta_client + delta_server; // overflow when both deltas are large
    sum / 2  // intended, but sum already wrapped
}
```

### Reproduction

```rust
checked_compute_delta(i64::MAX, 0, 0, i64::MAX)
// Returns Err("overflow"), should return Ok(i64::MAX)
```

The mathematical result `(i64::MAX + i64::MAX) / 2 = i64::MAX` fits in `i64`, but the intermediate sum `i64::MAX + i64::MAX` overflows before division.

## Trigger Conditions

1. Host and VM exchange timestamps for clock synchronization
2. Timestamp deltas (computed as `recv - send`) approach `i64::MAX / 2`
3. `delta_client + delta_server` overflows `i64` before the division by 2
4. Function returns `Err`, clock sync aborts
5. VM runs with unsynchronized clock, leading to time-dependent failures

## Impact

- **Clock synchronization failure**: Host-VM time sync breaks for large timestamps, causing VM clock drift
- **Cascading failures**: TLS certificate validation, token expiration, and time-sensitive operations may fail unexpectedly
- **Silent in production**: Error propagates but may not surface clearly in logs

## Suggested Fix

Use wider intermediate arithmetic or restructure to avoid overflow:

```rust
// Option 1: Cast to i128 for intermediate math
fn checked_compute_delta(
    client_ts_send: i64,
    client_ts_recv: i64,
    server_ts_send: i64,
    server_ts_recv: i64,
) -> Result<i64> {
    let delta_client = (client_ts_recv as i128) - (client_ts_send as i128);
    let delta_server = (server_ts_recv as i128) - (server_ts_send as i128);
    let sum = delta_client + delta_server;
    let result = sum / 2;
    if result >= i64::MIN as i128 && result <= i64::MAX as i128 {
        Ok(result as i64)
    } else {
        Err(Error::Overflow)
    }
}

// Option 2: Divide-before-add pattern
// (delta_client / 2) + (delta_server / 2) + (delta_client % 2 + delta_server % 2) / 2
```