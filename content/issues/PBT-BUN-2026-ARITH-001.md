---
id: PBT-BUN-2026-ARITH-001
date: "2026-05-29"
repo: bun
repo_url: https://github.com/oven-sh/bun
title: "[Bug]: LinearFifo::ordered_remove_item uses wrong wrap length — panics or corrupts data"
cwe: CWE-682
cwe_name: Incorrect Calculation
severity: MEDIUM
status: CONFIRMED_FIXED
issue_url: https://github.com/oven-sh/bun/issues/31563
affected_version: "unknown"
component: collections
file_paths:
  - src/collections/linear_fifo.rs
author: Toan
language: Rust
---

## Summary

`LinearFifo::ordered_remove_item` computes wrong slice bounds when the readable region wraps around the backing buffer. Both wrapped sub-branches use `count - head` / `head - count` instead of the correct `wrap_len = head + count - buf_len`. Result: panic in debug builds, silent FIFO corruption in release builds.

One in-tree caller exists at `src/runtime/bake/dev_server/source_map_store.rs`.

## Vulnerable Code

`src/collections/linear_fifo.rs` — wrapped branch of `ordered_remove_item`:

```rust
if index < head {
    shift_down_one(&mut buf[index..count - head]);       // ← wrong bound
} else {
    let wrap = unsafe { ptr::read(buf.as_ptr()) };
    shift_down_one(&mut buf[index..]);
    unsafe { ptr::write(buf.as_mut_ptr().add(buf_len - 1), wrap) };
    shift_down_one(&mut buf[..head - count]);             // ← wrong bound
}
```

## Root Cause

When readable data wraps, the readable region splits into two segments:
- **tail:** `buf[head..buf_len)`
- **wrapped prefix:** `buf[..wrap_len)` where `wrap_len = head + count - buf_len`

Both sub-branches use the wrong expression:
- `index < head` branch uses `count - head` → underflows when `head > count`, wrong otherwise
- `index >= head` branch uses `head - count` → underflows when `head < count`, wrong otherwise

## Reproducer

A valid wrapped state reaching the `index >= head` sub-branch:

| Step | Operation | `head` | `count` | `buf_len` |
|------|-----------|--------|---------|-----------|
| 1 | write 12 items | 0 | 12 | 16 |
| 2 | read 8 items | 8 | 4 | 16 |
| 3 | write 10 items | 8 | 14 | 16 |
| 4 | call `ordered_remove_item(6)` | 8 | 14 | 16 |

```
Step 3: wraps because buf_len - head = 8 < count = 14
  tail length: buf_len - head = 8
  wrapped prefix: head + count - buf_len = 8 + 14 - 16 = 6

Step 4: index = 8 + 6 = 14 → index >= head branch
head - count = 8 - 14 → usize underflow → panic (debug) / corruption (release)
```

Other wrapped sub-branch reachable with `head=12, count=8, buf_len=16` where `count - head` underflows.

## Suggested Fix

Compute `wrap_len` once and use it in both branches:

```rust
let wrap_len = head + count - buf_len;

if index < head {
    shift_down_one(&mut buf[index..wrap_len]);
} else {
    let wrap = unsafe { ptr::read(buf.as_ptr()) };
    shift_down_one(&mut buf[index..]);
    unsafe { ptr::write(buf.as_mut_ptr().add(buf_len - 1), wrap) };
    shift_down_one(&mut buf[..wrap_len]);
}
```

## Test Coverage Gap

No existing tests validate `ordered_remove_item` against wrapped layouts. Needed regression tests:
1. Create wrapped readable data, remove item where `index >= head`
2. Create wrapped readable data, remove item where `index < head`
3. Verify FIFO contents against reference `Vec`
4. Cover both `head < count` and `head > count` wrapped states
