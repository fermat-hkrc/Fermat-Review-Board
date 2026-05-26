---
id: PBT-HITLS-2026-CRYPTO-002
date: "2026-05-19"
repo: openHiTLS
repo_url: https://gitcode.com/openHiTLS/openhitls
title: "[Bug]: Incorrect Comments about the reserve blocks property/invariant in XTS mode documentation"
cwe: CWE-1078
cwe_name: Inappropriate Source Code Style, Formatting, and Commenting
severity: LOW
status: CONFIRMED_FIXED
language: C
issue_url: https://gitcode.com/openHiTLS/openhitls/issues/148
affected_version: "*"
component: crypto
file_paths:
  - include/crypto/crypt_eal_cipher.h
author: Toan
---

## Summary

The XTS mode documentation in `include/crypto/crypt_eal_cipher.h:159-162` states that when the total length of input data plus buffer is less than 32 blocks, the output is 0. This is incorrect — the implementation does not guarantee this property.

The documented claim:

```
In XTS mode, update reserves the last two blocks for final processing, If the total length of the input data
plus the buffer is less than 32 blocks, the output is 0.
```

**Expected for inLen=32**: `outLen = (32/16 - 2) * 16 = 0`

The actual implementation behaves like OpenSSL and does not produce 0 output in this case. Unit test confirming the discrepancy:
https://github.com/thanhtoantnt/openHiTLS/commit/c454407b592fed5479888c982cbbbf82e68f801a

Confirmed as a documentation bug, not an implementation bug.

## Trigger Conditions

1. Caller reads the XTS mode "reserve blocks" documentation in `crypt_eal_cipher.h`
2. Caller expects `outLen = 0` when `inLen < 32` (or `inLen = 32`)
3. Implementation returns a non-zero output length, following OpenSSL behavior
4. Disconnect between documented invariant and actual behavior

## Impact

- **Misleading API contract**: Developers cannot rely on the documented "reserve blocks" invariant for correct buffer sizing
- **Behavior mismatch**: Callers expecting zero output for small inputs will receive unexpected data

## Suggested Fix

Update the documentation in `crypt_eal_cipher.h:159-162` to accurately describe the reserve-blocks behavior matching the OpenSSL-compatible implementation, removing the incorrect claim that output is 0 when total input plus buffer is less than 32 blocks.