---
id: OH-2026-CRYPTO-002
date: "2026-05-19"
repo: openHiTLS
repo_url: https://gitcode.com/openHiTLS/openhitls
title: "XTS mode outLen formula in documentation always yields multiple of 16, but implementation does not"

status: CONFIRMED_FIXED
issue_url: https://gitcode.com/openHiTLS/openhitls/issues/149
affected_version: "*"
component: crypto
file_paths:
  - include/crypto/crypt_eal_cipher.h
author: Toan
---

## Summary

The documentation for XTS mode in `include/crypto/crypt_eal_cipher.h:159-162` states that `outLen = (inLen / 16 - 2) * 16`, which always produces a multiple of 16. The actual implementation does not always return a multiple of 16, meaning callers relying on the documented formula may allocate insufficient buffer space.

## Problem

The documented formula:

```
1. When data is input for the first time, outLen = (inLen / 16 - 2) * 16.
2. Enter the encrypted data for multiple times. At this time, outLen = ((inLen + cache) / 16 - 2) * 16.
```

Both expressions always yield a multiple of 16 due to integer division by 16 followed by multiplication by 16. However, the implementation does not always produce output lengths that are multiples of 16, making the documentation misleading.

A unit test confirming the discrepancy is provided at:
https://github.com/openHiTLS/openHiTLS/commit/34cea5020c740a503539f84cc3142b01374fa8df

The issue was confirmed as a documentation bug, not an implementation bug.

## Trigger Conditions

1. Caller reads the XTS mode documentation in `crypt_eal_cipher.h`
2. Caller uses the documented formula to calculate expected output buffer size
3. Caller allocates buffer based on `(inLen / 16 - 2) * 16`
4. Implementation returns a different (potentially larger) output length
5. Buffer overflow or truncation may occur

## Impact

- **Buffer miscalculation**: Callers trusting the documented formula may allocate insufficient buffers for XTS mode output
- **Misleading API contract**: Developers cannot rely on the documented behavior for correct buffer sizing

## Suggested Fix

Update the documentation in `crypt_eal_cipher.h:159-162` to accurately describe the actual output length calculation, removing the claim that `outLen` is always a multiple of 16.