---
id: PBT-OH-2026-DEVMGR-003
date: "2026-05-19"
repo: distributedhardware_device_manager
repo_url: https://gitcode.com/openharmony/distributedhardware_device_manager
title: "GeneratePinCode off-by-one loop condition returns short PIN ~16% of the time, causing intermittent pairing failure"
cwe: CWE-193
cwe_name: Off-by-One Error
severity: HIGH
status: SUBMITTED
language: "C++"
issue_url: https://gitcode.com/openharmony/distributedhardware_device_manager/issues/2440
affected_version: "5.0+"
component: dm_random
file_paths:
  - utils/src/dm_random.cpp
author: Toan
---

## Summary

`GeneratePinCode(pinLength)` in `utils/src/dm_random.cpp:101` returns `pinLength - 1` characters approximately 1/pinLength of the time (~16% for 6-digit PINs). This causes device pairing to fail intermittently with no clear error.

## Vulnerable Code

```cpp
// utils/src/dm_random.cpp:101
// left_digit_count = pinLength - 1
while (pinCode.length() < left_digit_count) {   // '<' allows exact-length exit
```

When `std::to_string(gen())` appends a sum that brings the total to exactly `pinLength - 1`, the loop exits one iteration early. `substr(0, pinLength)` on a shorter string silently returns fewer characters.

### Example (pinLength=6)

```
Initial:  GenRandInt(1,9) = "3"           → length 1
Iter 1:   gen() = "7254"                  → length 5
Check:    5 < 5? FALSE → exit             ← too early
Result:   substr(0, 6) on 5-char string → "37254"  ← 5 chars, not 6
```

Downstream validation rejects this: `"37254".length() < DM_MIN_PINCODE_SIZE (6)` → pairing fails.

## Trigger Conditions

1. `GeneratePinCode` is called with `pinLength` (typically 6)
2. Random generation produces a sum that brings `pinCode.length()` to exactly `left_digit_count` (`pinLength - 1`)
3. Loop condition `pinCode.length() < left_digit_count` evaluates false, exits early
4. `substr(0, pinLength)` on the shorter string returns a PIN with fewer characters
5. Downstream check rejects the short PIN → device pairing fails

## Impact

- **Intermittent pairing failure**: ~16% of 6-digit PIN generations produce a short PIN, causing device pairing to fail
- **No clear error**: The short PIN is silently generated; the failure manifests downstream, making diagnosis difficult
- **Affected callers**: `ExportAuthInfo` and any code path calling `GeneratePinCode`

## Suggested Fix

```diff
- while (pinCode.length() < left_digit_count) {
+ while (pinCode.length() <= left_digit_count) {
```

`substr(0, pinLength)` already bounds the result, so overshooting is harmless. The `<=` condition ensures the loop always runs enough iterations.