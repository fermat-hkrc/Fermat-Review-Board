---
id: PBT-OG-2026-ARITH-001
date: "2026-04-23"
repo: openGauss-server
repo_url: https://gitcode.com/opengauss/openGauss-server
title: "[Bug]: Modulo-by-zero silently returns dividend in A/B/C compatibility modes"
cwe: CWE-682
cwe_name: Incorrect Calculation
severity: MEDIUM
status: CONFIRMED_FIXED
issue_url: https://gitcode.com/opengauss/openGauss-server/issues/8127
affected_version: "7.0.0-RC2"
component: arithmetic
file_paths:
  - src/common/backend/utils/adt/int.cpp
  - src/common/backend/utils/adt/int8.cpp
  - src/common/backend/utils/adt/numeric.cpp
author: Toan
language: C++
---

## Summary

In openGauss 7.0.0-RC2, the modulo operator (`%`) silently returns the dividend instead of raising a division-by-zero error when the divisor is zero, in all compatibility modes except `PG`. This violates the arithmetic property `x % 0 → ERROR` and matches none of the target databases the modes are designed to emulate.

## Vulnerable Code

All five modulo functions share the same conditional pattern. Only `PG_FORMAT` raises an error; all other modes return the dividend silently.

**`int4mod`** — `src/common/backend/utils/adt/int.cpp:1086-1096`
```cpp
if (unlikely(arg2 == 0)) {
    if (DB_IS_CMPT(PG_FORMAT)) {
        ereport(ERROR, (errcode(ERRCODE_DIVISION_BY_ZERO), errmsg("division by zero")));
        PG_RETURN_NULL();
    }
    /* zero is allowed to be divisor */
    PG_RETURN_INT32(arg1);   // ← returns dividend!
}
```

**`int2mod`** — `src/common/backend/utils/adt/int.cpp:1116-1126` — identical pattern

**`int8mod`** — `src/common/backend/utils/adt/int8.cpp:593-603` — identical pattern

**`int1mod`** — `src/common/backend/utils/adt/int.cpp:1809-1818` — identical pattern

**`numeric_mod`** — `src/common/backend/utils/adt/numeric.cpp:2556-2568`
```cpp
if (0 == cmp_var(&arg2, &const_zero)) {
    if (DB_IS_CMPT(PG_FORMAT)) {
        ereport(ERROR, (errcode(ERRCODE_DIVISION_BY_ZERO), errmsg("division by zero")));
        PG_RETURN_NULL();
    }
    PG_RETURN_NUMERIC(num1);  // ← returns dividend!
}
```

## Evidence

```sql
-- Tested across all DBCOMPATIBILITY modes:
SELECT 5 % 0;

-- db_a (A):   Returns 5   ← WRONG
-- db_b (B):   Returns 5   ← WRONG
-- db_c (C):   Returns 5   ← WRONG
-- db_pg (PG): ERROR: division by zero ← CORRECT
```

### Cross-Mode Results

| Mode | `5 % 0` | Expected |
|------|---------|----------|
| A (Oracle) | `5` (dividend) | `ERROR` |
| B (MySQL) | `5` (dividend) | `NULL` |
| C (Teradata) | `5` (dividend) | `ERROR` |
| **PG (PostgreSQL)** | **ERROR: division by zero** | **ERROR ✓** |

## Why This Is a Bug (Not a Design Choice)

None of the target databases return the dividend for modulo-by-zero — openGauss A/B/C matches none of them:

| Target Database | `5 MOD 0` Behavior |
|----------------|-------------------|
| Oracle (A_FORMAT target) | `ORA-01476: divisor is equal to zero` |
| MySQL (B_FORMAT target) | Returns `NULL` |
| Teradata (C_FORMAT target) | `2616: Invalid character data` |
| PostgreSQL (PG_FORMAT target) | `ERROR: division by zero` |

openGauss A/B/C returns `5` — a behavior that matches **none** of the target databases.

## Inconsistency with Division Functions

The division functions (`int4div`, `int2div`, `int1div`, etc.) do **not** have this format-dependent behavior — they always raise `ERRCODE_DIVISION_BY_ZERO` regardless of compatibility mode. Only the modulo functions have this conditional, making the behavior inconsistent even within the same mode.

## Impact

- **Silent arithmetic error**: code expecting an exception receives a garbage result
- **Inconsistent behavior**: mode PG errors, modes A/B/C silently return wrong value
- **Mathematical property violated**: `a = (a % b) * 1` — but `5 = (5 % 0) * 1 = 5 * 1 = 5` hides the error
- **Applications** that divide by user-supplied values may get wrong results in A/B/C without any indication

## Suggested Fix

Remove the format-conditional guard from all five modulo functions and always raise `ERRCODE_DIVISION_BY_ZERO`, consistent with the division functions:

```cpp
if (unlikely(arg2 == 0)) {
    ereport(ERROR, (errcode(ERRCODE_DIVISION_BY_ZERO), errmsg("division by zero")));
    PG_RETURN_NULL();
}
```

For B_FORMAT (MySQL compatibility), returning `NULL` instead of raising an error would be the most accurate fix.
