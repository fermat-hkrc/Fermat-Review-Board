---
id: PBT-KUASAR-2026-KERNEL-001
date: "2026-05-19"
repo: kuasar
repo_url: https://github.com/kuasar-io/kuasar
title: "merge_cpusets returns Err when one operand is empty — empty string split yields unparsable empty element"
cwe: CWE-20
cwe_name: Improper Input Validation
severity: MEDIUM
status: CONFIRMED_FIXED
language: Rust
issue_url: https://github.com/kuasar-io/kuasar/issues/245
affected_version: "*"
component: vmm/sandbox
file_paths:
  - vmm/sandbox/src/utils.rs
author: Toan
---

## Summary

`merge_cpusets` in `vmm/sandbox/src/utils.rs:197` returns `Err` when either operand is an empty string. An empty cpuset means "no CPU affinity specified" and should be valid. The root cause is that `"".split(',')` yields `[""]` (one empty-string element), which fails to parse as `u32`.

## Vulnerable Code

```rust
// vmm/sandbox/src/utils.rs:197
fn merge_cpusets(cpuset1: &str, cpuset2: &str) -> Result<String> {
    // ...
    // When cpuset1 or cpuset2 is "", the split produces [""]
    // which fails to parse as u32, returning Err
}
```

### Reproduction

```rust
merge_cpusets("0", "")   // Returns Err, should return Ok("0")
merge_cpusets("", "0")   // Returns Err, should return Ok("0")
```

A non-empty cpuset merged with an empty one should yield the non-empty cpuset. Instead, the function errors out.

### Root Cause

`"".split(',')` returns an iterator producing `[""]` — a single empty-string element. When the function attempts to parse this element as a `u32`, it fails, causing the entire merge to fail.

## Trigger Conditions

1. Two containers share resources via `merge_resources` (utils.rs:153)
2. One container has a cpuset specified (e.g. `"0-3"`), the other has none (empty string `""`)
3. `merge_cpusets` is called with the empty cpuset as either operand
4. Empty string split yields `[""]`, which fails `u32` parsing → `Err` returned
5. Resource merging fails, container cannot start or receive CPU affinity

## Impact

- **Container startup failure**: Resource merging fails when one container has no CPU affinity, preventing container creation or update
- **No workaround**: Downstream code does not handle the `Err` gracefully in all paths
- **Intermittent**: Only manifests when one side of the merge has an unset cpuset — easily missed in testing

## Suggested Fix

Handle empty cpuset strings before splitting and parsing:

```rust
fn merge_cpusets(cpuset1: &str, cpuset2: &str) -> Result<String> {
    // Treat empty cpuset as "no affinity" — skip it
    if cpuset1.is_empty() {
        return Ok(cpuset2.to_string());
    }
    if cpuset2.is_empty() {
        return Ok(cpuset1.to_string());
    }
    // ... existing merge logic ...
}
```

Alternatively, filter out empty elements after splitting:

```rust
let cpus: Vec<u32> = cpuset.split(',')
    .filter(|s| !s.is_empty())
    .map(|s| s.parse::<u32>())
    .collect::<Result<Vec<_>, _>>()?;
```