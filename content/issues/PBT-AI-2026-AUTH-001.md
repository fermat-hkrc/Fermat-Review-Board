---
id: PBT-AI-2026-AUTH-001
date: "2026-04-24"
repo: agent-studio
repo_url: https://gitcode.com/openJiuwen/agent-studio
title: "[Bug]: mask_api_key(key, visible_chars=0) — Full Key Leaked"
cwe: CWE-200
cwe_name: Exposure of Sensitive Information
severity: MEDIUM
status: CONFIRMED_FIXED
language: Python
issue_url: https://gitcode.com/openJiuwen/agent-studio/issues/822
affected_version: "*"
component: security_utils
file_paths:
  - openjiuwen_studio/core/manager/model_manager/utils/security_utils.py
author: Toan
---

## Summary

`mask_api_key(key, visible_chars=0)` leaks the full API key. When `visible_chars=0`, Python's slice `api_key[-0:]` evaluates identically to `api_key[0:]` — the entire string — because `-0 == 0`. The function returns stars followed by the full unmasked key.

## Vulnerable Code

```python
# security_utils.py:302
return "*" * (len(api_key) - visible_chars) + api_key[-visible_chars:]
```

### Trace

```
mask_api_key("sk-abc123", 0):
  Check: len("sk-abc123") <= 0  →  False  (not triggered)
  Falls through to:
    "*" * (9 - 0) + "sk-abc123"[-0:]
  = "*********" + "sk-abc123"   ← full key appended
  = "*********sk-abc123"
```

Confirmed for every non-empty input:
```
mask_api_key('sk-abc',  0) = '******sk-abc'
mask_api_key('hello',   0) = '*****hello'
mask_api_key('x',       0) = '*x'
```

### Current Exposure

All existing call sites use the default `visible_chars=4` — no call site currently passes `0`. `visible_chars` is not exposed through any router or API parameter. This is a **latent bug**: no exploit path today, but any future caller that passes `0` intending "show nothing" will instead leak the full key.

## Trigger Conditions

1. A caller invokes `mask_api_key(key, visible_chars=0)` expecting "show nothing"
2. Python evaluates `api_key[-0:]` as `api_key[0:]` — the full string
3. Function returns stars concatenated with the complete unmasked API key
4. Key is logged, displayed, or stored in plaintext

## Impact

- **API key leakage**: Full key appears in output instead of being masked
- **Latent risk**: No current exploit path, but any future caller passing `0` will leak keys
- **Negative values also misbehave**: `visible_chars=-1` exposes more chars than intended

## Suggested Fix

```python
if visible_chars <= 0:
    return "*" * len(api_key)
return "*" * (len(api_key) - visible_chars) + api_key[-visible_chars:]
```