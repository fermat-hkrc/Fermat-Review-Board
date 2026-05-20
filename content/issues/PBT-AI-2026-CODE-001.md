---
id: PBT-AI-2026-CODE-001
date: "2026-05-20"
repo: agent-studio
repo_url: https://gitcode.com/openJiuwen/agent-studio
title: "[Bug]: _sanitize_identifier — Multiple Identifier Validity Failures"
cwe: CWE-20
cwe_name: Improper Input Validation
severity: MEDIUM
status: CONFIRMED_FIXED
issue_url: https://gitcode.com/openJiuwen/agent-studio/issues/821
affected_version: "*"
component: workflow_code_generator
file_paths:
  - openjiuwen_studio/core/manager/workflow_code_generator.py
author: Toan
---

## Summary

`_sanitize_identifier` in `workflow_code_generator.py:1031-1041` contains three bugs that produce invalid Python identifiers, causing `SyntaxError` in generated code or silent variable name collisions.

## Vulnerable Code

```python
def _sanitize_identifier(name: str) -> str:
    s = re.sub(r"[^\w]", "_", name, flags=re.UNICODE)  # replace non-word chars
    s = re.sub(r"^[0-9]+", "", s)                       # strip leading ASCII digits
    s = re.sub(r"_+", "_", s)
    s = s.strip("_").lower()
    return s or "component"
```

## Bug A — Special-char + digit → invalid Python identifier

When a name starts with a special character followed by a digit (e.g. `'#1'`, `'@0'`, `'-0'`):

1. Step 1: `'#1'` → `'_1'` (special char replaced with `_`)
2. Step 2: `^[0-9]+` does **not** match (string starts with `_`, not a digit)
3. Step 4: `strip('_')` removes the leading `_` → `'1'`
4. Result: `'1'` — starts with a digit, fails `isidentifier()`

```
'#1'      -> '1'      isidentifier=False  ← SyntaxError in generated code
'@0'      -> '0'      isidentifier=False
'12 34ab' -> '34ab'   isidentifier=False
```

**Realistic trigger:** User names a workflow node `"#1"`, `"Step #2"`, or `"-Node"` — common in practice.

## Bug B — Numeric-only names all collide to `"component"`

All purely numeric inputs produce the same fallback name:

```
"1"   -> ""  -> "component"
"42"  -> ""  -> "component"
"999" -> ""  -> "component"
```

`^[0-9]+` strips all digits, leaving `""`, then `s or "component"` fires. Multiple components named `"1"`, `"2"`, `"3"` all get `var_name="component"` in generated code — later definitions silently overwrite earlier ones with no deduplication guard.

## Bug C — Six Unicode `\w` characters are not valid Python identifiers (LOW)

`re.UNICODE` on `[^\w]` keeps `²` (U+00B2), `³` (U+00B3), `¹` (U+00B9), `¼` (U+00BC), `½` (U+00BD), `¾` (U+00BE) as "word chars", but Python's `isidentifier()` rejects them. A component named `"½"` or `"²"` produces an invalid identifier. Realistic risk is LOW — these characters are unlikely component names in production.

## Trigger Conditions

1. User names a workflow node with a special character followed by a digit (`"#1"`, `"@0"`, `"-Node"`)
2. `_sanitize_identifier` is called once per name in the code generator
3. Bug A: leading `_` from special char is stripped, leaving a digit-prefixed identifier
4. Bug B: purely numeric names all collapse to `"component"`, silently overwriting each other
5. Generated Python source contains invalid variable names → `SyntaxError` at runtime

## Impact

- **SyntaxError in generated code**: Invalid identifiers like `'1'` or `'0'` cause generated Python to fail at parse time
- **Silent variable collision**: Multiple numeric-named components all map to `"component"`, later definitions overwrite earlier ones
- **No error at generation time**: The code generator does not validate the sanitized result with `isidentifier()`

## Suggested Fix

```python
def _sanitize_identifier(name: str) -> str:
    # ASCII-only: avoids Unicode \w chars that fail isidentifier()
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    # Strip ALL leading digits AND underscores together (fixes Bug A)
    s = re.sub(r"^[0-9_]+", "", s)
    s = re.sub(r"_+", "_", s)
    s = s.strip("_").lower()
    return s or "component"
```