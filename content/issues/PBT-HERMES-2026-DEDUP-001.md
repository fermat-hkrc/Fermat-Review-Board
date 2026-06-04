---
id: PBT-HERMES-2026-DEDUP-001
date: "2026-06-01"
repo: hermes-webui
repo_url: https://github.com/nesquena/hermes-webui
title: "[Bug]: merge_session_messages_append_only fails to deduplicate legacy state messages"
cwe: CWE-1024
cwe_name: Comparison Using Incorrect Factors
severity: MEDIUM
status: CONFIRMED_FIXED
issue_url: https://github.com/nesquena/hermes-webui/issues/3346
affected_version: "*"
component: session-merge
stars: 12431
file_paths:
  - api/models.py
author: Toan
language: Python
---

## Summary

`merge_session_messages_append_only` in `api/models.py` fails to deduplicate state messages that share a legacy merge key (messages without explicit `id`/`message_id` fields). Two independent gaps: an early-return path that skips dedup entirely when the sidecar is empty, and a main merge loop that only records `message_id` keys in `seen_message_keys` so duplicate legacy keys pass through.

## Impact

- **Severity: MEDIUM** — users see the same message twice in chat history when state DB contains duplicate rows
- No error/warning produced
- Database compaction, recovery, or race conditions can produce such duplicate rows, so the bug is reachable in normal operation

## Root Cause

### Gap 1: Early return path (line 3954)

```python
if not sidecar_messages:
    if watermark_timestamp is not None:
        return [
            msg for msg in state_messages
            if (timestamp := _message_timestamp_as_float(msg)) is not None
            and timestamp <= watermark_timestamp
        ]
    return state_messages   # ← returns state verbatim, no dedup
```

When `sidecar_messages` is empty, returns `state_messages` directly (or filtered) without any deduplication.

### Gap 2: Main merge loop (line 4052)

```python
if key[0] == "message_id":
    seen_message_keys.add(key)   # ← ONLY for message_id keys
```

`seen_message_keys` only tracks `message_id` keys in the state loop. Legacy keys like `('legacy', 'user', 'hello', '', '', '')` are never recorded — a second state message with the same legacy key passes the `if key in seen_message_keys` check and gets appended again.

## Reproduction

```python
from api.models import merge_session_messages_append_only

state = [
    {"role": "user", "content": "hello"},
    {"role": "user", "content": "hello"},  # duplicate
]

# Gap 1: empty sidecar → early return, no dedup
result = merge_session_messages_append_only([], state)
print(len(result))  # 2 (expected 1)

# Gap 2: non-empty sidecar → main loop skips legacy dedup
sidecar = [{"role": "system", "content": "sys", "id": "s1"}]
result = merge_session_messages_append_only(sidecar, state)
print(len(result))  # 3 (expected 2)
```

| Sidecar | State | Expected | Actual |
|---|---|---|---|
| `[]` | `[a, a]` | 1 | **2** (Gap 1) |
| `[system]` | `[a, a]` | 2 | **3** (Gap 2) |
| `[{id, a}]` | `[a, a]` | 1 | **2** (Gap 2) |

## Suggested Fix

### Fix Gap 2 — main loop

```python
# before
if key[0] == "message_id":
    seen_message_keys.add(key)

# after
seen_message_keys.add(key)
```

Every message that reaches the append point should have its key recorded, regardless of prefix.

### Fix Gap 1 — early return

```python
if not sidecar_messages:
    if watermark_timestamp is not None:
        filtered = [
            msg for msg in state_messages
            if (timestamp := _message_timestamp_as_float(msg)) is not None
            and timestamp <= watermark_timestamp
        ]
    else:
        filtered = state_messages
    seen = set()
    result = []
    for msg in filtered:
        key = _session_message_merge_key(msg)
        if key not in seen:
            seen.add(key)
            result.append(msg)
    return result
```
