---
id: ARKUI-2026-MEMLEAK-001
date: "2026-04-14"
repo: arkui_ace_engine
repo_url: https://gitcode.com/openharmony/arkui_ace_engine
title: "[Bug]: UnmarshallStyledStringDescriptor leaks spanString on repeated calls"
cwe: CWE-401
cwe_name: Missing Release of Memory after Effective Lifetime
severity: MEDIUM
status: CONFIRMED_FIXED
issue_url: https://gitcode.com/openharmony/arkui_ace_engine/issues/75638
affected_version: master
component: styled_string
file_paths:
  - frameworks/core/interfaces/native/node/styled_string_impl.cpp
author: Toan
language: C++
---

## Summary

`UnmarshallStyledStringDescriptor` in `frameworks/core/interfaces/native/node/styled_string_impl.cpp:520` allocates a new `MutableSpanString` and assigns it to `descriptor->spanString` without checking if the descriptor already contains a valid spanString. If called multiple times on the same descriptor, the previous allocation is leaked.

## Vulnerable Code

**`frameworks/core/interfaces/native/node/styled_string_impl.cpp:520`**
```cpp
MutableSpanString* spanString = new MutableSpanString(u"");
spanString->DecodeTlvExt(vec, spanString, nullptr);
descriptor->spanString = reinterpret_cast<void*>(spanString);  // OVERWRITES WITHOUT FREEING
```

On repeated calls, the previous `spanString` allocation is overwritten without being freed, causing a memory leak.

## Suggested Fix

```cpp
if (descriptor->spanString) {
    auto* oldSpanString = reinterpret_cast<SpanString*>(descriptor->spanString);
    delete oldSpanString;
}
MutableSpanString* spanString = new MutableSpanString(u"");
// ...
```

## Similar Pattern

The same leak pattern appears in:
- `frameworks/core/interfaces/native/node/styled_string_impl.cpp:611`
- `frameworks/core/interfaces/native/node/styled_string_impl.cpp:945`
