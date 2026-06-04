---
id: HITLS-2026-MEM-001
date: "2026-03-30"
repo: openHiTLS
repo_url: https://gitcode.com/openHiTLS/openhitls
title: "[Bug]: Memory leak in ConstructUserPsk — pskSession not freed on identity allocation failure"
cwe: CWE-401
cwe_name: Missing Release of Memory after Effective Lifetime
severity: MEDIUM
status: CONFIRMED_FIXED
language: C
issue_url: https://gitcode.com/openHiTLS/openhitls/issues/145
affected_version: "*"
component: tls/handshake
file_paths:
  - tls/handshake/send/src/send_client_hello.c
author: Toan
---

## Summary

In `ConstructUserPsk` (`send_client_hello.c:375-399`), `userPsk->pskSession` is allocated via `HITLS_SESS_Dup` at line 388. If the subsequent `BSL_SAL_Calloc` for `userPsk->identity` fails at line 392, the error path frees `userPsk` but never frees `userPsk->pskSession`, leaking the duplicated session object.

## Vulnerable Code

```c
static UserPskList *ConstructUserPsk(HITLS_Session *sessoin, const uint8_t *identity, uint32_t identityLen,
    uint8_t curIndex)
{
    // ...
    UserPskList *userPsk = BSL_SAL_Calloc(1, sizeof(UserPskList));
    if (userPsk == NULL) {
        return NULL;
    }
    userPsk->pskSession = HITLS_SESS_Dup(sessoin); // ← ALLOCATION
    userPsk->identity = BSL_SAL_Calloc(1, identityLen);
    if (userPsk->identity == NULL) {
        BSL_SAL_FREE(userPsk);  // ← LEAK: pskSession not freed before freeing userPsk
        return NULL;
    }
    // ...
}
```

## Trigger Conditions

1. TLS 1.3 handshake constructs a PSK list via `ConstructUserPsk`
2. `HITLS_SESS_Dup` succeeds, allocating `userPsk->pskSession`
3. Subsequent `BSL_SAL_Calloc` for `userPsk->identity` fails (OOM)
4. Error path calls `BSL_SAL_FREE(userPsk)` but never frees `userPsk->pskSession`
5. Session object is leaked

## Impact

- **Memory leak**: Each failed identity allocation leaks a duplicated TLS session object
- **Resource exhaustion**: Under memory pressure or repeated handshake attempts, leaked sessions accumulate
- **TLS handshake path**: Triggered during client hello construction — affects any TLS 1.3 PSK resumption flow

## Suggested Fix

Free `userPsk->pskSession` before freeing `userPsk` in the error path:

```c
if (userPsk->identity == NULL) {
    HITLS_SESS_Free(userPsk->pskSession);  // ← ADD
    BSL_SAL_FREE(userPsk);
    return NULL;
}
```