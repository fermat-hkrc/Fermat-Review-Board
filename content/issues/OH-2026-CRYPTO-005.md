---
id: OH-2026-CRYPTO-005
date: "2026-05-19"
repo: openHiTLS
repo_url: https://gitcode.com/openHiTLS/openhitls
title: "[Bug]: Reinit succeeds from INIT state (before any Update)"
cwe: CWE-385
cwe_name: Missing State Tracking
severity: MEDIUM
status: SUBMITTED
issue_url: https://gitcode.com/openHiTLS/openhitls/issues/157
affected_version: "*"
component: hmac
file_paths:
  - crypto/hmac/src/hmac.c
author: Toan
---

## Summary

`CRYPT_HMAC_Reinit` is intended to reset the running hash back to the post-`Init` baseline, allowing the same key to be reused for a new message without calling `Init` again. Per the state model, it should only be valid from `UPDATE` or `FINAL` state — after at least one `Update` or `Final` has been called. However, it succeeds when called immediately after `Init`, before any `Update`.

## Vulnerable Code

```c
// crypto/hmac/src/hmac.c:226
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL) {  // only checks pointers
        ...
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    return CRYPT_SUCCESS;  // always succeeds once Init has run
}
```

The `CRYPT_HMAC_Ctx` struct has no state field. `Reinit` only checks that `copyCtx` is non-NULL, which is true as soon as `Init` has run, so it succeeds from any post-`Init` state including `INIT`.

Reference model defines:
```
Reinit is valid from:   UPDATE, FINAL
Reinit is invalid from: NEW, INIT, DEINIT
```

### Reproducer

```c
CRYPT_HMAC_Init(mac, key, 32);        // state: INIT
int32_t ret = CRYPT_HMAC_Reinit(mac);  // reference model: should return ERR_STATE
ASSERT_NE(ret, CRYPT_SUCCESS);         // FAILS: ret == CRYPT_SUCCESS (0)
```

## Trigger Conditions

1. Caller initializes an HMAC context with `CRYPT_HMAC_Init`
2. Caller calls `CRYPT_HMAC_Reinit` before any `Update` or `Final`
3. `Reinit` succeeds (returns `CRYPT_SUCCESS`) instead of returning a state error
4. Caller cannot detect incorrect API usage

## Impact

- **State machine violation**: `Reinit` from `INIT` state is a no-op (`iCtx` and `mdCtx` already hold the same state), so output is still correct — but the state machine contract is broken
- **No misuse detection**: Callers cannot detect incorrect usage patterns; silent success masks bugs in caller code
- **Lower severity than CRYPTO-004**: No wrong output, but violated invariant prevents callers from catching errors

## Suggested Fix

Add a `hasData` flag to `CRYPT_HMAC_Ctx` that is set after the first `Update` call and cleared by `Init` and `Deinit`. `Reinit` checks the flag before proceeding:

```c
// crypto/hmac/src/hmac.c — struct addition
struct HMAC_Ctx {
    CRYPT_MAC_AlgId hmacId;
    EAL_MdMethod method;
    void *mdCtx;
    void *oCtx;
    void *iCtx;
    bool hasData;    // ← ADD: set true on first Update, cleared by Init/Deinit
};

// crypto/hmac/src/hmac.c — Reinit fix
int32_t CRYPT_HMAC_Reinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.copyCtx == NULL ||
        ctx->mdCtx == NULL || ctx->iCtx == NULL ||
        !ctx->hasData) {                             // ← ADD check
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    ctx->method.copyCtx(ctx->mdCtx, ctx->iCtx);
    ctx->hasData = false;                            // ← RESET for next round
    return CRYPT_SUCCESS;
}
```