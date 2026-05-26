---
id: PBT-HITLS-2026-CRYPTO-003
date: "2026-05-19"
repo: openHiTLS
repo_url: https://gitcode.com/openHiTLS/openhitls
title: "[Bug]: Any operation (Update, Reinit, Final) succeeds silently after Deinit — producing wrong output"
cwe: CWE-459
cwe_name: Incomplete Cleanup
severity: HIGH
status: CONFIRMED_REAL
language: C
issue_url: https://gitcode.com/openHiTLS/openhitls/issues/156
affected_version: "*"
component: hmac
file_paths:
  - crypto/hmac/src/hmac.c
author: Toan
---

## Summary

`CRYPT_HMAC_Deinit` clears the internal hash state of each sub-context (`mdCtx`, `iCtx`, `oCtx`) but does not null those pointers. Method function pointers (`method.update`, `method.copyCtx`, etc.) are also left intact. As a result, every subsequent operation (`Update`, `Reinit`, `Final`) passes its NULL guard and runs on cleared state — producing cryptographically incorrect output with a `CRYPT_SUCCESS` return code.

## Vulnerable Code

```c
// crypto/hmac/src/hmac.c:236
int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)ctx->method.deinit(ctx->mdCtx);  // clears state, but...
    (void)ctx->method.deinit(ctx->iCtx);   // ...does NOT null any pointer
    (void)ctx->method.deinit(ctx->oCtx);
    return CRYPT_SUCCESS;
}
```

After `Deinit`, `ctx->mdCtx != NULL` and `ctx->method.update != NULL`, so downstream guards in `Update`, `Reinit`, and `Final` all pass. Operations execute on zeroed state and return `CRYPT_SUCCESS`.

### Case A — Update after Deinit succeeds silently

```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out, &outLen);
CRYPT_HMAC_Deinit(mac);

int32_t ret = CRYPT_HMAC_Update(mac, msg, 64);
ASSERT_NE(ret, CRYPT_SUCCESS);  // FAILS: ret == CRYPT_SUCCESS (0)
```

### Case B — Reinit+Final after Deinit produces wrong output

```c
CRYPT_HMAC_Init(mac, key, 32);
CRYPT_HMAC_Update(mac, msg, 64);
CRYPT_HMAC_Final(mac, out1, &outLen1);
CRYPT_HMAC_Deinit(mac);

int32_t reinitRet = CRYPT_HMAC_Reinit(mac);         // succeeds — should fail
CRYPT_HMAC_Update(mac, msg, 64);                     // succeeds — on cleared state
int32_t finalRet = CRYPT_HMAC_Final(mac, out2, &outLen2);
ASSERT_NE(finalRet, CRYPT_SUCCESS);  // FAILS: finalRet == CRYPT_SUCCESS (0)
// out2 is cryptographically wrong output
```

## Trigger Conditions

1. Caller initializes an HMAC context and performs one or more operations
2. Caller calls `CRYPT_HMAC_Deinit` to clear the context
3. Caller inadvertently calls `Update`, `Reinit`, or `Final` without re-initializing
4. All operations succeed with `CRYPT_SUCCESS`, but operate on cleared state
5. `Final` emits MAC bytes derived from zeroed internal state — incorrect but accepted by MAC verification

## Impact

- **Silent wrong MAC output**: `Final` after `Deinit` returns `CRYPT_SUCCESS` with cryptographically incorrect output. MAC verification using this output would accept values it should reject.
- **No error signal**: Callers have no way to detect the invalid state — every function returns `CRYPT_SUCCESS`
- **Security**: An attacker who can trigger Deinit then Final on a context could produce a valid-looking MAC without knowing the key, potentially bypassing authentication

## Suggested Fix

Null the three sub-context pointers inside `CRYPT_HMAC_Deinit` after clearing them:

```c
int32_t CRYPT_HMAC_Deinit(CRYPT_HMAC_Ctx *ctx)
{
    if (ctx == NULL || ctx->method.deinit == NULL) {
        return CRYPT_NULL_INPUT;
    }
    (void)ctx->method.deinit(ctx->mdCtx);
    ctx->mdCtx = NULL;                     // ← ADD
    (void)ctx->method.deinit(ctx->iCtx);
    ctx->iCtx = NULL;                      // ← ADD
    (void)ctx->method.deinit(ctx->oCtx);
    ctx->oCtx = NULL;                      // ← ADD
    return CRYPT_SUCCESS;
}
```

With `mdCtx == NULL`, downstream guards in `Update`, `Reinit`, and `Final` correctly reject the invalid state. No changes to those functions are required.