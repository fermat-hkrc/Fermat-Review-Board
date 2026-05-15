---
id: OH-2026-CRYPTO-001
date: "2026-04-23"
repo: security_crypto_framework
repo_url: https://gitcode.com/openharmony/security_crypto_framework
title: 密钥协商共享密钥（异步路径）未清零
cwe: CWE-244
cwe_name: Improper Clearing of Heap Memory Before Release
status: CONFIRMED_FIXED
affected_version: "2026.04.23 最新版本"
component: security_crypto_framework
issue_url: https://gitcode.com/openharmony/security_crypto_framework/issues/575
file_paths:
  - common/src/memory.c
  - common/src/blob.c
  - plugin/openssl_plugin/crypto_operation/cipher/src/cipher_aes_common.c
  - frameworks/js/napi/crypto/src/napi_key_agreement.cpp
author: Zirui
---

## 漏洞概述

`HcfFree()` 是对 `free()` 的空壳封装，释放内存时不执行清零操作，导致敏感密钥材料残留在堆中。同一代码库中已有安全清零函数 `HcfBlobDataClearAndFree()`，但未被统一使用。密钥协商的异步路径使用了不安全的 `HcfFree`，而同步路径正确使用了安全清理函数，形成不一致的安全隐患。

## 问题根因

`HcfFree()` 是对 `free()` 的空壳封装，无内存清零：

```c
// common/src/memory.c:34-39
void HcfFree(void *addr) {
    if (addr != NULL) {
        free(addr);  // 无 memset_s，敏感数据残留在堆中
    }
}
```

同一代码库中已有安全清零函数但未统一使用：

```c
// common/src/blob.c:32-42 — 正确的安全清理函数
void HcfBlobDataClearAndFree(HcfBlob *blob) {
    (void)memset_s(blob->data, blob->len, 0, blob->len);  // 先清零
    HcfFree(blob->data);
    blob->data = NULL;
    blob->len = 0;
}
```

## 触发路径 1：Cipher AAD/IV/Tag 未清零

```c
// cipher_aes_common.c:62-85 — FreeCipherData
void FreeCipherData(CipherData **data) {
    if ((*data)->aad != NULL) {
        HcfFree((*data)->aad);   // line 72: AAD（附加认证数据）未清零释放
    }
    if ((*data)->iv != NULL) {
        HcfFree((*data)->iv);    // line 75: IV（初始化向量）未清零释放
    }
    if ((*data)->tag != NULL) {
        HcfFree((*data)->tag);   // line 79: Tag（认证标签）未清零释放
    }
    HcfFree(*data);
}
```

**触发**：任何使用 AES-GCM/CCM 加解密的操作都会分配 AAD/IV/Tag 内存，操作结束后通过 `FreeCipherData` 释放，敏感数据留在堆中。

## 触发路径 2：密钥协商共享密钥（异步路径）未清零

```cpp
// napi_key_agreement.cpp:83-89 — FreeKeyAgreementCtx（异步回调清理）
if (ctx->returnSecret.data != nullptr) {
    HcfFree(ctx->returnSecret.data);     // line 84: 共享密钥未清零释放
    ctx->returnSecret.data = nullptr;
    ctx->returnSecret.len = 0;
}
```

对比同步路径（正确实现）：

```cpp
// napi_key_agreement.cpp:353 — 同步路径
HcfBlobDataClearAndFree(&returnSecret);  // line 353: 正确清零后释放
```

**触发**：JS 应用调用 `generateSecret()` 异步接口进行 ECDH/DH/X25519 密钥协商时，共享密钥通过异步回调路径释放，使用 `HcfFree` 而非 `HcfBlobDataClearAndFree`。同步接口 `generateSecretSync()` 则正确使用了安全清理。

## 影响分析

| 影响 | 说明 |
|------|------|
| **共享密钥泄漏** | ECDH 共享密钥是协议中最敏感的值，泄漏后可解密全部后续通信 |
| **IV/Tag 泄漏** | GCM 模式下 IV 泄漏可削弱加密强度，Tag 泄漏可伪造认证消息 |
| **堆残留** | 释放后的内存页可被其他进程复用，导致跨进程敏感数据泄漏 |

## 修复建议

```diff
 // ===== 方案一：新增 HcfSecureFree =====
+void HcfSecureFree(void *addr, size_t size) {
+    if (addr != NULL) {
+        (void)memset_s(addr, size, 0, size);
+        free(addr);
+    }
+}

 // 修复 FreeCipherData:
 void FreeCipherData(CipherData **data) {
     if ((*data)->aad != NULL) {
-        HcfFree((*data)->aad);
+        HcfSecureFree((*data)->aad, (*data)->aadLen);
     }
     if ((*data)->iv != NULL) {
-        HcfFree((*data)->iv);
+        HcfSecureFree((*data)->iv, (*data)->ivLen);
     }
     if ((*data)->tag != NULL) {
-        HcfFree((*data)->tag);
+        HcfSecureFree((*data)->tag, (*data)->tagLen);
     }
 }

 // 修复 napi_key_agreement.cpp 异步路径:
 if (ctx->returnSecret.data != nullptr) {
-    HcfFree(ctx->returnSecret.data);
+    HcfBlobDataClearAndFree(&ctx->returnSecret);
 }
```
