---
id: OH-2026-APPVERIFY-001
date: "2026-04-29"
repo: security_appverify
repo_url: https://gitcode.com/openharmony/security_appverify
title: "Lite 版 APPVERI_SetDebugMode() 无授权检查"
cwe: CWE-749
cwe_name: Exposed Dangerous Method or Function
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_appverify/issues/172
author: Zirui
---

### 漏洞编号：
            
CWE-749 (Exposed Dangerous Method or Function)
### 漏洞归属组件
            

### 漏洞归属版本
            
2026.04.23 最新版本
### CVSS V3.0分值
            

### 漏洞简述
            
### 漏洞函数

`APPVERI_SetDebugMode()` 在公共头文件 `app_verify_pub.h:134` 中声明，无任何授权检查：

```c
// app_verify.c:1225-1238 — 无授权检查设置全局调试标志
int32_t APPVERI_SetDebugMode(bool mode) {
    LOG_INFO("set debug mode: %d", mode);
    if (g_isDebugMode == mode) {
        return V_OK;
    }
    int32_t ret = PKCS7_EnableDebugMode(mode);
    if (ret != V_OK) {
        LOG_ERROR("enable pcks7 debug mode failed");
        return ret;
    }
    g_isDebugMode = mode;   // 全局标志，影响所有后续验证
    return V_OK;
}

// app_verify.c:1241-1244 — 同样无授权
void APPVERI_SetActsMode(bool mode) {
    g_isActsMode = mode;
}
```

```c
// app_verify_pub.h:134 — 公共 API 声明，任何链接此库的代码均可调用
int32_t APPVERI_SetDebugMode(bool mode);
```

### 触发路径：g_isDebugMode 导致验证回退到测试 CA

```c
// app_verify.c:401-416 — GetProfileCertTypeBySignInfo
const TrustAppCert *trustCert = GetProfSourceBySigningCert(
    signer, g_trustAppList, sizeof(g_trustAppList) / sizeof(TrustAppCert));
if (g_isDebugMode && trustCert == NULL) {                     // line 406
    trustCert = GetProfSourceBySigningCert(
        signer, g_trustAppListTest,                            // line 407-408: 回退到测试 CA
        sizeof(g_trustAppListTest) / sizeof(TrustAppCert));
}

// app_verify.c:432-445 — GetAppCertTypeBySignInfo（同模式）
const TrustAppCert *trustCert = GetAppSourceBySigningCert(
    signer, g_trustAppList, sizeof(g_trustAppList) / sizeof(TrustAppCert));
if (g_isDebugMode && trustCert == NULL) {                     // line 437
    trustCert = GetAppSourceBySigningCert(
        signer, g_trustAppListTest,                            // line 438-439: 回退到测试 CA
        sizeof(g_trustAppListTest) / sizeof(TrustAppCert));
}
```

### 触发步骤

1. 攻击者在同一进程中加载共享库（如通过合法应用捆绑恶意 .so）
2. 调用 `APPVERI_SetDebugMode(true)` — 无任何授权检查
3. `g_isDebugMode` 全局标志设为 true，影响进程内所有后续验证
4. 测试签名的应用包通过 `g_trustAppListTest` 中的测试 CA 验证成功
### 影响性分析说明
            
### 影响

- **签名验证绕过**：测试 CA（如 `CN=Huawei CBG Software Signing Service CA Test`）签名的应用可通过验证
- **全局影响**：一旦设置，进程内所有后续验证均受影响
- **IoT 设备风险**：Lite 版本面向 IoT/嵌入式设备，进程隔离和整体安全性较弱
### 原理分析
            

### 受影响版本
            

### 规避方案或消减措施
            
### 建议修复（伪代码）

```c
// ===== 方案：添加调用者验证 =====
int32_t APPVERI_SetDebugMode(bool mode) {
+   // 验证调用者为系统级进程
+   if (getuid() != 0 && getgid() != 0) {
+       LOG_ERROR("Unauthorized caller: uid=%d", getuid());
+       return V_ERR_PERMISSION_DENIED;
+   }
    LOG_INFO("set debug mode: %d", mode);
    if (g_isDebugMode == mode) {
        return V_OK;
    }
    int32_t ret = PKCS7_EnableDebugMode(mode);
    if (ret != V_OK) {
        return ret;
    }
    g_isDebugMode = mode;
    return V_OK;
}

// 或：如果此函数仅供内部使用，移除公共声明
// app_verify_pub.h:
- int32_t APPVERI_SetDebugMode(bool mode);
```
