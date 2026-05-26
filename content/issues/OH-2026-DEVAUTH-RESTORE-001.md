---
id: OH-2026-DEVAUTH-RESTORE-001
date: "2026-04-29"
repo: security_device_auth
repo_url: https://gitcode.com/openharmony/security_device_auth
title: "RESTORE_CODE 路径跳过 CheckPermission 权限检查"
cwe: CWE-862
cwe_name: Missing Authorization
status: SUBMITTED
language: C
issue_url: https://gitcode.com/openharmony/security_device_auth/issues/1037
author: Zirui
---

### 漏洞编号：
            
CWE-862 (Missing Authorization)
### 漏洞归属组件
            

### 漏洞归属版本
            

### CVSS V3.0分值
            

### 漏洞简述
            
### 正常路径：所有方法经 CheckPermission

```cpp
// ipc_dev_auth_stub.cpp:260-310 — HandleDeviceAuthCall
int32_t ServiceDevAuth::HandleDeviceAuthCall(uint32_t code, MessageParcel &data, ...) {
    switch (code) {
        case static_cast<uint32_t>(DevAuthInterfaceCode::DEV_AUTH_CALL_REQUEST):
            ret = GetMethodId(data, methodId);
            ret = CheckPermission(methodId);  // line 277: 所有正常调用必须通过权限检查
            if (ret != HC_SUCCESS) {
                return ret;
            }
            serviceCall = GetCallMethodByMethodId(methodId);
            ret = serviceCall(reqParams, reqParamNum, ...);
    }
}
```

`CheckPermission`（permission_adapter.cpp:192-207）执行完整权限链：
```cpp
int32_t CheckPermission(int32_t methodId) {
    AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();     // line 194: 获取调用者令牌
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);  // line 195
    if (!CheckTokenType(tokenType, methodId)) { return DENIED; }  // line 196: 令牌类型检查
    if (tokenType == TOKEN_NATIVE && CheckNativeTokenInfo(...) != SUCCESS) {
        return DENIED;  // line 199: Native 令牌 APL 等级 + 进程白名单
    }
    if (CheckACLPermission(methodId) != SUCCESS) { return DENIED; }  // line 202: ACL 权限
    return SUCCESS;
}
```

### 漏洞路径：RESTORE_CODE 跳过上述全部检查

```cpp
// ipc_dev_auth_stub.cpp:320-335 — OnRemoteRequest
int32_t ServiceDevAuth::OnRemoteRequest(uint32_t code, MessageParcel &data, ...) {
    std::u16string readToken = data.ReadInterfaceToken();  // line 324
    bool isRestoreCall = ((code == RESTORE_CODE) &&         // line 325: code == 14701
        (readToken == std::u16string(u"OHOS.Updater.RestoreData")));  // 且令牌匹配
    if (readToken != GetDescriptor() && !isRestoreCall) {
        return -1;  // line 326-328: 令牌不匹配且非 Restore → 拒绝
    }
    if (isRestoreCall) {
        return HandleRestoreCall(data, reply);  // line 331: 直接调用，未经 CheckPermission
    } else {
        return HandleDeviceAuthCall(code, data, reply, option);  // line 333: 正常路径
    }
}
```

### HandleRestoreCall 执行的敏感操作

```cpp
// ipc_dev_auth_stub.cpp:226-246 — HandleRestoreCall
int32_t ServiceDevAuth::HandleRestoreCall(MessageParcel &data, MessageParcel &reply) {
    int32_t osAccountId = DEFAULT_UPGRADE_OS_ACCOUNT_ID;
    data.ReadInt32(osAccountId);  // line 231: 从 IPC 读取账户 ID
    int32_t res = ExecuteAccountAuthCmd(osAccountId, UPGRADE_DATA, nullptr, nullptr);
    // line 233: 执行数据升级/迁移操作
    ReloadOsAccountDb(osAccountId);  // line 234: 重新加载账户数据库
    reply.WriteInt32(res);
}
```

### 触发步骤

1. 攻击者构造 IPC 消息：`code = 14701`, 接口令牌 = `"OHOS.Updater.RestoreData"`
2. `OnRemoteRequest` 匹配 `isRestoreCall` 条件，直接调用 `HandleRestoreCall`
3. 跳过 `CheckPermission` 的令牌类型检查、APL 等级验证、进程白名单、ACL 权限检查
4. 执行 `ExecuteAccountAuthCmd(UPGRADE_DATA)` 和 `ReloadOsAccountDb`

### 影响性分析说明
            
### 影响

- 绕过完整权限链触发数据升级和账户数据库重载
- 唯一保护是接口令牌字符串 `"OHOS.Updater.RestoreData"`（静态常量，可从公开共享库获取）

### 原理分析
            

### 受影响版本
            

### 规避方案或消减措施
            
### 建议修复（伪代码）

```cpp
// ===== 方案：为 Restore 路径添加权限验证 =====
int32_t ServiceDevAuth::OnRemoteRequest(uint32_t code, MessageParcel &data, ...) {
    std::u16string readToken = data.ReadInterfaceToken();
    bool isRestoreCall = ((code == RESTORE_CODE) &&
        (readToken == std::u16string(u"OHOS.Updater.RestoreData")));
    if (readToken != GetDescriptor() && !isRestoreCall) {
        return -1;
    }
+   if (isRestoreCall) {
+       // 验证调用者 UID 是否为系统级进程
+       auto callingUid = IPCSkeleton::GetCallingUid();
+       if (callingUid >= FIRST_APPLICATION_UID) {  // 非系统 UID
+           LOGE("Restore call from unauthorized uid: %d", callingUid);
+           return HC_ERR_IPC_PERMISSION_DENIED;
+       }
        return HandleRestoreCall(data, reply);
    } else {
        return HandleDeviceAuthCall(code, data, reply, option);
    }
}
```
