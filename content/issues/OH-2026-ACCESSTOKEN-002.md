---
id: OH-2026-ACCESSTOKEN-002
date: "2026-04-29"
repo: security_access_token
repo_url: https://gitcode.com/openharmony/security_access_token
title: "TokenSyncManagerStub::OnRemoteRequest 缺少 VerifyAccessToken 授权检查"
cwe: CWE-190
cwe_name: Integer Overflow or Wraparound
status: SUBMITTED
language: "C++"
issue_url: https://gitcode.com/openharmony/security_access_token/issues/3173
author: Zirui
---

下列还有一个问题，也请您顺便看看：

## TokenSyncManagerStub::OnRemoteRequest 缺少 VerifyAccessToken 授权检查
**CWE**: CWE-862 (Missing Authorization)

## 涉及文件

- `services/tokensyncmanager/src/service/token_sync_manager_stub.cpp` (line 33-80)

## 问题描述

```cpp
// token_sync_manager_stub.cpp:33-80
int32_t TokenSyncManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    // line 37: 仅检查是否为本地调用
    if (!IPCSkeleton::IsLocalCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "non-local calling");
        return SOFTBUS_ERR;
    }

    // line 41-44: 仅验证接口描述符
    std::u16string descriptor = TokenSyncManagerStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        return ERROR;
    }

    // 直接分发到 GetRemoteHapTokenInfoInner / DeleteRemoteHapTokenInfoInner / UpdateRemoteHapTokenInfoInner
    // 无 VerifyAccessToken、CheckPermission 或 IsSameProcess 调用
}
```

### 现有检查与缺失

| 检查项 | 是否存在 | 说明 |
|--------|---------|------|
| IsLocalCalling | ✓ | 仅验证调用来自本机，不验证调用者身份 |
| ReadInterfaceToken | ✓ | 仅验证消息格式，不提供授权 |
| VerifyAccessToken | ✗ | **缺失** — 不验证调用者是否持有相应权限 |
| CheckPermission | ✗ | **缺失** |
| GetCallingUid/Pid | ✗ | **缺失** — 不验证调用者进程身份 |

### 对比：同仓库中的正确做法

同仓库中 `AccessTokenManagerServiceStub::OnRemoteRequest` 实现了完整的授权检查链：

```cpp
// accesstoken_manager_service_stub.cpp（正确做法）
int32_t AccessTokenManagerServiceStub::OnRemoteRequest(...) {
    // 1. ReadInterfaceToken 验证
    // 2. 根据 code 查找对应的 handler
    // 3. handler 内部调用 VerifyAccessToken 验证调用者权限
}
```

## 触发条件

1. 本机上任何进程（包括普通应用进程）可向 TokenSyncManagerService 发送 IPC 请求
2. 只需知道接口描述符字符串（可从公开共享库中获取）
3. `IsLocalCalling` 检查仅排除远程调用，不排除本机恶意进程

## 影响

- **未授权的 Token 操作**：恶意本地进程可调用 `GetRemoteHapTokenInfo`、`DeleteRemoteHapTokenInfo`、`UpdateRemoteHapTokenInfo`
- **分布式权限篡改**：攻击者可删除或修改远端设备的 HAP Token 信息，影响跨设备权限验证
- **安全子系统核心服务**：TokenSyncManager 是权限同步的核心服务，其授权缺失影响整个分布式权限体系

## 建议修复

```cpp
int32_t TokenSyncManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
+   // 验证调用者权限
+   AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
+   if (AccessTokenKit::VerifyAccessToken(callerToken, "ohos.permission.DISTRIBUTED_DATASYNC")
+       != PermissionState::PERMISSION_GRANTED) {
+       LOGE(ATM_DOMAIN, ATM_TAG, "permission denied");
+       return ERR_PERMISSION_DENIED;
+   }

    if (!IPCSkeleton::IsLocalCalling()) {
        // ...
    }
    // ...
}
```
