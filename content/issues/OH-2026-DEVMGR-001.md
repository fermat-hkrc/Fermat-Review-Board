---
id: OH-2026-DEVMGR-001
date: "2026-05-03"
repo: distributedhardware_device_manager
repo_url: https://gitcode.com/openharmony/distributedhardware_device_manager
title: "IpcServerStub::OnRemoteRequest 缺少调用者身份验证"
severity: HIGH
cwe: CWE-862
cwe_name: Missing Authorization
status: CONFIRMED_REAL
issue_url: https://gitcode.com/openharmony/distributedhardware_device_manager/issues/2426
author: fermat-hkrc
---

## 问题描述

### IpcServerStub::OnRemoteRequest 缺少鉴权

```cpp
// services/service/src/ipc/standard/ipc_server_stub.cpp:306
int32_t IpcServerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    // 分发 IPC 请求，无任何调用者身份验证
    switch (code) {
        case CLIENT_CODE_3RD:
            // 直接委托给 ipcServiceStub3rd_，无鉴权
            return ipcServiceStub3rd_->OnRemoteRequest(code, data, reply, option);
        case CLIENT_CODE:
            // 直接委托给 IPCObjectStub，无鉴权
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        default:
            // 仅读取接口令牌（描述符匹配，非权限检查）
            if (!data.ReadInterfaceToken()) {
                return ERR_INVALID_STATE;
            }
            // ...
    }
}
```

### 缺失的安全检查

`IpcServerStub::OnRemoteRequest` 的各个分支中缺少以下关键验证：

- `CLIENT_CODE_3RD` 分支：**无任何验证**，直接委托给第三方 IPC Stub 处理
- `CLIENT_CODE` 分支：**无任何验证**，直接委托给 `IPCObjectStub` 处理
- `default` 分支：仅有 `ReadInterfaceToken()`（验证接口描述符匹配），这是**反序列化保护**，不是**权限检查**

所有分支均缺少：
- 无 `VerifyAccessToken()` / `CheckPermission()` 调用（无法验证调用者权限）
- 无 `GetCallingUid()` / `GetCallingPid()` 调用（无法识别调用者身份）
- 无 `IPCSkeleton::IsLocalCalling()` 检查（无法区分本地/远程调用）

### 对比：其他 OpenHarmony 组件的正确做法

OpenHarmony 中其他成熟的 IPC Stub 实现通常在 `OnRemoteRequest` 入口处添加调用者身份验证：

```cpp
// 正确做法示例（参考其他 OpenHarmony 组件）
int32_t SomeStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string descriptor = SomeStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        return ERR_INVALID_STATE;
    }

    if (!IPCSkeleton::IsLocalCalling()) {
        auto callingUid = IPCSkeleton::GetCallingUid();
        // 验证调用者权限
    }
    // ...
}
```

## 触发条件

1. 任意进程可通过 ServiceManager 获取 Device Manager 服务的 IPC 代理
2. 构造 IPC 消息发送到 `IpcServerStub`，使用 `CLIENT_CODE_3RD` 或 `CLIENT_CODE` 代码，无需任何权限即可触发对应处理逻辑
3. 即使使用 `default` 分支，仅需匹配正确的接口描述符（可从公开源码获取）即可通过验证

## 影响

- **CLIENT_CODE_3RD 分支**: 未授权进程可通过第三方 IPC 代理访问设备管理功能，包括设备发现、认证、绑定等操作
- **CLIENT_CODE 分支**: 未授权进程可直接访问设备管理的核心 IPC 对象，绕过所有访问控制
- **设备管理安全**: 攻击者可未经授权地执行设备绑定/解绑、获取设备列表、操控设备间通信等敏感操作
- **横向移动**: 攻击者可利用未授权的设备管理能力在设备间横向移动，扩大攻击范围

## 建议修复

在 `OnRemoteRequest` 入口添加调用者身份验证：

```cpp
int32_t IpcServerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
+   // 添加调用者身份验证
+   if (!IPCSkeleton::IsLocalCalling()) {
+       auto callingUid = IPCSkeleton::GetCallingUid();
+       auto callingPid = IPCSkeleton::GetCallingPid();
+       // 验证调用者是否持有设备管理相关权限
+       // 建议使用 VerifyAccessToken 或 CheckPermission
+   }

    switch (code) {
        case CLIENT_CODE_3RD:
            return ipcServiceStub3rd_->OnRemoteRequest(code, data, reply, option);
        case CLIENT_CODE:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        default:
            if (!data.ReadInterfaceToken()) {
                return ERR_INVALID_STATE;
            }
            // ...
    }
}
```

对于 `CLIENT_CODE_3RD` 和 `CLIENT_CODE` 分支，也建议在委托前添加接口令牌检查。

## 涉及文件

- `services/service/src/ipc/standard/ipc_server_stub.cpp` (line 306)

感谢您的关注！
