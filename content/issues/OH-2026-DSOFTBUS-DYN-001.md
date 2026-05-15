---
id: OH-2026-DSOFTBUS-DYN-001
date: "2026-04-29"
repo: communication_dsoftbus
repo_url: https://gitcode.com/openharmony/communication_dsoftbus
title: "DSoftBus 动态加载 Stub 的 OnRemoteRequest 缺少授权检查"
cwe: CWE-20
cwe_name: Improper Input Validation
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/communication_dsoftbus/issues/9228
author: Zirui
---

### 漏洞编号：
            
CWE-862 (Missing Authorization)
### 漏洞归属组件
            

### 漏洞归属版本
            

### CVSS V3.0分值
            

### 漏洞简述
            
## 问题描述

### 1. BusCenterExObjStub::OnRemoteRequest

```cpp
// bus_center_ex_obj_stub.cpp:49-67
int32_t BusCenterExObjStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    // 无 VerifyAccessToken / CheckPermission / GetCallingUid 检查
    // 直接调用 onRemoteRequestFunc_（通过 dlsym 动态加载的函数指针）
    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
```

### 2. TransSpecObjectStub::OnRemoteRequest

```cpp
// trans_spec_object_stub.cpp:55-72
int32_t TransSpecObjectStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    // 无 VerifyAccessToken / CheckPermission / GetCallingUid 检查
    // 直接调用 onRemoteRequestFunc_
    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
```

两个 Stub 均通过 `dlsym` 从动态库加载 `onRemoteRequestFunc_` 函数指针，然后在 `OnRemoteRequest` 中直接调用，无任何授权验证。

### 对比：同仓库中的正确做法

同仓库中 `SoftBusServerStub` 的各 Inner handler 均调用 `PermissionVerify()` 进行权限检查：

```cpp
// softbus_server_stub.cpp — 正确做法
int32_t SoftBusServerStub::ActiveMetaNodeInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = PermissionVerify(SERVER_ACTIVE_META_NODE);  // ✓ 权限检查
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    // ... 处理请求
}
```

## 触发条件

1. 攻击者进程可向 BusCenterExObjStub / TransSpecObjectStub 发送 IPC 请求
2. 无需任何权限即可触发 `onRemoteRequestFunc_` 中的操作
### 影响性分析说明
            
## 影响

- **BusCenterExObjStub**：处理总线中心扩展操作，未授权调用可能影响设备发现和组网
- **TransSpecObjectStub**：处理传输层特殊操作，未授权调用可能影响数据传输通道
### 原理分析
            

### 受影响版本
            

### 规避方案或消减措施
            
## 建议修复

在 `OnRemoteRequest` 入口添加授权检查：

```cpp
int32_t BusCenterExObjStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
+   AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
+   if (AccessTokenKit::VerifyAccessToken(callerToken, OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER)
+       != PermissionState::PERMISSION_GRANTED) {
+       LNN_LOGE("permission denied");
+       return SOFTBUS_PERMISSION_DENIED;
+   }
    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
```
