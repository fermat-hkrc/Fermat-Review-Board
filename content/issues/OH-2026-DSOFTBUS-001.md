---
id: OH-2026-DSOFTBUS-001
date: "2026-05-07"
repo: communication_dsoftbus
repo_url: https://gitcode.com/openharmony/communication_dsoftbus
title: "BusCenterExObjStub 和 TransSpecObjectStub 的 OnRemoteRequest 缺少调用者身份验证"
cwe: CWE-862
cwe_name: Missing Authorization
status: SUBMITTED
language: "C++"
issue_url: https://gitcode.com/openharmony/communication_dsoftbus/issues/9200
author: Zirui
---




## 问题描述

### 1. BusCenterExObjStub::OnRemoteRequest

```cpp
// core/bus_center/extend/src/bus_center_ex_obj_stub.cpp:49
int32_t BusCenterExObjStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    // 直接通过 dlsym 解析的函数指针处理请求，无任何鉴权
    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }
    // fallback: 委托给 IPCObjectStub，同样无鉴权
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
```

### 2. TransSpecObjectStub::OnRemoteRequest

```cpp
// core/transmission/broadcast/src/trans_spec_object_stub.cpp:55
int32_t TransSpecObjectStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    // 相同的 dlsym 委托模式，无任何鉴权
    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }
    // fallback: 委托给 IPCObjectStub，同样无鉴权
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
```

### 漏洞模式分析

两个 IPC Stub 具有完全相同的漏洞模式：

1. **dlsym 委托**: 通过 `dlsym` 在运行时解析 `OnRemoteRequest` 处理函数指针
2. **零鉴权**: 在委托前后均无任何形式的调用者身份验证
3. **不安全的 fallback**: 当 `onRemoteRequestFunc_` 为 nullptr 时，回退到 `IPCObjectStub::OnRemoteRequest()`，该基类同样不执行权限检查

两个 Stub 均缺少：
- 无 `ReadInterfaceToken()` 调用（无法验证调用者接口描述符）
- 无 `VerifyAccessToken()` / `CheckPermission()` 调用（无法验证调用者权限）
- 无 `GetCallingUid()` / `GetCallingPid()` 调用（无法识别调用者身份）
- 无 `IPCSkeleton::IsLocalCalling()` 检查（无法区分本地/远程调用）

### 对比：其他 OpenHarmony 组件的正确做法

OpenHarmony 中其他安全的 IPC Stub 实现通常在 `OnRemoteRequest` 入口处添加完整的鉴权链：

```cpp
// 正确做法示例
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

1. 任意进程可通过 ServiceManager 获取 SoftBus 服务的 IPC 代理
2. 构造 IPC 消息发送到 `BusCenterExObjStub` 或 `TransSpecObjectStub`，无需任何权限即可触发对应处理逻辑
3. 由于使用 dlsym 动态解析，攻击者可通过枚举 code 值触发不同的处理函数

## 影响

- **BusCenterExObjStub**: 未授权进程可访问总线中心扩展功能，包括设备发现、组网管理、总线中心信息查询等敏感操作
- **TransSpecObjectStub**: 未授权进程可访问传输广播功能，可能操控设备间数据传输通道
- **dsoftbus 核心安全**: 这两个 Stub 是 dsoftbus 核心通信框架的一部分，缺少鉴权可能导致：
  - 未授权的设备发现和组网
  - 设备间通信通道被恶意操控
  - 敏感设备信息泄露
- **分布式安全**: dsoftbus 是 OpenHarmony 分布式能力的通信基础，其安全问题可影响所有依赖分布式能力的服务

## 建议修复

在两个 Stub 的 `OnRemoteRequest` 入口添加调用者身份验证：

```cpp
// BusCenterExObjStub 修复示例（TransSpecObjectStub 同理）
int32_t BusCenterExObjStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
+   // 添加接口令牌验证
+   std::u16string descriptor = BusCenterExObjStub::GetDescriptor();
+   std::u16string remoteDescriptor = data.ReadInterfaceToken();
+   if (descriptor != remoteDescriptor) {
+       return ERR_INVALID_STATE;
+   }
+
+   // 添加调用者身份验证
+   if (!IPCSkeleton::IsLocalCalling()) {
+       auto callingUid = IPCSkeleton::GetCallingUid();
+       auto callingPid = IPCSkeleton::GetCallingPid();
+       // 验证调用者是否持有分布式软总线相关权限
+       // 建议使用 VerifyAccessToken 或 CheckPermission
+   }

    if (onRemoteRequestFunc_ != nullptr) {
        return onRemoteRequestFunc_(code, data, reply, option);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
```

`TransSpecObjectStub::OnRemoteRequest` 需要应用同样的修复。

## 涉及文件

- `core/bus_center/extend/src/bus_center_ex_obj_stub.cpp` (line 49)
- `core/transmission/broadcast/src/trans_spec_object_stub.cpp` (line 55)

