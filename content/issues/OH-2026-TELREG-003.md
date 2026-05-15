---
id: OH-2026-TELREG-003
date: "2026-05-07"
repo: telephony_state_registry
repo_url: https://gitcode.com/openharmony/telephony_state_registry
title: "TelephonyStateRegistryService::UpdateNetworkState 在 EXT_WRAPPER 分支未检查 network..."
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/telephony_state_registry/issues/254
author: Zirui
---

---

## 漏洞概述

`TelephonyStateRegistryService::UpdateNetworkState` 函数在 line 391 对 `networkState` 做了 nullptr 检查（用于 deep copy），但在 line 403-419 的 observer 通知循环中，当 `TELEPHONY_EXT_WRAPPER.onNetworkStateUpdated_` 非空时，直接调用 `networkState->Marshalling(data)`（line 410），未检查 `networkState` 是否为 nullptr。

## 漏洞详情

### 问题代码

**文件**: `services/src/telephony_state_registry_service.cpp:378-423`

```cpp
int32_t TelephonyStateRegistryService::UpdateNetworkState(int32_t slotId, const sptr<NetworkState> &networkState)
{
    // ... permission checks ...
    std::unique_lock<std::shared_mutex> uniLock(lock_);
    searchNetworkState_[slotId] = networkState;
    if (networkState != nullptr) {  // ← line 391: 此处有 null check
        sptr<NetworkState> searchNetworkState = sptr<NetworkState>::MakeSptr();
        if (searchNetworkState != nullptr) {
            MessageParcel networkData;
            networkState->Marshalling(networkData);
            searchNetworkState->ReadFromParcel(networkData);
            searchNetworkState_[slotId] = searchNetworkState;
        }
    }
    uniLock.unlock();
    std::shared_lock<std::shared_mutex> lock(lock_);
    for (size_t i = 0; i < stateRecords_.size(); i++) {
        TelephonyStateRegistryRecord r = stateRecords_[i];
        if (r.IsExistStateListener(...) && (r.slotId_ == slotId) &&
            r.telephonyObserver_ != nullptr) {
            if (TELEPHONY_EXT_WRAPPER.onNetworkStateUpdated_ != nullptr) {
                sptr<NetworkState> networkStateExt = new NetworkState();
                MessageParcel data;
                networkState->Marshalling(data);  // ← line 410: 无 null check，崩溃
                networkStateExt->ReadFromParcel(data);
                TELEPHONY_EXT_WRAPPER.onNetworkStateUpdated_(slotId, r, networkStateExt, networkState);
                r.telephonyObserver_->OnNetworkStateUpdated(slotId, networkStateExt);
            } else {
                r.telephonyObserver_->OnNetworkStateUpdated(slotId, networkState);  // ← 传 nullptr 给 observer
            }
        }
    }
    // ...
}
```

### 对比：同函数正确实现

Line 391 已经证明 `networkState` 可以为 nullptr（否则不需要检查），但 line 410 的代码路径未做同样的保护。

### 触发条件

1. `UpdateNetworkState` 被调用时 `networkState` 参数为 nullptr
2. 系统加载了 TELEPHONY_EXT_WRAPPER 扩展（`onNetworkStateUpdated_` 非空）
3. 存在已注册的 OBSERVER_MASK_NETWORK_STATE 监听器
4. Line 410 解引用 nullptr → SIGSEGV

### 攻击面分析

- `UpdateNetworkState` 通过 IPC 从 `TelephonyStateRegistryStub::OnUpdateNetworkState` 调用
- Stub 层（line 334-348）对 `Unmarshalling` 返回值有 nullptr 检查，正常 IPC 路径不会传入 nullptr
- 但函数签名接受 `const sptr<NetworkState>&`，内部其他调用路径可能传入 nullptr
- Line 391 的 null check 证明开发者预期此参数可能为 nullptr
- 当 EXT_WRAPPER 扩展加载时，服务进程崩溃（DoS）

### 影响

- telephony_state_registry 服务进程崩溃
- 所有依赖电话状态注册服务的应用功能中断
- 服务重启期间电话状态通知丢失

## 修复建议

```cpp
    for (size_t i = 0; i < stateRecords_.size(); i++) {
        TelephonyStateRegistryRecord r = stateRecords_[i];
        if (r.IsExistStateListener(TelephonyObserverBroker::OBSERVER_MASK_NETWORK_STATE) && (r.slotId_ == slotId) &&
            r.telephonyObserver_ != nullptr) {
            if (TELEPHONY_EXT_WRAPPER.onNetworkStateUpdated_ != nullptr) {
+               if (networkState == nullptr) {
+                   TELEPHONY_LOGE("networkState is nullptr, skip ext wrapper");
+                   continue;
+               }
                sptr<NetworkState> networkStateExt = new NetworkState();
                MessageParcel data;
                networkState->Marshalling(data);
```

## 涉及文件

- `services/src/telephony_state_registry_service.cpp` (line 410) — 缺失 null check
