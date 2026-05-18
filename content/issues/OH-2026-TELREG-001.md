---
id: OH-2026-TELREG-001
date: "2026-05-07"
repo: telephony_state_registry
repo_url: https://gitcode.com/openharmony/telephony_state_registry
title: "TelephonyObserver::OnNetworkStateUpdatedInner 未检查 Unmarshalling 返回值导致空指针崩溃"
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/telephony_state_registry/issues/254
author: Zirui
---


## 漏洞概述

`TelephonyObserver::OnNetworkStateUpdatedInner` 调用 `NetworkState::Unmarshalling(data)` 后未检查返回值是否为 nullptr，直接将结果传递给 `OnNetworkStateUpdated`。下游的 `AniTelephonyObserver::OnNetworkStateUpdated` 和 `EventListenerHandler::WorkNetworkStateUpdated` 均直接解引用该指针（`networkState->GetLongOperatorName()` 等），导致空指针崩溃。

## 漏洞详情

### 问题代码

**文件**: `frameworks/native/observer/src/telephony_observer.cpp:126-132`

```cpp
void TelephonyObserver::OnNetworkStateUpdatedInner(
    MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    sptr<NetworkState> networkState = NetworkState::Unmarshalling(data);
    // ^^^ Unmarshalling 在数据格式异常时返回 nullptr
    OnNetworkStateUpdated(slotId, networkState);  // nullptr 传入，无检查
}
```

### 对比：同仓库正确实现

**文件**: `services/src/telephony_state_registry_stub.cpp:334-348`

```cpp
int32_t TelephonyStateRegistryStub::OnUpdateNetworkState(MessageParcel &data, MessageParcel &reply)
{
    int32_t ret = TELEPHONY_SUCCESS;
    int32_t slotId = data.ReadInt32();
    sptr<NetworkState> result = NetworkState::Unmarshalling(data);
    if (result == nullptr) {  // ← 正确：检查了 nullptr
        TELEPHONY_LOGE("...GetNetworkStatus is null");
        ret = TELEPHONY_ERR_FAIL;
        return ret;
    }
    ret = UpdateNetworkState(slotId, result);
    ...
}
```

### 崩溃路径

```
[IPC] TelephonyObserverProxy::OnNetworkStateUpdated (发送端，networkState 可为 nullptr)
  → Marshalling 跳过 (line 167: if networkState != nullptr)
  → 接收端 MessageParcel 中无 NetworkState 数据
  → TelephonyObserver::OnNetworkStateUpdatedInner
    → NetworkState::Unmarshalling(data) 返回 nullptr
    → OnNetworkStateUpdated(slotId, nullptr)
      → AniTelephonyObserver::OnNetworkStateUpdated (observer_ani.cpp:53)
        → networkState->GetLongOperatorName()  // ← 崩溃：空指针解引用
      → EventListenerHandler::WorkNetworkStateUpdated (event_listener_handler.cpp:830)
        → networkState->GetLongOperatorName()  // ← 崩溃：空指针解引用
```

### 触发条件

1. `TelephonyObserverProxy::OnNetworkStateUpdated` 被调用时 `networkState` 为 nullptr（line 167 跳过 Marshalling）
2. 或者 IPC 消息中的 NetworkState 数据格式异常导致 `Unmarshalling` 失败
3. Observer 端收到消息后直接解引用 nullptr

### 攻击面分析

- `TelephonyObserver` 是客户端侧的 IPC Stub，接收来自 `telephony_state_registry` 服务的通知
- 服务端（`TelephonyStateRegistryService`）在 `SendNetworkStateChanged` 中调用 `TelephonyObserverProxy::OnNetworkStateUpdated`
- 如果服务端传入 nullptr（例如网络状态未初始化时），或 IPC 传输中数据损坏，客户端进程崩溃
- 影响：注册了网络状态监听的应用进程崩溃（DoS）

## 修复建议

```cpp
void TelephonyObserver::OnNetworkStateUpdatedInner(
    MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    sptr<NetworkState> networkState = NetworkState::Unmarshalling(data);
+   if (networkState == nullptr) {
+       TELEPHONY_LOGE("OnNetworkStateUpdatedInner: Unmarshalling NetworkState failed");
+       return;
+   }
    OnNetworkStateUpdated(slotId, networkState);
}
```

## 涉及文件

- `frameworks/native/observer/src/telephony_observer.cpp` (line 130-131) — 缺失 null check
- `frameworks/ets/ani/observer/src/cxx/observer_ani.cpp` (line 55) — 直接解引用
- `frameworks/js/napi/src/event_listener_handler.cpp` (line 842) — 直接解引用
- `frameworks/cj/src/observer_event_handler.cpp` (line 481) — 直接解引用

## 参考

- CWE-476: NULL Pointer Dereference
- 同仓库正确实现：`telephony_state_registry_stub.cpp:339` 的 nullptr 检查
