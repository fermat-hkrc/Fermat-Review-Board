---
id: OH-2026-COMMON-EVENT-004
date: "2026-08-31"
repo: notification_common_event_service
repo_url: https://gitcode.com/openharmony/notification_common_event_service
title: "两套 NAPI SubscriberInstance 生命周期字段未统一同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 4
affected_version: "6f5e69cb84cf9e779810a17694779dc62b02850d"
component: Common Event NAPI Subscriber
language: C++
file_paths:
  - interfaces/kits/napi/common_event/src/common_event.cpp
  - interfaces/kits/napi/napi_common_event/src/napi_common_event.cpp
author: Zirui
vendor: public
---

## 漏洞概述

Common Event 两套 NAPI `SubscriberInstance` 实现对 `env_` 和 `tsfn_` 使用了不一致的同步。setter 无锁写入这些生命周期字段，而环境清理、析构和事件回调在 `envMutex_` 下读取或清理它们。复用 subscriber、环境销毁和异步事件回调重叠时会形成实际数据竞争。

## 根本原因

**位置**：

- `interfaces/kits/napi/common_event/src/common_event.cpp`
- `interfaces/kits/napi/napi_common_event/src/napi_common_event.cpp`

```cpp
void SubscriberInstance::SetEnv(napi_env env)
{
    env_ = env; // 未持有 envMutex_
}

void SubscriberInstance::SetThreadSafeFunction(napi_threadsafe_function tsfn)
{
    tsfn_ = tsfn; // 未持有 envMutex_
}
```

`ClearEnv`、析构和 `OnReceiveEvent` 使用 `envMutex_` 访问相同字段。`SetCallbackRef` 只持有另一把 `refMutex_`，删除旧引用时又读取没有被该锁保护的 `env_`。

## 影响

- 事件回调可能丢失或访问错误的 N-API 环境。
- thread-safe function 或 callback reference 可能被错误释放、重复使用或泄漏。
- 极端交错下可导致调用应用进程崩溃。

## 触发条件

同一调用进程复用 subscriber 再次订阅，同时发生 JS/ArkTS 环境清理或异步事件回调。首次订阅发生在注册前，风险主要集中在重复订阅和销毁阶段。

## 修复建议

所有 `env_`、`tsfn_` 和相关 callback reference 的读写、替换与清理都应使用统一的生命周期锁。更稳妥的方案是明确一次性初始化和关闭状态，关闭后拒绝重新设置或投递回调。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
