---
id: OH-2026-COMMON-EVENT-003
date: "2026-08-31"
repo: notification_common_event_service
repo_url: https://gitcode.com/openharmony/notification_common_event_service
title: "StaticSubscriberConnection 无锁读取 action_ 导致断连决策竞态"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "6f5e69cb84cf9e779810a17694779dc62b02850d"
component: Static Subscriber Connection
language: C++
file_paths:
  - services/include/static_subscriber_connection.h
  - services/src/static_subscriber_connection.cpp
  - services/src/ability_manager_helper.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`NotifyEvent` 和 `RemoveEvent` 在 `StaticSubscriberConnection::mutex_` 下修改 `action_`，但 `IsEmptyAction` 直接无锁执行 `action_.empty()`。Ability Manager 的连接完成回调不经过断连任务使用的 FFRT queue，因此它可以与延时断连任务并发访问同一个 vector。

## 根本原因

**位置**：`services/include/static_subscriber_connection.h`

```cpp
bool IsEmptyAction() const
{
    return action_.empty(); // 未持有 mutex_
}
```

`AbilityManagerHelper::DisconnectAbility` 先调用受锁的 `RemoveEvent`，该函数返回并释放锁后再调用 `IsEmptyAction`。与此同时，`OnAbilityConnectDone` 可以直接进入 `NotifyEvent` 并在 `mutex_` 下修改 `action_`。读取方没有使用同一把锁，无法与写入方建立同步关系。

## 影响

- 延时断连任务可能依据过时或竞争中的列表状态提前断开 subscriber ability。
- 也可能错误延后断连，表现为通用事件丢失、延迟或连接状态异常。
- 无锁读取与 vector 修改构成 C++ 数据竞争。

## 触发条件

Ability 连接完成回调与 15 秒延时断连任务重叠，并且回调恰好在 `IsEmptyAction` 读取期间调用 `NotifyEvent` 修改 `action_`。

## 修复建议

让 `IsEmptyAction` 获取 `mutex_`，或在 `RemoveEvent` 的同一临界区内返回删除后的空状态。避免在释放锁后再次读取用于断连决策的容器。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
