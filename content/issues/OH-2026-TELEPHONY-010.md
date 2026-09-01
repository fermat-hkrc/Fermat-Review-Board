---
id: OH-2026-TELEPHONY-010
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "MultiSimController 主卡设置等待状态未按条件变量规则同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Multi-SIM Controller
language: C++
file_paths:
  - services/sim/src/multi_sim_controller.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`SetPrimarySlotToRil` 使用 `setPrimarySlotToRilMutex_` 等待主卡设置完成，但 RIL 响应和 timeout 回调无锁写入 `isSettingPrimarySlotToRil_` 与 `setPrimarySlotResponseResult_` 后直接通知条件变量。写方未持有等待方使用的互斥量，无法建立 happens-before 关系。

## 根本原因

**位置**：`services/sim/src/multi_sim_controller.cpp`

```cpp
std::unique_lock lock(setPrimarySlotToRilMutex_);
isSettingPrimarySlotToRil_ = true;
cv_.wait(lock, [this] { return !isSettingPrimarySlotToRil_; });

// RIL/EventHandler 回调
isSettingPrimarySlotToRil_ = false;       // 无锁写入
setPrimarySlotResponseResult_ = result;   // 无锁写入
cv_.notify_all();
```

首次忙状态检查也发生在取得互斥量之前。timeout 事件调用同一个无锁写函数，不能消除竞争。

## 影响

- 等待线程可能看不到完成状态或取得错误的 RIL 结果。
- 主卡设置可能错误超时、错误返回成功或持续等待到超时处理。
- 同一组状态字段存在确定的数据竞争。

## 触发条件

每次有权限的主卡设置请求都会由服务调用线程等待，并由 RIL/EventHandler 线程完成或超时，因此正常请求即可形成并发访问。

## 修复建议

响应和 timeout 回调必须在 `setPrimarySlotToRilMutex_` 下更新结果及完成谓词，再调用 `notify_all`。首次忙状态检查也应移入相同临界区。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
