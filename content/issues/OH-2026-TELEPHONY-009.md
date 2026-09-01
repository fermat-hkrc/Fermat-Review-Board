---
id: OH-2026-TELEPHONY-009
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "MultiSimMonitor 管理器向量和加载状态锁覆盖不一致"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2766
report_count: 7
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Multi-SIM Monitor
language: C++
file_paths:
  - services/sim/src/multi_sim_monitor.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`MultiSimMonitor` 使用 `simStateMgrMutex_` 保护部分 manager vectors 和 SIM 加载状态，但 `AddExtraManagers` 在加锁前读取 vector 大小，`IsValidSlotId`、`IsNeedOperatorReLoad`、`ResetSimLoadAccount` 和 `RegisterCoreNotify` 又存在无锁访问。注册、第三卡槽初始化和 SIM 事件来自不同执行线程。

## 根本原因

**位置**：`services/sim/src/multi_sim_monitor.cpp`

```cpp
auto size = simStateManager_.size(); // 加锁前读取
std::unique_lock lock(simStateMgrMutex_);
simStateManager_.push_back(manager);

return slotId < simFileManager_.size(); // 其他路径无锁读取
```

同一批字段在部分方法中正确使用共享锁，说明设计允许跨线程访问；未加锁方法破坏了统一同步约定。

## 影响

- 可能遗漏通知注册或错误复位 SIM 账户加载状态。
- 卡槽有效性和 operator config 刷新可能短暂错误。
- vector 元数据与并发扩容冲突时会产生未定义行为。

## 触发条件

第三卡槽首次初始化、SIM 状态刷新、系统能力事件和观察者注册在不同线程交错执行。

## 修复建议

所有 manager vector、状态 vector 和 `isSimAccountLoaded_` 访问统一使用 `simStateMgrMutex_`。size 检查必须移动到临界区内，并尽量以一次不可变快照完成后续操作。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
