---
id: OH-2026-TELEPHONY-012
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "MultiSimController 管理器向量更新与读取未统一同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
hidden_from_dashboard: true
hidden_date: "2026-09-01"
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Multi-SIM Manager Lifecycle
language: C++
file_paths:
  - services/sim/src/multi_sim_controller.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`MultiSimController::AddExtraManagers` 在 `simStateManagerMutex_` 下向 `simStateManager_` 和 `simFileManager_` 追加第三卡槽对象。部分读取路径正确使用同一锁，但初始化、默认卡槽查找、号码读写和 primary-slot ready 路径仍会无锁按 slot ID 访问这些 vectors。

## 根本原因

**位置**：`services/sim/src/multi_sim_controller.cpp`

```cpp
{
    std::unique_lock lock(simStateManagerMutex_);
    simStateManager_.push_back(stateManager);
    simFileManager_.push_back(fileManager);
}

auto manager = simFileManager_[slotId]; // 部分生产路径未持锁
```

`shared_ptr` 可以保护已经安全取得的对象，但不能保护取得元素时 vector 本身正在扩容或替换。

## 影响

- 可能错误判断 manager 为空或遗漏第三卡槽。
- vector 重分配期间的无锁元素访问构成未定义行为。
- SIM 初始化、号码查询或主卡准备流程可能失败。

## 触发条件

产品支持第三卡槽，并在 extra manager 首次添加时并发执行一个无锁读取 manager vector 的服务路径。

## 修复建议

所有 manager vector 读取统一使用 `simStateManagerMutex_`。如果初始化后不再变化，应在受锁阶段构造完成后发布不可变快照。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
