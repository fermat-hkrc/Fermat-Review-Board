---
id: OH-2026-TELEPHONY-005
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "SimStateHandle 的 SIM 对外状态读写缺少统一同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2765
report_count: 7
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: SIM State Handle
language: C++
file_paths:
  - services/sim/src/sim_state_handle.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`SimStateHandle` 的 `externalState_` 由 SIM/RIL 事件路径写入，主要状态转换使用 `simStateInitMutex_`。公开 `GetSimState` 和 `SetSimState` 却完全不加锁。异步 IPC 查询线程能够与 SIM 插拔、RIL 状态变化或 eSIM 切换事件并发访问该字段。

## 根本原因

**位置**：`services/sim/src/sim_state_handle.cpp`

```cpp
SimState SimStateHandle::GetSimState() const
{
    return externalState_; // 无锁读取
}

void SimStateHandle::SetSimState(SimState state)
{
    externalState_ = state; // 无锁写入
}
```

其他转换路径在 `simStateInitMutex_` 下写同一字段。部分路径加锁不能保护上述无锁 getter/setter。

## 影响

- SIM 状态查询可能返回旧值或错误枚举值。
- 状态通知次序可能与实际 SIM 生命周期不一致。
- 七个报告点属于同一字段和同步根因，应合并为一个问题。

## 触发条件

在 SIM 插拔、RIL 状态变化或 eSIM profile 切换期间，并发通过 core service 查询或更新 SIM 状态。

## 修复建议

让 `externalState_` 的全部读写使用 `simStateInitMutex_`，或在状态仅为独立小枚举且无需关联其他字段时使用合适的原子类型。状态更新和通知应基于同一次一致快照。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
