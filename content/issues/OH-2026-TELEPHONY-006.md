---
id: OH-2026-TELEPHONY-006
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "SimStateHandle 注册重试状态缺少统一同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2765
report_count: 3
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: SIM State Registry Integration
language: C++
file_paths:
  - services/sim/src/sim_state_handle.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`SimStateHandle` 的 `lockReason_` 和 `needReupdate_` 在状态注册、SIM 事件和系统能力恢复路径间无统一锁保护。Registry 更新路径无锁写入字段，SIM 事件与恢复事件又可以从不同 EventHandler 或工作线程读取和修改它们。

## 根本原因

**位置**：`services/sim/src/sim_state_handle.cpp`

```cpp
lockReason_ = reason;
auto result = UpdateStateRegistry();
needReupdate_ = (result != TELEPHONY_SUCCESS);

if (needReupdate_) { // 另一事件路径读取
    UpdateSimStateToStateRegistry(lockReason_);
}
```

部分调用在 `simStateInitMutex_` 内，另一些调用在主动解锁后执行。被调函数自身没有建立统一同步，因此不能依赖调用侧的局部锁范围。

## 影响

- Registry 更新失败后的重试标志可能丢失。
- 恢复时可能使用上一状态的 SIM 锁定原因。
- `TelephonyStateRegistry` 可能暂时收到旧状态或错误原因。

## 触发条件

Registry 服务断连或恢复事件与 SIM 状态变化并发发生，使两个事件源同时访问注册重试状态。

## 修复建议

将 `lockReason_`、`needReupdate_` 和本次注册结果封装为由同一互斥量保护的状态对象。更新、判断和清除重试状态应在一个临界区内完成。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
