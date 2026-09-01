---
id: OH-2026-TELEPHONY-019
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "IccOperatorPrivilegeController 状态机和规则访问未同步"
severity: LOW
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 2
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: ICC Operator Privilege
language: C++
file_paths:
  - services/sim/src/icc_operator_privilege_controller.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`LogicalStateMachine::SuccessLoaded` 在 `mtx_` 下读取 `isAvailable_` 和 `isTransmitting_`，但 SIM 状态与 RIL channel 回调使用的 setter 不取得该锁。相邻的 `rules_` 也会在状态变化或 channel 完成路径清空、填充，同时查询工作线程遍历规则。

## 根本原因

**位置**：`services/sim/src/icc_operator_privilege_controller.cpp`

```cpp
std::unique_lock lock(mtx_);
cv_.wait(lock, [this] { return isAvailable_ && !isTransmitting_; });

void SetSimAvailable(bool value)
{
    isAvailable_ = value; // 未持有 mtx_
}
```

`HasOperatorPrivileges` 在异步工作线程查询，SIM/RIL 完成事件在 EventHandler 写状态和规则，因此实际并发路径存在。

## 影响

- 查询可能暂时依据上一张 SIM 的规则返回错误结果。
- 规则加载状态可能错误，表现为查询失败或旧规则短暂可见。
- `rules_` 遍历与清空或填充并发时存在容器竞争。

当前仓库中没有发现该查询结果直接放行特权 APDU、订阅或网络配置的 sink，因此本报告记录真实的安全敏感状态风险，不将其描述为已经成立的权限绕过。

## 触发条件

SIM 移除、eSIM profile 切换或 operator privilege APDU 加载完成时，并发调用 `hasOperatorPrivileges`。

## 修复建议

状态字段和 `rules_` 必须由同一互斥量保护，并以一次完整快照发布。查询只应读取与当前 SIM 身份和加载代次匹配的规则集合。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
