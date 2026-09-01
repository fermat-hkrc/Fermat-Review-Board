---
id: OH-2026-TELEPHONY-011
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "MultiSimController 本地 SIM 缓存使用不一致的锁"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 2
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Multi-SIM Cache
language: C++
file_paths:
  - services/sim/src/multi_sim_controller.cpp
author: Zirui
vendor: public
---

## 漏洞概述

多数 `localCacheInfo_` getter 使用 `mutex_` 的共享锁，数据库刷新路径使用独占锁。但 `IsESimUpdateStatus`、`GetFirstActivedSlotId` 无锁遍历或读取缓存，`AddExtraManagers` 又使用另一把 `simStateManagerMutex_` 读取其大小。查询线程能够与数据库刷新和 eSIM 状态更新线程并发。

## 根本原因

**位置**：`services/sim/src/multi_sim_controller.cpp`

```cpp
for (const auto &info : localCacheInfo_) { // 无 mutex_
    // 检查 eSIM 更新状态
}

std::shared_lock lock(simStateManagerMutex_);
auto size = localCacheInfo_.size(); // 错误的保护锁
```

`simStateManagerMutex_` 不同步使用 `mutex_` 更新缓存的路径。已授权 getter 的锁也无法保护其他无锁函数。

## 影响

- 查询可能返回混合版本 SIM 数据或错误的 active/default 卡槽。
- vector 重分配期间无锁遍历可产生未定义行为。
- eSIM 更新状态判断和账户缓存可能暂时不一致。

## 触发条件

eSIM profile 更新、SIM 插拔或账户数据库刷新期间，并发查询 SIM 账户或默认卡槽信息。

## 修复建议

所有 `localCacheInfo_` 访问统一使用 `mutex_`。读取多个相关字段时在共享锁下取得完整快照，避免使用 manager 锁代替缓存锁。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
