---
id: OH-2026-TELEPHONY-008
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "NetworkSearchManager 管理器映射大小读取未同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Network Search Manager
language: C++
file_paths:
  - services/network_search/src/network_search_manager.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`NetworkSearchManager` 的添加、删除、查找和清理路径使用 `mutexInner_` 保护 `mapManagerInner_`，但 `GetImei` 和 `ClearManagerInner` 的部分控制流在锁外读取 `mapManagerInner_.size()`。设备标识查询可以与扩展卡槽初始化或服务重置并发。

## 根本原因

**位置**：`services/network_search/src/network_search_manager.cpp`

```cpp
if (mapManagerInner_.size() > 1) { // 未持有 mutexInner_
    auto other = FindManagerInner(otherSlotId); // 只有实际查找加锁
}
```

加锁的 `FindManagerInner` 只能保护后续对象查找，不能补救此前已经发生的无锁容器元数据读取。

## 影响

- IMEI 查询可能错误跳过或执行另一卡槽比较。
- reset 清理循环可能使用不一致的 map 大小。
- 无锁 size 读取与 map 修改构成 C++ 数据竞争。

## 触发条件

extra slot 初始化、RIL/网络搜索重置或管理器清理期间，并发执行受权限保护的 IMEI 查询。

## 修复建议

将所有 size 检查和遍历放入 `mutexInner_` 保护。需要在锁外继续处理时，应在锁内取得 `shared_ptr` 列表或大小快照。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
