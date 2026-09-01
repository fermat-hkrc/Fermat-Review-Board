---
id: OH-2026-TELEPHONY-017
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "TelRilManager 模块向量大小与扩容未统一同步"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Telephony RIL Manager
language: C++
file_paths:
  - services/tel_ril/src/tel_ril_manager.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`InitTelModule` 在 `telRilMutex_` 下向六个 RIL 模块 vectors 追加对象，各 getter 也使用该锁读取元素。但 `InitTelExtraModule` 在加锁前读取 vector 大小，`ResetRilInterface` 同样无锁读取 size 作为循环上限。第三卡槽初始化可以与 RIL HDI 断连或恢复并发。

## 根本原因

**位置**：`services/tel_ril/src/tel_ril_manager.cpp`

```cpp
auto oldSize = telRilCall_.size(); // 加锁前读取
std::unique_lock lock(telRilMutex_);
telRilCall_.push_back(callModule);

for (size_t i = 0; i < telRilCall_.size(); ++i) { // 无锁循环上限
    ResetInterface(i);
}
```

循环内元素 getter 的锁可以保护单次取得对象，但不能同步此前的无锁 size 读取。

## 影响

- reset 循环可能遗漏新卡槽或使用不一致的边界。
- 第三卡槽可能继续持有旧 RIL interface，导致后续调用失败。
- vector 元数据的并发读取和扩容构成 C++ 数据竞争。

## 触发条件

第三卡槽 RIL 模块首次追加时，同时发生 RIL HDI 服务断连、恢复或接口重置。

## 修复建议

`InitTelExtraModule` 和 `ResetRilInterface` 必须在 `telRilMutex_` 下取得向量大小或完整快照。observer handlers 也应采用同一发布和读取规则。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
