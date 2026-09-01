---
id: OH-2026-TELEPHONY-018
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "IccDiallingNumbersManager 请求完成状态和结果列表未同步"
severity: LOW
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2767
report_count: 2
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: ICC Dialling Numbers Manager
language: C++
file_paths:
  - services/sim/src/icc_dialling_numbers_manager.cpp
author: Zirui
vendor: public
---

## 漏洞概述

SIM 电话簿查询、增加、删除和更新接口在 `mtx_` 下等待 `hasQueryEventDone_` 或 `hasEventDone_`。完成回调在 EventHandler 线程无锁写这些谓词；加载完成还会修改 `diallingNumbersList_`，等待线程醒来后在同一请求中遍历该 vector。

## 根本原因

**位置**：`services/sim/src/icc_dialling_numbers_manager.cpp`

```cpp
std::unique_lock lock(mtx_);
hasQueryEventDone_ = false;
cv_.wait_for(lock, timeout, [this] { return hasQueryEventDone_; });

// EventHandler 回调
FillResults(result);          // 修改 diallingNumbersList_
hasQueryEventDone_ = true;   // 未持有 mtx_
cv_.notify_all();
```

`queryMtx_` 和 `mtx_` 只能串行调用方，不能同步不持锁的完成回调。条件变量通知本身也不发布未受同锁保护的 vector 修改。

## 影响

- SIM 电话簿请求可能无谓超时或返回不完整结果。
- 结果 vector 可在等待线程读取时被回调修改。
- 超时后的迟到响应可能污染下一笔查询或更新。

## 触发条件

任意受权限保护的 SIM 电话簿异步查询或写操作。IPC/分离查询线程等待，而 EventHandler 处理文件完成事件，正常调用链即可并发。

## 修复建议

完成回调在 `mtx_` 下发布结果和完成标志。为每次请求绑定唯一标识，超时后不允许旧响应更新下一笔操作的共享结果。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
