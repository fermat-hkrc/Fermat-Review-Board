---
id: OH-2026-TELEPHONY-013
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "SimSmsController 完成标志和结果列表未按条件变量规则同步"
severity: LOW
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 2
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: SIM SMS Controller
language: C++
file_paths:
  - services/sim/src/sim_sms_controller.cpp
author: Zirui
vendor: public
---

## 漏洞概述

SIM 短信更新、删除、写入和加载接口在静态 `mtx_` 下等待 `responseReady_` 或 `loadDone_`。对应 EventHandler 完成回调却不持有 `mtx_` 就写入这些谓词、结果和 `smsList_`，然后通知条件变量。

## 根本原因

**位置**：`services/sim/src/sim_sms_controller.cpp`

```cpp
std::unique_lock lock(mtx_);
responseReady_ = false;
processWait_.wait_for(lock, timeout, [this] { return responseReady_; });

// EventHandler 回调
responseReady_ = true; // 未持有 mtx_
processWait_.notify_all();
```

条件变量不会自动同步未持锁的写方。超时后的迟到响应还可能错误满足下一笔操作使用的共享谓词。

## 影响

- 已完成操作可能仍等待到超时。
- 结果列表可在读取时被回调并发修改。
- 迟到响应可能污染下一笔 SIM 短信读写结果。

## 触发条件

任何受权限保护的 SIM 短信读写都会由业务线程等待、RIL EventHandler 完成。响应延迟超过等待时间并紧接着发起下一操作时，错配风险进一步扩大。

## 修复建议

完成回调应在 `mtx_` 下写结果和谓词，再执行通知。为每个请求分配唯一代次或请求 ID，超时后拒绝迟到响应更新下一笔请求状态。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
