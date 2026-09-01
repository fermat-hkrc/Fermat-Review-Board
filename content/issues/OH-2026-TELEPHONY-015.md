---
id: OH-2026-TELEPHONY-015
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "StkController 响应完成标志未按条件变量规则同步"
severity: LOW
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2767
report_count: 1
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: SIM Toolkit Controller
language: C++
file_paths:
  - services/sim/src/stk_controller.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`StkController` 的三个命令接口在 `stkMutex_` 下清零共享 `responseFinished_` 和结果字段并等待 `stkCv_`。三个完成回调在 EventHandler 线程无锁写入相同状态后通知。不同命令还共用一个完成标志，迟到响应可与下一请求混淆。

## 根本原因

**位置**：`services/sim/src/stk_controller.cpp`

```cpp
std::unique_lock lock(stkMutex_);
responseFinished_ = false;
stkCv_.wait_for(lock, timeout, [this] { return responseFinished_; });

// EventHandler 回调
result_ = callbackResult;  // 未持有 stkMutex_
responseFinished_ = true;
stkCv_.notify_all();
```

调用方互斥只能串行三个 API，不能同步无锁回调写入。一个共享谓词也无法区分请求代次。

## 影响

- STK terminal response、envelope 或 call setup 结果可能错误。
- 命令可能无谓等待到一秒超时。
- 上一请求的迟到响应可能错误满足下一笔命令。

## 触发条件

执行任意受权限保护的 STK 命令。正常异步响应即可产生数据竞争；响应超过一秒后紧接着发起另一命令会扩大错配窗口。

## 修复建议

完成回调在 `stkMutex_` 下更新结果和完成谓词，并为每次命令分配请求标识。通知前校验响应属于当前等待请求，超时后丢弃迟到结果。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
