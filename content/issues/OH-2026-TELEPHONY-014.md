---
id: OH-2026-TELEPHONY-014
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "UsimDiallingNumbersService 的 PBR 加载状态访问未同步"
severity: LOW
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2767
report_count: 2
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: USIM Dialling Numbers
language: C++
file_paths:
  - services/sim/src/usim_dialling_numbers_service.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`LoadPbrFiles` 和 `SendBackResult` 在静态 `mtx_` 下访问 `isProcessingPbr`，但 PBR 加载错误、重试和完成回调无锁写入该字段及 `isLoadDiallingNumSuccess_`。查询线程与 SIM 文件 EventHandler 来自不同执行上下文。

## 根本原因

**位置**：`services/sim/src/usim_dialling_numbers_service.cpp`

```cpp
std::lock_guard lock(mtx_);
if (isProcessingPbr) {
    return;
}
isProcessingPbr = true;

// EventHandler 错误或重试路径
isProcessingPbr = false; // 无锁写入
isLoadDiallingNumSuccess_ = result;
```

只有部分状态转换进入 `mtx_`，因此读取方无法获得完整加载状态的同步保证。

## 影响

- 可能错误判断已有加载正在进行并重复发起 PBR/ADN 加载。
- 调用方可能获得错误的 success 状态。
- 电话簿查询可能超时、失败或返回不一致结果。

## 触发条件

PBR/ADN 加载失败、重试或完成时，并发发起 USIM 电话簿查询。

## 修复建议

用 `mtx_` 保护所有 PBR 加载状态读写，或者使用原子状态机。结果发布、完成状态切换和等待方通知应作为一个同步操作处理。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
