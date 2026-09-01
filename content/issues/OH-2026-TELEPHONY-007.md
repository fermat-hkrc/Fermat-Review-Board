---
id: OH-2026-TELEPHONY-007
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "IccFile 的 EONS 容器和加载状态在锁外读取"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2766
report_count: 4
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: ICC File and EONS
language: C++
file_paths:
  - services/sim/src/icc_file.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`IccFile::ClearData` 在 `iccFileMutex_` 下清空 OPL/PNN vectors 并重置加载状态。`ObtainEons` 和 `UpdateOpkeyConfig` 却在锁外复制这些容器或读取状态字段。查询线程和 SIM 状态清理线程不受同一个 EventHandler 串行化。

## 根本原因

**位置**：`services/sim/src/icc_file.cpp`

```cpp
void IccFile::ClearData()
{
    std::unique_lock lock(iccFileMutex_);
    oplFiles_.clear();
    pnnFiles_.clear();
    isOplFileResponsed_ = false;
}

auto oplFiles = oplFiles_;            // 无共享锁复制 vector
if (isOplFileResponsed_) { /* ... */ } // 无锁读取状态
```

一侧加锁而消费侧无锁，不能建立容器和相关加载标志的一致快照。

## 影响

- 运营商名称查询可能返回空值、旧 EONS 或不一致结果。
- vector 复制与并发 `clear` 构成未定义行为，极端情况下可使 telephony 服务异常。
- operator config 刷新可能依据错误的加载状态执行。

## 触发条件

SIM 移除、eSIM 停用或 SIM 文件刷新执行 `ClearData` 时，并发查询运营商名称或更新 opkey 配置。

## 修复建议

在 `ObtainEons` 和 `UpdateOpkeyConfig` 中使用 `iccFileMutex_` 的共享锁，并在锁内一次性复制容器和加载标志。后续计算只使用该一致快照。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
