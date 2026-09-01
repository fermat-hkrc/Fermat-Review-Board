---
id: OH-2026-TELEPHONY-016
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "SimFile 的 MSISDN 异步完成结果未同步"
severity: LOW
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: SIM File MSISDN Update
language: C++
file_paths:
  - services/sim/src/sim_file.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`SimFile::UpdateMsisdnNumber` 写入 `lastMsisdn_`、`lastMsisdnTag_` 和 `waitResult_` 后等待异步 SIM 文件更新。`ProcessSetMsisdnDone` 在 EventHandler 线程不持有等待方使用的锁，直接读取请求参数、写缓存和完成结果并通知。

## 根本原因

**位置**：`services/sim/src/sim_file.cpp`

```cpp
lastMsisdn_ = number;
lastMsisdnTag_ = tag;
waitResult_ = false;
std::unique_lock lock(mtx_);
processWait_.wait_for(lock, timeout);

// EventHandler 回调，无 mtx_
msisdn_ = lastMsisdn_;
msisdnTag_ = lastMsisdnTag_;
waitResult_ = true;
processWait_.notify_all();
```

超时后新请求可覆盖 last 字段，上一请求的迟到响应随后会把新请求参数写入缓存。

## 影响

- 更新接口可能返回错误的失败或成功状态。
- 缓存号码和标签可能与 SIM 实际数据不一致。
- 迟到响应可污染下一次 MSISDN 更新结果。

## 触发条件

执行受权限保护的 SIM 本机号码更新。正常响应即可形成数据竞争；响应超时后立即发起下一请求可造成明确的结果错配。

## 修复建议

在同一互斥量下维护请求参数、结果和完成谓词。为请求分配唯一 ID，并在回调中拒绝已经超时或不属于当前请求的响应。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
