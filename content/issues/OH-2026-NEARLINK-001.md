---
id: OH-2026-NEARLINK-001
date: "2026-08-31"
repo: communication_nearlink_service
repo_url: https://gitcode.com/openharmony/communication_nearlink_service
title: "SchedulePostTaskBlocked 超时返回后任务继续引用调用方栈地址"
severity: MEDIUM
cwe: CWE-562
cwe_name: Return of Stack Variable Address
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/communication_nearlink_service/issues/190
report_count: 17
affected_version: "211765308f9b2e67fd288dcb0d0a1f8ddda9f2fa"
component: NearLink Stack Scheduler
language: C
file_paths:
  - services/stack/src/cp/nlstkfwk/schedule/src/nlstk_schedule.c
  - services/stack/src/cp/nlstkfwk/schedule/src/cp_worker.c
  - services/stack/src/cp/bsl/sle/cm/link/src/cm_api.c
  - services/stack/src/cp/bsl/sle/servm/ssap/src/nlstk_ssap_app_client.c
  - services/service/src/ssap/ssap_client_stack_adapter.cpp
  - services/stack/src/cp/bal/profile/icce/src/nlstk_icce_client.c
author: Zirui
vendor: public
---

## 漏洞概述

`SchedulePostTaskBlocked` 把回调和参数地址保存到堆任务并提交到全局调度队列，然后等待 semaphore。等待超过三秒后，函数直接返回，但没有取消原任务，也没有等待回调停止使用参数。17 个调用点把局部结构、局部输出变量或包含栈指针的参数传给该接口，因此原任务稍后执行时会访问已经离开作用域的栈地址。

## 根本原因

**位置**：`services/stack/src/cp/nlstkfwk/schedule/src/nlstk_schedule.c`

```c
task->callback = cb;
task->arg = arg;
SchedulePostTask(task);

if (SemWaitTimeout(sem, NLSTK_API_TIME_OUT) != 0) {
    SchedulePostTask(FreeSem, sem);
    return NLSTK_ERRCODE_TASK_TIMEOUT; // 原任务仍可继续访问 arg
}
```

超时分支只把释放 semaphore 的任务排到同一队列。它既不取消原任务，也没有改变 `arg` 的所有权。即使原任务已经开始，调用返回时它仍可能在访问调用方栈对象。

## 影响

- 超时后写入失效的栈地址，造成 NearLink 服务内存破坏。
- 返回对象指针、数量和局部结构可能被异步任务覆盖。
- 可导致共享 NearLink 服务崩溃或不可预测行为。
- 17 个报告位置共用同一个调度超时根因，因此合并为一个 Issue。

## 触发条件

具有 `ACCESS_NEARLINK` 或 `MANAGE_NEARLINK` 权限的调用方并发发起 SSAP GetServices 等 IPC 请求，通过请求压力让全局调度队列延迟超过 `NLSTK_API_TIME_OUT`。阻塞调用返回后，原任务继续处理其保存的栈参数。

## 修复建议

超时返回前必须保证原任务已经取消或不再使用调用方参数。可采用可取消任务和完成确认；也可以把所有参数及输出缓冲复制到由任务独立拥有的堆对象，并在任务与等待方之间使用引用计数管理生命周期。

## 参考

- [CWE-562: Return of Stack Variable Address](https://cwe.mitre.org/data/definitions/562.html)
