---
id: OH-2026-STORAGE-004
date: "2026-08-31"
repo: filemanagement_storage_service
repo_url: https://gitcode.com/openharmony/filemanagement_storage_service
title: "AccountSubscriber 的 userId_ 由不同互斥锁保护"
severity: MEDIUM
cwe: CWE-362
cwe_name: Concurrent Execution using Shared Resource with Improper Synchronization
status: PENDING
hidden_from_dashboard: true
hidden_date: "2026-09-01"
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "ed50e0173ce700c1d613efb5f3ad63a7c63e1e25"
component: Storage Account Subscriber
language: C++
file_paths:
  - services/storage_manager/account_subscriber/account_subscriber.cpp
  - services/storage_manager/include/account_subscriber/account_subscriber.h
author: Zirui
vendor: public
---

## 漏洞概述

`AccountSubscriber::NotifyUserChangedEvent` 在 `userRecordMutex_` 下写 `userId_`，随后创建分离线程连接 Media DataShare。该线程仅持有 `mediaMutex_` 就读取 `userId_`。连续账户事件会让旧线程读取到新用户 ID，并把 helper 写入错误用户的 map 项。

## 根本原因

**位置**：`services/storage_manager/account_subscriber/account_subscriber.cpp`

```cpp
{
    std::lock_guard lock(userRecordMutex_);
    userId_ = eventUserId;
}
std::thread([this] {
    std::lock_guard lock(mediaMutex_);
    mediaShareMap_[userId_] = GetSystemAbility(); // 使用另一把锁读取
}).detach();
```

两把互斥锁之间没有同步关系。分离线程也没有按值捕获创建时对应的用户 ID。

## 影响

- 旧账户事件的线程可能把 Media DataShare helper 关联到新用户。
- 媒体库连接、缓存和账户状态处理可能出现错配。
- 后续存储管理操作可能失败或使用错误的账户状态。

## 触发条件

连续用户解锁或切换事件发生，同时前一次事件创建的 `GetSystemAbility` 线程尚未完成。

## 修复建议

在线程创建时按值捕获本次事件的 `userId`，并使用该局部值作为 map key。若仍保留成员字段，则所有读写必须使用同一把锁，并管理分离线程的完成时机。

## 参考

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
