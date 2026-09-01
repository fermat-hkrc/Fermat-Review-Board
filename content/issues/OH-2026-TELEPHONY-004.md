---
id: OH-2026-TELEPHONY-004
date: "2026-08-31"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "OperatorNameUtils 在 fclose 失败路径遗失已分配内容"
severity: LOW
cwe: CWE-401
cwe_name: Missing Release of Memory after Effective Lifetime
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/telephony_core_service/issues/2764
report_count: 2
affected_version: "670d98dfcc1bdb77a984d948bd10d21a3cc06aae"
component: Operator Name Configuration
language: C++
file_paths:
  - services/network_search/src/operator_name_utils.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`OperatorNameUtils::LoaderJsonFile` 为固定运营商配置文件分配最多 10 MiB 的 `content`。读取成功后，函数直接返回 `CloseFile` 的结果；若 `fclose` 返回错误，调用方按失败路径退出但没有释放仍然非空的 `content`。

## 根本原因

**位置**：`services/network_search/src/operator_name_utils.cpp:111`

```cpp
char *content = new char[fileSize + 1];
// 读取配置成功
return CloseFile(file); // fclose 失败时 content 仍由调用方持有

if (LoaderJsonFile(content) != TELEPHONY_SUCCESS) {
    return; // content 未释放
}
```

两条工具报告来自初始化和解析调用链，但最终到达的是同一个错误所有权分支。

## 影响

- 在“分配和读取成功、关闭文件失败”时泄漏配置内容缓冲区。
- 单次泄漏大小最高接近 10 MiB。
- 固定路径和单例初始化限制了重复触发频率，但错误路径内存所有权仍然不完整。

## 触发条件

读取 `/etc/telephony/operator_name.json` 成功后，底层 `fclose` 返回非零。配置路径不是应用可控路径，触发通常依赖文件系统或故障注入异常。

## 修复建议

使用 RAII 容器保存内容。若保留裸指针，应在 `LoaderJsonFile` 返回关闭错误前释放内容，或让调用方在所有错误分支统一释放非空指针。

## 参考

- [CWE-401: Missing Release of Memory after Effective Lifetime](https://cwe.mitre.org/data/definitions/401.html)
