---
id: OH-2026-TELEPHONY-001
date: "2026-08-18"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "eSIM CarrierIdentifiers 使用空 MCC/MNC 固定下标读取导致越界访问"
severity: MEDIUM
cwe: CWE-125
cwe_name: Out-of-bounds Read
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "e313c25c811710e5425c3c51338521719b086c2b"
component: eSIM rules authorization table parser
language: C++
file_paths:
  - services/sim/src/esim_file.cpp
  - services/sim/src/esim_manager.cpp
  - frameworks/native/src/core_manager_inner.cpp
author: Zirui
vendor: terminal
---

## 漏洞概述

`EsimFile::BuildCarrierIdentifiers()` 在解析每个 eUICC rules authorization table 的 carrier 条目前，都会调用 `CarrierIdentifiers({}, 0, u"", u"")` 构造默认值。`CarrierIdentifiers()` 把空字节数组转换为空字符串后，不检查长度便读取下标 0 至 5，造成确定存在的越界读取和 C++ 未定义行为。

该问题只会编译进启用 `core_service_support_esim` 的产品。源码能够确认受影响的精确基线为 `e313c25c811710e5425c3c51338521719b086c2b`；尚未确认首个受影响或已修复的公开发行版。

## 根本原因

### 默认值通过需要有效 MCC/MNC 的解析函数构造

`BuildCarrierIdentifiers()` 无条件执行以下调用，随后才检查 ASN.1 子节点：

```cpp
CarrierIdentifier defaultCarrier = CarrierIdentifiers({}, 0, u"", u"");
```

`CarrierIdentifiers()` 虽然接收 `mccMncLen`，但没有使用该参数。空输入经 `BytesToHexStr()` 得到空 `strResult`，代码仍固定读取六个字符：

```cpp
std::string strResult = Asn1Utils::BytesToHexStr(mccMncData);
std::string mMcc(NUMBER_THREE, '\0');
mMcc[NUMBER_ZERO] = strResult[NUMBER_ONE];
mMcc[NUMBER_ONE] = strResult[NUMBER_ZERO];
mMcc[NUMBER_TWO] = strResult[NUMBER_THREE];
std::string mMnc(NUMBER_THREE, '\0');
mMnc[NUMBER_ZERO] = strResult[NUMBER_FIVE];
mMnc[NUMBER_ONE] = strResult[NUMBER_FOUR];
if (strResult[NUMBER_TWO] != 'F') {
    mMnc[NUMBER_TWO] = strResult[NUMBER_TWO];
}
```

对空 `std::string` 使用这些下标违反容器边界要求。即使删除默认值调用，当前函数对不足 3 字节、转换后不足 6 个十六进制字符的 MCC/MNC 输入也存在同样问题。

### 调用链来自 eUICC APDU 响应解析

已确认的生产代码调用链为：

1. `CoreManagerInner::GetRulesAuthTable()` 调用 `EsimManager::GetRulesAuthTable()`。
2. `EsimManager` 调用 `EsimFile::ObtainRulesAuthTable()`。
3. `ObtainRulesAuthTable()` 通过 `ProcessRequestRulesAuthTable()` 向 RIL/eUICC 发送 `TAG_ESIM_GET_RAT` APDU 请求并等待响应。
4. 响应事件进入 `ProcessRequestRulesAuthTableDone()`，经过 `ParseEvent()` 和 `RequestRulesAuthTableParseTagCtxComp0()` 解析 ASN.1 节点。
5. 每个解析出的 carrier 节点都会进入 `BuildCarrierIdentifiers()`，并在函数开头触发空输入读取。

因此，到达条件不是调用方直接传入空 MCC/MNC；空输入由实现自身创建。来自 eUICC 的响应只需被解析出至少一个 carrier 条目，即可到达该代码。

### 构建与权限边界

根 `BUILD.gn` 的正式共享库目标 `tel_core_service` 仅在 `core_service_support_esim` 为真时加入 `esim_file.cpp`、`esim_controller.cpp` 等 eSIM 源文件，并通过 `telephony_extra_defines` 定义 `CORE_SERVICE_SUPPORT_ESIM`。该构建参数默认关闭，只有产品声明对应部件能力时才开启。

本仓库中 `GetRulesAuthTable()` 仅通过 `CoreManagerInner` 和内部 `IEsimManager` 路径提供，没有发现面向普通 JavaScript 应用的直接入口或在本仓库内执行的独立 IPC 权限检查。上层 eSIM 服务的调用权限不在本仓库中，尚未确认。APDU 响应来自 RIL/eUICC，而不是普通应用提供的缓冲区，因此不能据此声称普通应用或远程网络调用方能够直接控制越界内容。

### 引入历史

提交 `3cb6cea1ff9029274c4f6087e0ae0d0ab979cd82` 在构造默认 carrier 时引入了空字符串版本的 `CarrierIdentifiers()` 调用。提交 `b2f9379bedff167ab0d3d3689176b41f4ebe2abf` 将 MCC/MNC 参数改为字节数组，并把调用改为当前的空数组形式，但保留了固定下标读取。精确基线 `e313c25c811710e5425c3c51338521719b086c2b` 仍包含该逻辑。

## 影响

越界读取产生未定义行为。在启用 eSIM 且处理 rules authorization table 时，可能导致 `tel_core_service` 异常退出，或生成错误的 MCC/MNC 默认值并影响授权规则解析结果。

源码证据不能证明该读取能够稳定泄露相邻内存，也不能证明外部调用方能够控制被读取的具体字节。因此不应将影响扩大为确定的信息泄露、远程代码执行或普通应用可直接触发的攻击。

## 触发条件

同时满足以下条件时可到达问题代码：

1. 产品构建启用了 `core_service_support_esim`，因而定义 `CORE_SERVICE_SUPPORT_ESIM` 并编译完整 eSIM 实现。
2. 目标槽位支持 eSIM，内部调用方发起 `GetRulesAuthTable()`。
3. eUICC/RIL 返回的 APDU 数据通过 ASN.1 解析，并产生至少一个进入 `BuildCarrierIdentifiers()` 的 carrier 节点。

一旦进入 `BuildCarrierIdentifiers()`，默认 carrier 的空输入读取会无条件发生。若实际 MCC/MNC 字段不足 3 字节，后续对真实字段的解析还会再次面临相同的固定下标越界风险。

## 修复建议

1. 不要通过 `CarrierIdentifiers()` 解析空输入来构造默认值。直接对 `CarrierIdentifier` 做值初始化，并显式设置空字段。
2. 在 `CarrierIdentifiers()` 内使用 `mccMncLen` 和实际容器长度验证 MCC/MNC 至少包含 3 字节，并在十六进制转换后确认字符串长度至少为 6，再执行任何下标访问。
3. 将解析接口改为能够表达失败的返回类型。遇到缺失或过短的 MCC/MNC 时向 `RequestRulesAuthTableParseTagCtxComp0()` 返回错误，不要继续生成部分有效的 carrier 条目。
4. 在 ASN.1 边界验证 carrier 节点的必需字段和长度，避免依赖更深层函数对格式作隐含假设。

## 参考

- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [OpenHarmony telephony_core_service](https://gitcode.com/openharmony/telephony_core_service)
