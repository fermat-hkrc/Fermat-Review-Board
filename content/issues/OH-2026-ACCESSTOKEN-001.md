---
id: OH-2026-ACCESSTOKEN-001
date: "2026-04-29"
repo: security_access_token
repo_url: https://gitcode.com/openharmony/security_access_token
title: "SoftBusChannel::ExecuteCommand 中 static_cast<int32_t> 截断 size_t 导致堆溢出风险"
cwe: CWE-190
cwe_name: Integer Overflow or Wraparound
status: CONFIRMED_REAL
language: "C++"
issue_url: https://gitcode.com/openharmony/security_access_token/issues/3173
author: Zirui
---

### 漏洞编号：
            
CWE-190 (Integer Overflow), CWE-680 (Integer Overflow to Buffer Overflow)
### 漏洞归属组件
            
security_access_token — SoftBusChannel IPC 通信层（soft_bus_channel.cpp）

### 漏洞归属版本
            
GitCode master 分支（2026-04-29）

### CVSS V3.0分值
            
7.5（High）— AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

### 漏洞简述
            
`SoftBusChannel::ExecuteCommand` 将 `size_t` 类型的 payload 长度通过 `static_cast<int32_t>` 截断为 32 位有符号整数。当远端设备通过 SoftBus 发送超大 JSON payload 时，截断后的 `len` 变为负数，导致后续 `new[]` 分配和 `memset_s` 操作使用错误的长度值，构成堆溢出风险。
## 问题描述

```cpp
// soft_bus_channel.cpp:177-192
std::string SoftBusChannel::ExecuteCommand(const std::string &commandName, const std::string &jsonPayload)
{
    // ...
    int len = static_cast<int32_t>(RPC_TRANSFER_HEAD_BYTES_LENGTH + jsonPayload.length());
    //         ^^^^^^^^^^^^^^^^^ line 186: size_t (64位) 截断为 int32_t (32位有符号)
    unsigned char* buf = new (std::nothrow) unsigned char[len + 1];
    //                                                    ^^^^^^^ line 187: 若 len 为负数，len+1 作为 size_t 变为极大值
    if (buf == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No enough memory: %{public}d", len);
        return "";
    }
    (void)memset_s(buf, len + 1, 0, len + 1);  // line 192: 同样使用截断后的 len
    // ...
}
```

`jsonPayload.length()` 返回 `size_t`（64 位平台上为 64 位无符号整数）。`RPC_TRANSFER_HEAD_BYTES_LENGTH + jsonPayload.length()` 的结果通过 `static_cast<int32_t>` 截断为 32 位有符号整数。

若 `jsonPayload` 长度超过 `INT32_MAX - RPC_TRANSFER_HEAD_BYTES_LENGTH`（约 2GB），`len` 将变为负数。`len + 1` 作为 `size_t` 传入 `new[]` 时，负数被解释为极大的无符号值，导致：
- 分配失败（返回 nullptr，被 null 检查捕获）— 较好情况
- 或分配极小缓冲区（取决于编译器对 `int + 1` 的处理）— 后续 `memset_s` 和 `PrepareBytes` 越界写入

## 触发条件

TokenSyncManager 处理跨设备 Token 同步时，若远端设备发送超大 JSON payload（通过 `SoftBusSocketListener::OnBytesReceived` 接收），可触发此整数截断。

攻击路径：
1. 攻击者控制分布式网络中的一台设备
2. 通过 SoftBus 向目标设备发送超大 JSON payload
3. 目标设备的 `ExecuteCommand` 处理该 payload 时触发截断
### 影响性分析说明
            
截断后的 `len` 用于内存分配和后续写入操作。在 64 位平台上，当 payload 超过 2GB 时触发整数截断，可能导致分配极小缓冲区后越界写入。攻击路径通过分布式 SoftBus 网络远程可达。
### 原理分析
            
`size_t`（64位无符号）通过 `static_cast<int32_t>` 截断为 32 位有符号整数，高位数据丢失。截断后的负值在传入 `new[]` 时被隐式转换为极大的 `size_t`，或在后续 `memset_s`/`PrepareBytes` 中作为长度参数引发越界写入。根本原因是类型不匹配且缺少上限校验。

### 受影响版本
            
GitCode master 分支（2026-04-29）

### 规避方案或消减措施
            
在执行 `static_cast` 前添加长度上限检查，或直接使用 `size_t` 类型避免截断。
## 建议修复

```cpp
// 修复方案：使用 size_t 并添加上限检查
std::string SoftBusChannel::ExecuteCommand(const std::string &commandName, const std::string &jsonPayload)
{
    // ...
    size_t total = RPC_TRANSFER_HEAD_BYTES_LENGTH + jsonPayload.length();
+   if (total > MAX_COMMAND_LENGTH) {  // 添加合理上限，如 10MB
+       LOGE(ATM_DOMAIN, ATM_TAG, "payload too large: %{public}zu", total);
+       return "";
+   }
-   int len = static_cast<int32_t>(RPC_TRANSFER_HEAD_BYTES_LENGTH + jsonPayload.length());
-   unsigned char* buf = new (std::nothrow) unsigned char[len + 1];
+   unsigned char* buf = new (std::nothrow) unsigned char[total + 1];
    // ...
}
```
