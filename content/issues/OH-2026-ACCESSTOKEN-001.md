---
id: OH-2026-ACCESSTOKEN-001
date: "2026-04-29"
repo: security_access_token
repo_url: https://gitcode.com/openharmony/security_access_token
title: "SoftBusChannel::ExecuteCommand 中 static_cast<int32_t> 截断 size_t 导致堆溢出风险"
cwe: CWE-190
cwe_name: Integer Overflow or Wraparound
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_access_token/issues/3173
author: fermat-hkrc
---

### 漏洞编号：
            
CWE-190 (Integer Overflow), CWE-680 (Integer Overflow to Buffer Overflow)
### 漏洞归属组件
            

### 漏洞归属版本
            

### CVSS V3.0分值
            

### 漏洞简述
            
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
            
## 影响

- **堆溢出**：截断后的 `len` 用于分配和后续内存操作，可能导致写入超出分配缓冲区
- **影响范围**：所有参与分布式 Token 同步的 OpenHarmony 设备
### 原理分析
            

### 受影响版本
            

### 规避方案或消减措施
            
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
