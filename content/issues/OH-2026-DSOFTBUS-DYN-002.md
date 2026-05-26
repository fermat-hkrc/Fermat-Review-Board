---
id: OH-2026-DSOFTBUS-DYN-002
date: "2026-04-29"
repo: communication_dsoftbus
repo_url: https://gitcode.com/openharmony/communication_dsoftbus
title: "DSoftBus IPC Inner Handler 从 MessageParcel 读取长度后未做边界检查即用于内存操作"
cwe: CWE-20
cwe_name: Improper Input Validation
status: SUBMITTED
language: "C++"
issue_url: https://gitcode.com/openharmony/communication_dsoftbus/issues/9228
author: Zirui
---

下列还有几个类似问题，也请您可以看看：

# DSoftBus IPC Inner Handler 从 MessageParcel 读取长度后未做边界检查即用于内存操作

**CWE**: CWE-20 (Improper Input Validation), CWE-120 (Buffer Copy without Checking Size of Input)

## 问题描述

以下 4 个 Inner handler 存在相同模式：从 IPC 数据中读取 `uint32_t len`，未验证其合理范围，直接用于 `ReadRawData(len)` 及后续数据传递。

### 实例 1：SendMessageInner

```cpp
// softbus_server_stub.cpp:1077-1109
int32_t SoftBusServerStub::SendMessageInner(MessageParcel &data, MessageParcel &reply)
{
    // ...
    uint32_t len;
    if (!data.ReadUint32(len)) {                    // line 1090: 读取攻击者可控的长度
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }

    auto rawData = data.ReadRawData(len);            // line 1095: 直接使用未验证的 len
    COMM_CHECK_AND_RETURN_RET_LOGE(rawData != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read rawData failed!");
    void *dataInfo = const_cast<void *>(rawData);
    // ...
    // dataInfo 和 len 传入 SendMessage，后续可能用于 memcpy_s
}
```

### 实例 2：CloseChannelWithStatisticsInner

```cpp
// softbus_server_stub.cpp:1041-1075
int32_t SoftBusServerStub::CloseChannelWithStatisticsInner(MessageParcel &data, MessageParcel &reply)
{
    // ...
    uint32_t len;
    if (!data.ReadUint32(len)) {                    // line 1060: 读取未验证的长度
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }

    auto rawData = data.ReadRawData(len);            // line 1065: 直接使用
    // ...
    int32_t retReply = CloseChannelWithStatistics(channelId, channelType, laneId, dataInfo, len);
}
```

### 实例 3：OnBrProxyDataRecvInner（客户端 Stub）

```cpp
// softbus_client_stub.cpp:915-926
int32_t SoftBusClientStub::OnBrProxyDataRecvInner(MessageParcel &data, MessageParcel &reply)
{
    // ...
    uint32_t len;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadUint32(len), ...);  // line 920: 读取未验证的长度

    const uint8_t *dataInfo = reinterpret_cast<const uint8_t *>(data.ReadRawData(len));  // line 922
    COMM_CHECK_AND_RETURN_RET_LOGE(dataInfo != nullptr, ...);
    // dataInfo 和 len 传入 ClientTransBrProxyDataReceived
}
```

### 实例 4：GetAllOnlineNodeInfoInner — 整数溢出

```cpp
// softbus_server_stub.cpp:1228-1265
int32_t SoftBusServerStub::GetAllOnlineNodeInfoInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t infoTypeLen;
    // ...
    if (!data.ReadUint32(infoTypeLen)) {             // line 1240: 读取攻击者可控的 infoTypeLen
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = GetAllOnlineNodeInfo(clientName, &nodeInfo, infoTypeLen, &infoNum);
    // ...
    if (infoNum > 0) {
        if (!reply.WriteRawData(nodeInfo, static_cast<int32_t>(infoTypeLen * infoNum))) {
            // line 1259: infoTypeLen * infoNum 可能溢出 int32_t
        }
    }
}
```

`infoTypeLen` 由 IPC 调用者控制，`infoTypeLen * infoNum` 乘积可能溢出 `int32_t`，导致 `WriteRawData` 写入错误长度的数据。

### 现有保护与不足

- `MessageParcel::ReadRawData(len)` 在 `len` 超过 parcel 剩余数据时返回 `nullptr`，提供了一定的隐式保护
- 但这不等同于显式的业务层边界检查：攻击者可构造恰好满足 parcel 长度但语义上不合理的 `len` 值
- 下游函数（如 `SendMessage`、`CloseChannelWithStatistics`）可能基于 `len` 做进一步内存操作，而不再验证

### 不属于此问题的函数

经源码验证，以下函数被 04-30 报告列入但实际不存在此问题：

| 函数 | 驳回原因 |
|------|---------|
| GetLocalDeviceInfoInner (line 1268) | line 1280 有 `if (infoTypeLen != sizeof(NodeBasicInfo))` 等值检查，已限定为固定大小 |
| ActiveMetaNodeInner (line 1855) | `ReadRawData(sizeof(MetaNodeConfigInfo))` 使用编译期常量，非攻击者可控 |

## 触发条件

1. 攻击者通过 ServiceManager 获取 SoftBusServerStub 的 Binder 引用
2. 构造 IPC 消息，设置 `len` 字段为异常值（极大值或与实际数据不一致的值）
3. Inner handler 直接使用该长度进行后续操作

## 影响

- **SendMessageInner / CloseChannelWithStatisticsInner / OnBrProxyDataRecvInner**：未验证的 `len` 传入下游函数，若下游基于 `len` 做 `memcpy_s` 等操作，可能导致越界读写
- **GetAllOnlineNodeInfoInner**：`infoTypeLen * infoNum` 整数溢出可导致 `WriteRawData` 写入错误长度

## 建议修复

对所有从 MessageParcel 读取的长度值添加上限检查：

```cpp
uint32_t len;
if (!data.ReadUint32(len)) {
    return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
}
+if (len > MAX_MESSAGE_LEN) {  // 添加合理上限，如 64KB 或 1MB
+    COMM_LOGE(COMM_SVC, "len exceeds maximum: %{public}u", len);
+    return SOFTBUS_INVALID_PARAM;
+}
auto rawData = data.ReadRawData(len);
```

对 `GetAllOnlineNodeInfoInner` 中的乘法添加溢出检查：

```cpp
+if (infoTypeLen > 0 && infoNum > INT32_MAX / infoTypeLen) {
+    COMM_LOGE(COMM_SVC, "integer overflow in size calculation");
+    SoftBusFree(nodeInfo);
+    return SOFTBUS_IPC_ERR;
+}
if (!reply.WriteRawData(nodeInfo, static_cast<int32_t>(infoTypeLen * infoNum))) {
```
