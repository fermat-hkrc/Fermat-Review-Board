---
id: OH-2026-DEVMGR-002
date: "2026-05-18"
repo: distributedhardware_device_manager
repo_url: https://gitcode.com/openharmony/distributedhardware_device_manager
title: "UnbindServiceProxyParam 序列化缺失 peerTokenId/peerNetworkId/peerUdid 字段，通信对端静默丢失数据"
cwe: CWE-1066
cwe_name: Missing Serialization Control Element
severity: MEDIUM
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/distributedhardware_device_manager/issues/2438
affected_version: "5.0+"
component: relationshipsyncmgr
file_paths:
  - services/service/src/relationshipsyncmgr/dm_transport_msg.cpp
  - interfaces/inner_kits/native_cpp/include/dm_device_info.h
author: Zirui
---

## 漏洞概述

`UnbindServiceProxyParam` 结构体包含 `peerTokenId`、`peerNetworkId`、`peerUdid` 三个字段，但 `dm_transport_msg.cpp` 中的 `ToJson`/`FromJson` 未对这些字段进行序列化与反序列化。所有经 IPC 传输的 `UnbindServiceProxyParam` 消息到达对端后，这三个字段为空值/零值，导致设备识别与鉴权数据静默丢失。

## 问题代码

```cpp
// services/service/src/relationshipsyncmgr/dm_transport_msg.cpp
// ToJson — peerTokenId, peerNetworkId, peerUdid 均未写入 JSON
void ToJson(cJSON *jsonObject, const UnbindServiceProxyParam &unBindServiceMsg)
{
    // ... 其他字段正常序列化 ...
    // ❌ 缺失: peerTokenId (vector<uint64_t>)
    // ❌ 缺失: peerNetworkId (string)
    // ❌ 缺失: peerUdid (string)
}

// FromJson — 同样未读取这三个字段
void FromJson(cJSON *jsonObject, UnbindServiceProxyParam &unBindServiceMsg)
{
    // ... 其他字段正常反序列化 ...
    // ❌ 缺失: peerTokenId
    // ❌ 缺失: peerNetworkId
    // ❌ 缺失: peerUdid
}
```

结构体定义（`dm_device_info.h`）中三个字段完整存在，但序列化代码不覆盖它们：

```cpp
// interfaces/inner_kits/native_cpp/include/dm_device_info.h
struct UnbindServiceProxyParam {
    std::vector<uint64_t> peerTokenId;   // ❌ ToJson/FromJson 未处理
    std::string peerNetworkId;           // ❌ ToJson/FromJson 未处理
    std::string peerUdid;                 // ❌ ToJson/FromJson 未处理
    std::string localUdid;               // ✅ 已处理
    int32_t userId;                       // ✅ 已处理
};
```

## 触发条件

1. 设备间执行 UnbindServiceProxy 流程
2. 调用方构造 `UnbindServiceProxyParam` 并填充 `peerTokenId`、`peerNetworkId`、`peerUdid`
3. `DMCommTool::SendUnBindServiceProxyObj` 调用 `ToJson` 序列化并发送
4. 对端 `DeviceManagerService::ProcessUnBindServiceProxy` 调用 `FromJson` 反序列化
5. 结果：`peerTokenId == {}`, `peerNetworkId == ""`, `peerUdid == ""` — 静默数据丢失

## 影响

- **设备识别失败**: 对端无法获取 peer 的 NetworkId 和 UDID，可能导致解绑操作指向错误设备
- **鉴权数据丢失**: `peerTokenId` 为空，依赖该字段的身份验证逻辑将基于空数据执行
- **静默错误**: 无任何日志或错误提示表明数据被丢弃，增加调试难度

## 修复建议

在 `dm_transport_msg.cpp` 的 `ToJson` 和 `FromJson` 中补全缺失字段的序列化：

```cpp
// In ToJson:
cJSON *peerTokenIdArr = cJSON_CreateArray();
for (auto const &tokenId : unBindServiceMsg.peerTokenId) {
    cJSON *item = cJSON_CreateNumber(static_cast<double>(tokenId));
    cJSON_AddItemToArray(peerTokenIdArr, item);
}
cJSON_AddItemToObject(jsonObject, "peerTokenId", peerTokenIdArr);
cJSON_AddStringToObject(jsonObject, "peerNetworkId", unBindServiceMsg.peerNetworkId.c_str());
cJSON_AddStringToObject(jsonObject, "peerUdid", unBindServiceMsg.peerUdid.c_str());

// In FromJson:
cJSON *peerTokenIdArr = cJSON_GetObjectItem(jsonObject, "peerTokenId");
if (cJSON_IsArray(peerTokenIdArr)) {
    int32_t arrSize = cJSON_GetArraySize(peerTokenIdArr);
    for (int32_t i = 0; i < arrSize; i++) {
        cJSON *item = cJSON_GetArrayItem(peerTokenIdArr, i);
        if (cJSON_IsNumber(item)) {
            unBindServiceMsg.peerTokenId.push_back(static_cast<uint64_t>(item->valuedouble));
        }
    }
}
cJSON *peerNetworkIdObj = cJSON_GetObjectItem(jsonObject, "peerNetworkId");
if (cJSON_IsString(peerNetworkIdObj)) {
    unBindServiceMsg.peerNetworkId = peerNetworkIdObj->valuestring;
}
cJSON *peerUdidObj = cJSON_GetObjectItem(jsonObject, "peerUdid");
if (cJSON_IsString(peerUdidObj)) {
    unBindServiceMsg.peerUdid = peerUdidObj->valuestring;
}
```

**注意**: `peerTokenId` 为 `vector<uint64_t>`，反序列化时必须使用 `valuedouble` 而非 `valueint`，因为 cJSON 的 `valueint` 为 `int` 类型，截断大于 `INT32_MAX` 的值。