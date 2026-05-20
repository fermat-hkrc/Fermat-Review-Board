---
id: PBT-OH-2026-DEVMGR-002
date: "2026-05-18"
repo: distributedhardware_device_manager
repo_url: https://gitcode.com/openharmony/distributedhardware_device_manager
title: "UnbindServiceProxyParam serialization omits peerTokenId/peerNetworkId/peerUdid — peer silently receives zeroed fields"
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
author: Toan
---

## Summary

`UnbindServiceProxyParam` defines `peerTokenId`, `peerNetworkId`, and `peerUdid` fields, but `ToJson`/`FromJson` in `dm_transport_msg.cpp` never serialize or deserialize them. Every IPC message carrying this struct arrives at the peer with these fields zeroed/empty — device identity and auth data silently dropped.

## Vulnerable Code

```cpp
// services/service/src/relationshipsyncmgr/dm_transport_msg.cpp
// ToJson — peerTokenId, peerNetworkId, peerUdid never written to JSON
void ToJson(cJSON *jsonObject, const UnbindServiceProxyParam &unBindServiceMsg)
{
    // ... other fields serialized normally ...
    // ❌ Missing: peerTokenId (vector<uint64_t>)
    // ❌ Missing: peerNetworkId (string)
    // ❌ Missing: peerUdid (string)
}

// FromJson — same three fields never read back
void FromJson(cJSON *jsonObject, UnbindServiceProxyParam &unBindServiceMsg)
{
    // ... other fields deserialized normally ...
    // ❌ Missing: peerTokenId
    // ❌ Missing: peerNetworkId
    // ❌ Missing: peerUdid
}
```

Struct definition in `dm_device_info.h` includes all three fields, yet serialization skips them:

```cpp
// interfaces/inner_kits/native_cpp/include/dm_device_info.h
struct UnbindServiceProxyParam {
    std::vector<uint64_t> peerTokenId;   // ❌ ToJson/FromJson does not handle
    std::string peerNetworkId;           // ❌ ToJson/FromJson does not handle
    std::string peerUdid;                // ❌ ToJson/FromJson does not handle
    std::string localUdid;              // ✅ handled
    int32_t userId;                      // ✅ handled
};
```

## Trigger Conditions

1. Two devices execute the UnbindServiceProxy flow
2. Caller constructs `UnbindServiceProxyParam` with `peerTokenId`, `peerNetworkId`, `peerUdid` populated
3. `DMCommTool::SendUnBindServiceProxyObj` calls `ToJson` to serialize and sends the message
4. Peer's `DeviceManagerService::ProcessUnBindServiceProxy` calls `FromJson` to deserialize
5. Result: `peerTokenId == {}`, `peerNetworkId == ""`, `peerUdid == ""` — silent data loss

## Impact

- **Device identification failure**: Peer cannot obtain the remote device's NetworkId or UDID, potentially causing unbind operations to target the wrong device
- **Auth data loss**: `peerTokenId` arrives empty; any logic relying on it for identity verification operates on null data
- **Silent failure**: No log or error indicates that fields were dropped, making debugging difficult

## Suggested Fix

Add the missing field serialization to both `ToJson` and `FromJson` in `dm_transport_msg.cpp`:

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

**Note on `peerTokenId`**: Must use `valuedouble` (not `valueint`) when deserializing `uint64_t` values from cJSON, since `valueint` is `int` and truncates values above `INT32_MAX`.