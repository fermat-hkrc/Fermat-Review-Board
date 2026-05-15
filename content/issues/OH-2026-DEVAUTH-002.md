---
id: OH-2026-DEVAUTH-002
date: "2026-04-29"
repo: security_device_auth
repo_url: https://gitcode.com/openharmony/security_device_auth
title: "IPC 回调 Stub 参数提取失败时 NULL 传入回调函数"
severity: MEDIUM
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_device_auth/issues/1037
author: fermat-hkrc
---

## 漏洞概述

在 OpenHarmony 的设备认证服务 (`device_auth`) 中，IPC 回调分发函数通过 `GetAndValNullParam` / `GetIpcRequestParamByType` 从 IPC 数据中提取参数，但均使用 `(void)` 丢弃了返回值。当参数提取失败时，指针变量仍保持初始的 NULL 值，随后被直接传入应用注册的回调函数。若回调实现解引用这些参数则触发崩溃。

**根因**：所有 `On*Stub` 函数共享同一编码模式 —— `(void)GetAndValNullParam(...)` 丢弃错误码，不对提取结果做任何校验就传入回调。

共 **12 个受影响函数实例**（分布在 lite 和 standard 两个变体文件中）。

## 受影响函数清单

### 1. OnTransmitStub — `data` 参数可为 NULL

**文件**: `frameworks/src/lite/ipc_adapt.c:715-742`

```c
static void OnTransmitStub(CallbackParams params)
{
    int64_t requestId = 0;
    int32_t inOutLen = sizeof(requestId);
    uint8_t *data = NULL;       // ← 初始化为 NULL
    uint32_t dataLen = 0u;
    bool bRet = false;
    DeviceAuthCallback callback;

    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        (uint8_t *)(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_COMM_DATA, (uint8_t *)&data, (int32_t *)(&dataLen));
    //  ^^^^^ 返回值被丢弃，提取失败时 data 仍为 NULL

    ret = GetSdkCallBackByRequestId(params.callbackId, requestId, (uint8_t *)(&callback),
        sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) { return; }

    if (callback.onTransmit != NULL) {
        bRet = callback.onTransmit(requestId, data, dataLen);
        //                                    ^^^^
        //                          data=NULL, dataLen=0 传入回调
    }
}
```

**触发**：IPC 消息中缺少 `PARAM_TYPE_COMM_DATA` → `data` 保持 NULL → `callback.onTransmit(requestId, NULL, 0)` → 回调实现解引用 `data` → SIGSEGV。

---

### 2. OnSessKeyStub — `keyData` 参数可为 NULL

**文件**: `frameworks/src/standard/ipc_adapt.cpp:803-827`（仅 Standard 版本）

```cpp
static void OnSessKeyStub(CallbackParams params)
{
    int64_t requestId = 0;
    uint8_t *keyData = nullptr;   // ← 初始化为 nullptr
    uint32_t dataLen = 0u;
    DeviceAuthCallback callback;

    int32_t inOutLen = sizeof(requestId);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_REQID,
        reinterpret_cast<uint8_t *>(&requestId), &inOutLen);
    (void)GetIpcRequestParamByType(params.cbDataCache, params.cacheNum, PARAM_TYPE_SESS_KEY,
        reinterpret_cast<uint8_t *>(&keyData), reinterpret_cast<int32_t *>(&dataLen));
    //  ^^^^^ 返回值被丢弃，提取失败时 keyData 仍为 nullptr

    int32_t ret = GetSdkCallBackByRequestId(params.callbackId, requestId,
        reinterpret_cast<uint8_t *>(&callback), sizeof(DeviceAuthCallback));
    if (ret != HC_SUCCESS) { return; }

    if (callback.onSessionKeyReturned != nullptr) {
        callback.onSessionKeyReturned(requestId, keyData, dataLen);
        //                                       ^^^^^^^
        //                             keyData=nullptr, dataLen=0 传入回调
    }
}
```

**触发**：IPC 消息中缺少 `PARAM_TYPE_SESS_KEY` → `keyData` 保持 nullptr → `callback.onSessionKeyReturned(requestId, nullptr, 0)` → 回调解引用 → SIGSEGV。

---

### 3. OnDevBoundStub — `udid`, `groupInfo` 参数可为 NULL

**文件**: `frameworks/src/lite/ipc_adapt.c:950-973`，`frameworks/src/standard/ipc_adapt.cpp:1002-1025`

```c
static void OnDevBoundStub(CallbackParams params)
{
    const char *groupInfo = NULL;   // ← 初始化为 NULL
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;        // ← 初始化为 NULL

    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);               // ← 返回值丢弃
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);     // ← 返回值丢弃
    (void)GetAndValNullParam(params.cbDataCache, params.cacheNum,
        PARAM_TYPE_APPID, (uint8_t *)(&appId), NULL);

    if (GetSdkCallBackByAppId(appId, CB_TYPE_LISTENER, ...) != HC_SUCCESS) { return; }

    if (callback.onDeviceBound != NULL) {
        callback.onDeviceBound(udid, groupInfo);
        //                     ^^^^  ^^^^^^^^^
        //                     可能为 NULL
    }
}
```

**触发**：IPC 消息中缺少 `PARAM_TYPE_UDID` / `PARAM_TYPE_GROUP_INFO` → `udid`/`groupInfo` 保持 NULL → `callback.onDeviceBound(NULL, NULL)` → 回调解引用 → SIGSEGV。

---

### 4. OnDevUnboundStub — `udid`, `groupInfo` 参数可为 NULL

**文件**: `frameworks/src/lite/ipc_adapt.c:975-998`，`frameworks/src/standard/ipc_adapt.cpp:1026-1049`

```c
static void OnDevUnboundStub(CallbackParams params)
{
    const char *groupInfo = NULL;
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;

    (void)GetAndValNullParam(..., PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    (void)GetAndValNullParam(..., PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);
    (void)GetAndValNullParam(..., PARAM_TYPE_APPID, (uint8_t *)(&appId), NULL);

    if (GetSdkCallBackByAppId(appId, ...) != HC_SUCCESS) { return; }

    if (callback.onDeviceUnBound != NULL) {
        callback.onDeviceUnBound(udid, groupInfo);   // ← udid/groupInfo 可为 NULL
    }
}
```

**触发**：与 OnDevBoundStub 相同模式。

---

### 5. OnDevUnTrustStub — `udid` 参数可为 NULL

**文件**: `frameworks/src/lite/ipc_adapt.c:1000-1020`，`frameworks/src/standard/ipc_adapt.cpp:1050-1070`

```c
static void OnDevUnTrustStub(CallbackParams params)
{
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;

    (void)GetAndValNullParam(..., PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    (void)GetAndValNullParam(..., PARAM_TYPE_APPID, (uint8_t *)(&appId), NULL);

    if (GetSdkCallBackByAppId(appId, ...) != HC_SUCCESS) { return; }

    if (callback.onDeviceNotTrusted != NULL) {
        callback.onDeviceNotTrusted(udid);   // ← udid 可为 NULL
    }
}
```

**触发**：IPC 消息中缺少 `PARAM_TYPE_UDID` → `udid` 保持 NULL → `callback.onDeviceNotTrusted(NULL)` → 回调解引用 → SIGSEGV。

---

### 6. OnDelLastGroupStub — `udid` 参数可为 NULL

**文件**: `frameworks/src/lite/ipc_adapt.c:1022-1046`，`frameworks/src/standard/ipc_adapt.cpp:1067-1090`

```c
static void OnDelLastGroupStub(CallbackParams params)
{
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;
    int32_t groupType = 0;
    int32_t inOutLen = 0;

    (void)GetAndValNullParam(..., PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
    inOutLen = sizeof(groupType);
    (void)GetIpcRequestParamByType(..., PARAM_TYPE_GROUP_TYPE, (uint8_t *)(&groupType), &inOutLen);
    (void)GetAndValNullParam(..., PARAM_TYPE_APPID, (uint8_t *)(&appId), NULL);

    if (GetSdkCallBackByAppId(appId, ...) != HC_SUCCESS) { return; }

    if (callback.onLastGroupDeleted != NULL) {
        callback.onLastGroupDeleted(udid, groupType);   // ← udid 可为 NULL
    }
}
```

**触发**：IPC 消息中缺少 `PARAM_TYPE_UDID` → `udid` 保持 NULL → `callback.onLastGroupDeleted(NULL, groupType)` → 回调解引用 → SIGSEGV。

---

## 调用链

```
IPC 入口 (CbStubOnRemoteRequest / StubDevAuthCb::OnRemoteRequest)
  → 解码 IPC 参数到 cbDataCache
  → ProcCbHook(callbackId, params)
    → stubTable[callbackId - 1](params)
      ├─ [1] OnTransmitStub       → callback.onTransmit(requestId, NULL, 0)
      ├─ [4] OnSessKeyStub        → callback.onSessionKeyReturned(requestId, NULL, 0)
      ├─ [7] OnDevBoundStub       → callback.onDeviceBound(NULL, NULL)
      ├─ [8] OnDevUnboundStub     → callback.onDeviceUnBound(NULL, NULL)
      ├─ [9] OnDevUnTrustStub     → callback.onDeviceNotTrusted(NULL)
      └─ [10] OnDelLastGroupStub  → callback.onLastGroupDeleted(NULL, groupType)
        → 应用注册的回调实现
          → 解引用 NULL 参数 → SIGSEGV
```

## 攻击场景

```
攻击者 / 恶意设备                          设备认证服务 (device_auth)
    |                                         |
    | 1. 构造恶意回调 IPC 消息                |
    |    callbackId = 任意 (1/4/7/8/9/10)     |
    |    cbDataCache 中故意缺少关键参数        |
    |    (如 UDID / COMM_DATA / SESS_KEY)      |
    |                                         |
    | 2. 发送到 DEV_AUTH_CALLBACK_REQUEST      |
    |---------------------------------------> |
    |                                         | 3. CbStubOnRemoteRequest 接收
    |                                         | 4. ProcCbHook(callbackId, params)
    |                                         | 5. On*Stub(params)
    |                                         |    → GetAndValNullParam → 失败
    |                                         |    → 参数保持 NULL
    |                                         | 6. 查找已注册回调 → 成功
    |                                         | 7. callback.onXxx(NULL, ...)
    |                                         |    → 回调解引用 NULL → SIGSEGV
```

### 触发条件

1. 攻击者能向 device_auth 服务发送 IPC 回调消息
2. 消息中的 `callbackId` 对应上述任一 Stub（1/4/7/8/9/10）
3. 消息中故意缺少对应参数（如 `PARAM_TYPE_UDID`、`PARAM_TYPE_COMM_DATA`、`PARAM_TYPE_SESS_KEY`）
4. `GetSdkCallBackByRequestId` / `GetSdkCallBackByAppId` 能找到已注册回调
5. 回调实现中解引用了 NULL 参数

### 攻击面评估

- **IPC 端点**：`DEV_AUTH_CALLBACK_REQUEST` 服务
- **访问控制**：取决于 device_auth 服务的 IPC 权限配置
- **影响进程**：注册了 `DataChangeListener` / `DeviceAuthCallback` 的应用进程

## 影响分析

- **进程崩溃 (SIGSEGV)**：回调实现解引用 NULL 参数时触发段错误
- **设备认证服务中断**：若回调在服务进程中执行，可导致整个认证服务崩溃
- **认证状态不一致**：设备绑定/解绑/信任变更事件丢失，安全状态不同步
- **Lite 版特有**：部分 Stub 在回调崩溃前执行了 `WriteInt32(params.reply, HC_SUCCESS)`，向调用方返回成功

## 修复建议

对所有 `On*Stub` 函数，**不再丢弃参数提取的返回值**，提取失败时直接返回：

```c
// 以 OnDevUnboundStub 为例，其余同理
static void OnDevUnboundStub(CallbackParams params)
{
    const char *groupInfo = NULL;
    const char *appId = NULL;
    DataChangeListener callback;
    const char *udid = NULL;

-   (void)GetAndValNullParam(..., PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL);
-   (void)GetAndValNullParam(..., PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL);
-   (void)GetAndValNullParam(..., PARAM_TYPE_APPID, (uint8_t *)(&appId), NULL);
+   if (GetAndValNullParam(..., PARAM_TYPE_UDID, (uint8_t *)(&udid), NULL) != HC_SUCCESS ||
+       GetAndValNullParam(..., PARAM_TYPE_GROUP_INFO, (uint8_t *)(&groupInfo), NULL) != HC_SUCCESS ||
+       GetAndValNullParam(..., PARAM_TYPE_APPID, (uint8_t *)(&appId), NULL) != HC_SUCCESS) {
+       LOGE("Failed to get params in OnDevUnboundStub");
+       return;
+   }

    if (GetSdkCallBackByAppId(appId, ...) != HC_SUCCESS) { return; }

    if (callback.onDeviceUnBound != NULL) {
        callback.onDeviceUnBound(udid, groupInfo);
    }
}
```

**需修改的全部位置**：

| 文件 | 函数 | 行号 |
|------|------|------|
| `frameworks/src/lite/ipc_adapt.c` | `OnTransmitStub` | 725-728 |
| `frameworks/src/lite/ipc_adapt.c` | `OnDevBoundStub` | 957-961 |
| `frameworks/src/lite/ipc_adapt.c` | `OnDevUnboundStub` | 982-986 |
| `frameworks/src/lite/ipc_adapt.c` | `OnDevUnTrustStub` | 1006-1008 |
| `frameworks/src/lite/ipc_adapt.c` | `OnDelLastGroupStub` | 1029-1034 |
| `frameworks/src/standard/ipc_adapt.cpp` | `OnSessKeyStub` | 812-815 |
| `frameworks/src/standard/ipc_adapt.cpp` | `OnDevBoundStub` | 1008-1012 |
| `frameworks/src/standard/ipc_adapt.cpp` | `OnDevUnboundStub` | 1032-1036 |
| `frameworks/src/standard/ipc_adapt.cpp` | `OnDevUnTrustStub` | 1056-1058 |
| `frameworks/src/standard/ipc_adapt.cpp` | `OnDelLastGroupStub` | 1073-1078 |

## 涉及文件

- `frameworks/src/lite/ipc_adapt.c` (5 个函数)
- `frameworks/src/standard/ipc_adapt.cpp` (5 个函数)
- `frameworks/src/lite/ipc_callback_stub.c` (IPC 入口)
- `frameworks/src/standard/ipc_callback_stub.cpp` (IPC 入口)

