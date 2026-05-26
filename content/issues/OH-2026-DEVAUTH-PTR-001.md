---
id: OH-2026-DEVAUTH-PTR-001
date: "2026-04-29"
repo: security_device_auth
repo_url: https://gitcode.com/openharmony/security_device_auth
title: "IPC 回调从 IPC 数据读取函数指针并直接调用"
cwe: CWE-822
cwe_name: Untrusted Pointer Dereference
status: CONFIRMED_FIXED
language: "C++"
issue_url: https://gitcode.com/openharmony/security_device_auth/issues/1035
author: Zirui
---

### 漏洞编号：
            
CWE-822 (Untrusted Pointer Dereference)
### 漏洞归属组件
            
frameworks/src/standard
### 漏洞归属版本
            
2026.04.23 最新版本
### CVSS V3.0分值
            

### 漏洞简述
            
### 完整攻击链

#### Step 1 — 发送端写入原始指针到 IPC

```cpp
// ipc_callback_proxy.cpp:28-49 — ProxyDevAuthCb::DoCallBack
void ProxyDevAuthCb::DoCallBack(int32_t callbackId, uintptr_t cbHook, ...) {
    (void)data.WriteInt32(callbackId);    // line 43: 写入 callbackId
    (void)data.WritePointer(cbHook);      // line 44: 将函数指针作为 uintptr_t 写入 IPC
    ret = remote->SendRequest(
        static_cast<uint32_t>(DevAuthCbInterfaceCode::DEV_AUTH_CALLBACK_REQUEST), ...);
}
```

攻击者控制 `cbHook` 值，通过 `WritePointer` 序列化为原始 `uintptr_t` 写入 IPC 消息。

#### Step 2 — 接收端从 IPC 读出指针，无任何验证

```cpp
// ipc_callback_stub.cpp:55-80 — StubDevAuthCb::OnRemoteRequest
int32_t StubDevAuthCb::OnRemoteRequest(uint32_t code, MessageParcel &data, ...) {
    if (data.ReadInterfaceToken() != GetDescriptor()) { return -1; }  // line 58: 仅接口令牌
    callbackId = data.ReadInt32();       // line 71
    cbHook = data.ReadPointer();          // line 72: 从 IPC 读出原始指针，无验证
    StubDevAuthCb::DoCallBack(callbackId, cbHook, data, reply, option);  // line 73: 直接分发
}
```

#### Step 3 — DoCallBack 仅检查非零

```cpp
// ipc_callback_stub.cpp:30-53 — StubDevAuthCb::DoCallBack
void StubDevAuthCb::DoCallBack(int32_t callbackId, uintptr_t cbHook, ...) {
    if (cbHook == 0x0) { return; }  // line 38: 唯一检查：非零即通过
    ProcCbHook(callbackId, cbHook, cbDataCache, ...);  // line 51: 传递攻击者控制的地址
}
```

#### Step 4 — ProcCbHook 分发至回调桩

```cpp
// ipc_adapt.cpp:736-757 — ProcCbHook
void ProcCbHook(int32_t callbackId, uintptr_t cbHook, ...) {
    CallbackStub stubTable[] = {
        OnTransmitStub, OnSessKeyStub, OnFinishStub, OnErrorStub,
        OnRequestStub, OnGroupCreatedStub, OnGroupDeletedStub, OnDevBoundStub,
        OnDevUnboundStub, OnDevUnTrustStub, OnDelLastGroupStub, OnTrustDevNumChangedStub,
        OnCredAddStub, OnCredDeleteStub, OnCredUpdateStub,
    };  // line 739-744: 15 个回调桩
    if ((callbackId < CB_ID_ON_TRANS) || (callbackId > CB_ID_ON_CRED_UPDATE)) { return; }
    if (cbHook == 0x0) { return; }  // line 750: 再次空指针检查，仍无地址验证
    CallbackParams params = { cbHook, cbDataCache, cacheNum, *reply };
    stubTable[callbackId - 1](params);  // line 755: 分发
}
```

#### Step 5 — 回调桩 reinterpret_cast 后直接调用（CFI 已禁用）

```cpp
// ipc_adapt.cpp:479-497 — OnTransmitStub（其余 14 个模式相同）
__attribute__((no_sanitize("cfi"))) static void OnTransmitStub(CallbackParams params) {
    bool (*onTransmitHook)(int64_t, uint8_t *, uint32_t) =
        reinterpret_cast<bool (*)(int64_t, uint8_t *, uint32_t)>(params.cbHook);  // line 488
    // ...从 IPC 数据提取参数...
    bRet = onTransmitHook(requestId, data, dataLen);  // line 494: 执行攻击者指定的地址
}

// ipc_adapt.cpp:499-516 — OnSessKeyStub（会话密钥回调）
__attribute__((no_sanitize("cfi"))) static void OnSessKeyStub(CallbackParams params) {
    void (*onSessKeyHook)(int64_t, uint8_t *, uint32_t) =
        reinterpret_cast<void (*)(int64_t, uint8_t *, uint32_t)>(params.cbHook);  // line 508
    onSessKeyHook(requestId, keyData, dataLen);  // line 514: 执行，参数含会话密钥数据
}
```

全部 15 个桩函数（OnTransmitStub, OnSessKeyStub, OnFinishStub, OnErrorStub, OnRequestStub, OnGroupCreatedStub, OnGroupDeletedStub, OnDevBoundStub, OnDevUnboundStub, OnDevUnTrustStub, OnDelLastGroupStub, OnTrustDevNumChangedStub, OnCredAddStub, OnCredDeleteStub, OnCredUpdateStub）均标注 `__attribute__((no_sanitize("cfi")))` 禁用控制流完整性检查。

### 触发条件

1. 攻击者进程可向 device_auth 回调桩发送 IPC 消息（任何拥有 `TOKEN_NATIVE` 权限的本地进程）
2. 回调桩已注册（任何设备认证客户端调用 `InitProxyAdapt()` 时注册）
3. 攻击者知道接口描述符字符串（可从公开共享库中获取）
### 影响性分析说明
            
### 影响

- **任意代码执行**：攻击者指定 `cbHook` 为任意地址，在 device_manager / softbus_server（`APL_SYSTEM_CORE` / `APL_SYSTEM_BASIC`）上下文中执行
- **会话密钥窃取**：OnSessKeyStub 接收 ECDH/DH 原始会话密钥数据
- **信任组操控**：OnGroupCreatedStub / OnDevBoundStub 控制设备信任关系
- CFI 显式禁用，编译器控制流完整性保护不生效
### 原理分析
            
### 触发条件

1. 攻击者进程可向 device_auth 回调桩发送 IPC 消息（任何拥有 `TOKEN_NATIVE` 权限的本地进程）
2. 回调桩已注册（任何设备认证客户端调用 `InitProxyAdapt()` 时注册）
3. 攻击者知道接口描述符字符串（可从公开共享库中获取）

### 受影响版本
            

### 规避方案或消减措施
            
### 建议修复（伪代码）

用回调索引替代原始指针传输：

```cpp
// ===== 方案：回调注册表 + 索引传输 =====

// 1) 新增本地回调注册表（仅在进程内部维护）
static std::unordered_map<int32_t, uintptr_t> g_registeredCallbacks;
static int32_t g_nextCallbackIndex = 1;

// 2) 注册时：存储函数指针，返回索引
int32_t RegisterCallback(uintptr_t funcPtr) {
    int32_t idx = g_nextCallbackIndex++;
    g_registeredCallbacks[idx] = funcPtr;
    return idx;  // 返回索引而非原始指针
}

// 3) Proxy 端：发送索引而非指针
void ProxyDevAuthCb::DoCallBack(int32_t callbackId, int32_t callbackIndex, ...) {
    data.WriteInt32(callbackId);
    data.WriteInt32(callbackIndex);      // 改为发送索引
    // ... 其余不变 ...
}

// 4) Stub 端：通过索引查找本地指针
void StubDevAuthCb::DoCallBack(int32_t callbackId, int32_t callbackIndex, ...) {
    auto it = g_registeredCallbacks.find(callbackIndex);
    if (it == g_registeredCallbacks.end()) {
        LOGE("Invalid callback index: %d", callbackIndex);
        return;  // 拒绝未注册的索引
    }
    uintptr_t cbHook = it->second;  // 本地验证后的合法指针
    ProcCbHook(callbackId, cbHook, ...);
}

// 5) 移除所有 __attribute__((no_sanitize("cfi")))
//    OnTransmitStub, OnSessKeyStub, ... (15 个桩函数)
```
