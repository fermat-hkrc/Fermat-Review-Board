---
id: OH-2026-TELREG-002
date: "2026-05-07"
repo: telephony_state_registry
repo_url: https://gitcode.com/openharmony/telephony_state_registry
title: "EventListenerHandler 多个 Work* 函数在 napi_open_handle_scope 失败后继续执行"
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/telephony_state_registry/issues/254
author: fermat-hkrc
---

---

## 漏洞概述

`EventListenerHandler` 中 13 个 `Work*` 回调函数在调用 `napi_open_handle_scope(env, &scope)` 后检查 `scope == nullptr`，但仅打印错误日志而不返回，继续使用可能无效的 `env` 调用 NAPI API（`napi_create_object`、`napi_set_element` 等）。当 `napi_open_handle_scope` 失败时（例如 JS 引擎已关闭或 env 无效），后续 NAPI 调用行为未定义，可能导致崩溃。

## 漏洞详情

### 问题代码模式（13 处重复）

**文件**: `frameworks/js/napi/src/event_listener_handler.cpp`

```cpp
// 示例：WorkCallStateUpdated (line 769)
void EventListenerHandler::WorkCallStateUpdated(uv_work_t *work, std::unique_lock<std::mutex> &lock)
{
    std::unique_ptr<CallStateContext> callStateInfo(static_cast<CallStateContext *>(work->data));
    const napi_env &env = callStateInfo->env;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        TELEPHONY_LOGE("scope is nullptr");  // ← 仅打印日志
    }
    // ← 缺少 return，继续执行
    napi_value callbackValue = nullptr;
    napi_create_object(callStateInfo->env, &callbackValue);  // ← 可能崩溃
    ...
}
```

### 对比：同文件正确实现

```cpp
// NapiReturnToJS (line 168) — 正确处理
napi_status NapiReturnToJS(napi_env env, napi_ref callbackRef, napi_value callbackVal, ...)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        TELEPHONY_LOGE("scope is nullptr");
        napi_close_handle_scope(env, scope);
        lock.unlock();
        return napi_ok;  // ← 正确：提前返回
    }
    ...
}
```

### 受影响函数（13 个）

| 行号 | 函数名 |
|------|--------|
| 775 | `WorkCallStateUpdated` |
| 794 | `WorkCallStateExUpdated` |
| 812 | `WorkSignalUpdated` |
| 837 | `WorkNetworkStateUpdated` |
| 869 | `WorkSimStateUpdated` |
| 891 | `WorkCellInfomationUpdated` |
| 910 | `WorkCellularDataConnectStateUpdated` |
| 927 | `WorkCellularDataFlowUpdated` |
| 945 | `WorkCfuIndicatorUpdated` |
| 964 | `WorkVoiceMailMsgIndicatorUpdated` |
| 983 | `WorkIccAccountUpdated` |
| 1044 | `WorkCCallStateUpdated` |

### 触发条件

1. JS 引擎正在关闭或 env 已失效时收到 telephony 状态更新回调
2. `napi_open_handle_scope` 返回失败（scope 为 nullptr）
3. 后续 NAPI 调用使用无效的 scope/env，行为未定义

### 影响

- 应用进程崩溃（SIGSEGV）
- 竞态条件：应用退出过程中收到异步回调时触发
- 影响所有注册了 telephony 状态监听的应用

## 修复建议

在每个 `Work*` 函数的 `scope == nullptr` 检查后添加 `return`：

```cpp
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        TELEPHONY_LOGE("scope is nullptr");
+       napi_close_handle_scope(env, scope);
+       return;
    }
```

## 涉及文件

- `frameworks/js/napi/src/event_listener_handler.cpp` (13 处，lines 775-1046)

## 扫描元数据

- **发现日期**: 2026-05-12
- **扫描工具**: Fermat Security Scanner L3 + 人工源码验证
- **检测规则**: MS-06-A1 (Null Pointer Dereference)
- **检测方式**: 静态分析发现模式 + 人工确认同文件有正确实现作为对比
- **置信度**: MEDIUM — 取决于 NAPI 引擎对 null scope 的容忍度，但属于明确的代码缺陷
