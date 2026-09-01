---
id: OH-2026-TELEPHONY-002
date: "2026-08-18"
repo: telephony_core_service
repo_url: https://gitcode.com/openharmony/telephony_core_service
title: "28 个 SIM NAPI 接口在异步任务创建失败时泄漏上下文"
severity: LOW
cwe: CWE-401
cwe_name: Missing Release of Memory after Effective Lifetime
status: PENDING
hidden_from_dashboard: true
hidden_date: "2026-09-01"
gitcode_issue_type: "缺陷"
report_count: 24
affected_version: "e313c25c811710e5425c3c51338521719b086c2b"
component: telephony.sim NAPI asynchronous work
language: C++
file_paths:
  - frameworks/js/sim/src/napi_sim.cpp
  - frameworks/js/sim/BUILD.gn
author: Zirui
vendor: public
---

## 漏洞概述

`telephony.sim` 的多项异步 NAPI 接口先通过裸 `new` 分配请求上下文，再把指针传给共享帮助函数 `NapiCreateAsyncWork2()`。该帮助函数在多个 N-API 调用失败时经 `NAPI_CALL` 直接返回 `nullptr`，但没有释放已经传入的上下文；调用者收到空结果后也直接返回。每次进入这些失败分支都会永久泄漏一个对应的异步上下文对象。

对当前源码逐一核对后，共有 29 个 `NapiCreateAsyncWork2()` 调用点。其中 `getAllSimAccountInfoList` 使用 `std::unique_ptr` 保留失败路径所有权，不受该问题影响；其余 28 个导出 API 使用裸指针，均具有相同泄漏路径。源码能够确认受影响的精确基线为 `e313c25c811710e5425c3c51338521719b086c2b`；尚未确认首个受影响或已修复的公开发行版。

## 根本原因

### 帮助函数未在所有权转移前保护传入指针

调用者的共同模式如下：

```cpp
auto asyncContext = new AsyncDefaultSlotId();
BaseContext &context = asyncContext->asyncContext.context;
// 组装参数和回调
napi_value result = NapiCreateAsyncWork2<AsyncDefaultSlotId>(
    para, asyncContext, initPara);
if (result) {
    NAPI_CALL(env,
        napi_queue_async_work_with_qos(env, context.work,
            napi_qos_user_initiated));
}
return result;
```

`NapiCreateAsyncWork2()` 只有参数匹配失败分支显式删除 `asyncContext`。围绕其他 N-API 操作的 `NAPI_CALL` 会在状态不为 `napi_ok` 时直接从函数返回，未执行清理：

```cpp
NAPI_CALL(env, napi_get_cb_info(
    env, para.info, &argc, argv, nullptr, nullptr));

if (context.callbackRef == nullptr) {
    NAPI_CALL(env, napi_create_promise(
        env, &context.deferred, &result));
} else {
    NAPI_CALL(env, napi_get_undefined(env, &result));
}

NAPI_CALL(env, napi_create_string_utf8(
    env, para.funcName.c_str(), para.funcName.length(), &resourceName));
NAPI_CALL(env, napi_create_async_work(
    env, nullptr, resourceName, para.execute, para.complete,
    static_cast<void *>(asyncContext), &context.work));
```

如果 `napi_get_cb_info()`、Promise/undefined 值创建、资源名创建或 `napi_create_async_work()` 失败，尚未建立能接管指针的异步任务，完成回调也不会运行。正常路径的完成回调会把 `data` 包装进 `std::unique_ptr`，但无法覆盖这些前置失败分支。

### 受影响接口数量为 28

当前 `InitNapiSim()` 注册的接口中，以下 28 个函数使用裸 `new` 后调用 `NapiCreateAsyncWork2()`：

1. `getDefaultVoiceSlotId`
2. `getDefaultVoiceSimId`
3. `getSimAuthentication`
4. `getSimAccountInfo`
5. `unlockPin`
6. `unlockPuk`
7. `alterPin`
8. `setLockState`
9. `setShowName`
10. `setShowNumber`
11. `unlockPin2`
12. `unlockPuk2`
13. `alterPin2`
14. `getOperatorConfigs`
15. `getActiveSimAccountInfoList`
16. `queryIccDiallingNumbers`
17. `addIccDiallingNumbers`
18. `delIccDiallingNumbers`
19. `updateIccDiallingNumbers`
20. `setVoiceMailInfo`
21. `sendEnvelopeCmd`
22. `sendTerminalResponseCmd`
23. `acceptCallSetupRequest`
24. `rejectCallSetupRequest`
25. `getLockState`
26. `unlockSimLock`
27. `getSimLabel`
28. `setSimLabelIndex`

`getAllSimAccountInfoList` 是第 29 个调用点。它以 `std::make_unique` 创建上下文，仅在异步任务成功排队后调用 `release()`，所以帮助函数返回失败时对象会由调用者自动释放。

### 构建与权限边界

`frameworks/js/sim/BUILD.gn` 的正式共享库目标 `sim` 编译 `napi_sim.cpp`，依赖 `napi:ace_napi`，安装到 `module/telephony`，并注册模块名 `telephony.sim`。`bundle.json` 将该目标列入 framework 构建组，因此问题位于随产品构建的 JS API 模块，而非测试代码。

各接口的 Telephony 权限检查位于后续执行或完成阶段，具体要求随 API 不同。这里的失败发生在异步任务建立之前，所以后续权限检查不会接管或释放上下文；这不构成 Telephony 权限绕过。普通 JavaScript 参数错误会进入 `MatchParameters()` 分支，该分支已经删除上下文，也不会触发本问题。可触发的前提是 N-API 环境异常或运行时内存、异步任务等资源不足，普通应用能否稳定制造这些失败尚未确认。

### 引入历史

提交 `3199ebc9ef6dc90153b1c409cbd926a4f52ba19b` 引入了 `NapiCreateAsyncWork2()` 的基本模式，提交 `46e0b6d94e2aff4bd1234bcca958e17825093951` 形成当前的异步上下文结构。提交 `aef9427abe2402a368011726018b4c6aff1c05f4` 为参数匹配失败增加了 `delete asyncContext`，但没有处理其他 `NAPI_CALL` 失败。后续接口继续复用该帮助函数，精确基线 `e313c25c811710e5425c3c51338521719b086c2b` 中仍有 28 个裸指针调用点。

## 影响

每次触发会泄漏一个相应类型的异步上下文及其已构造成员。单次泄漏量较小；只有在失败能够重复发生时，泄漏才会累积并增加进程内存占用，严重时可能影响 `telephony.sim` 所在应用进程的可用性。

现有源码不能证明普通应用能够稳定控制 N-API 内部失败，也没有证据表明泄漏会保留服务端 Telephony 对象、绕过权限或直接影响 `tel_core_service` 进程。因此不应将问题描述为稳定的远程拒绝服务或权限提升。

## 触发条件

1. JavaScript 调用上述 28 个异步 `telephony.sim` API 之一，并提供能够通过 `MatchParameters()` 的参数。
2. 裸指针上下文分配成功。
3. 随后的 `napi_get_cb_info()`、Promise/undefined 值创建、资源名创建或 `napi_create_async_work()` 返回失败。
4. `NapiCreateAsyncWork2()` 经 `NAPI_CALL` 返回 `nullptr`，调用者未获得成功结果，完成回调不会运行。

稳定累积资源消耗还要求上述失败可以被反复触发。当前仅确认静态失败路径，未确认普通应用具备这种稳定控制能力。

## 修复建议

1. 让 `NapiCreateAsyncWork2()` 在完成异步任务创建前以 `std::unique_ptr<AsyncContextType>` 持有上下文，只在 `napi_create_async_work()` 成功且所有权明确交给完成回调后调用 `release()`。
2. 避免在持有待释放资源的函数中直接使用会提前返回的 `NAPI_CALL`。逐项检查 `napi_status`，在统一清理路径释放上下文，并在已经创建 work 句柄时调用相应的 N-API 删除接口。
3. 统一 29 个调用点的所有权约定，使调用者保留 RAII 所有权直到异步任务成功排队；排队失败时同时释放 work 句柄和上下文。可参考当前 `getAllSimAccountInfoList` 延迟 `release()` 的实现方式。

## 参考

- [CWE-401: Missing Release of Memory after Effective Lifetime](https://cwe.mitre.org/data/definitions/401.html)
- [OpenHarmony telephony_core_service](https://gitcode.com/openharmony/telephony_core_service)
