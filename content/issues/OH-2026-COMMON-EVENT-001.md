---
id: OH-2026-COMMON-EVENT-001
date: "2026-08-18"
repo: notification_common_event_service
repo_url: https://gitcode.com/openharmony/notification_common_event_service
title: "Common Event ANI 整数对象创建失败后继续使用未初始化引用"
severity: LOW
cwe: CWE-457
cwe_name: Use of Uninitialized Variable
status: PENDING
gitcode_issue_type: "缺陷"
report_count: 3
affected_version: "7082b08c6b76935db0a03c951b3677d4012fbcf5"
component: Common Event ANI bindings
language: C++
file_paths:
  - frameworks/extension/src/ani/ani_common_event_utils.cpp
  - interfaces/kits/ani/common_event/src/ani_common_event_utils.cpp
author: Zirui
vendor: terminal
---

## 漏洞概述

Common Event 的两套 ANI 转换代码通过 `CreateAniIntObject` 把原生整数包装为 `std.core.Int` 对象。该辅助函数在查找类、查找构造函数或创建对象失败时只记录日志并返回，既不初始化输出引用，也不向调用方返回失败状态。

本报告合并 3 条工具报告：静态订阅扩展转换事件数据时使用的 `codeObject`，以及 ANI 公共接口转换订阅信息时使用的 `userIdObject` 和 `priorityObject`。源码复核还在 ANI 公共接口的事件数据转换中确认了第 4 个同根因 `codeObject` 调用点。四个局部变量声明时都没有初始值。调用方在 `CreateAniIntObject` 返回后不检查结果，继续把该值传给 `CallSetter`。`report_count` 仅统计 3 条原始有效报告，额外变体不重复计数。

这两套实现分别进入 `static_subscriber_extension_ani` 和 `ani_commoneventmanager` 共享库，并由组件构建组纳入产品。当前源码能够确认错误路径会继续使用一个没有有效 ANI 整数对象的引用；尚未确认普通应用能够稳定制造这些 ANI 运行时失败，也没有动态复现崩溃或拒绝服务。

当前 `master` 提交 `7082b08c6b76935db0a03c951b3677d4012fbcf5` 仍存在该问题。公开标签 `OpenHarmony-v6.0-Release` 中的前身 `CreateAniDoubleObject` 已存在相同的错误输出处理缺陷和三个对应调用点，因此这是目前能够确认的最早受影响公开发行标签。仓库中更早的公开标签不包含该 ANI 实现；尚未确认已修复发行版。

## 根本原因

### 辅助函数没有建立失败输出约定

**位置**: `interfaces/kits/ani/common_event/src/ani_common_event_utils.cpp:531`

```cpp
void AniCommonEventUtils::CreateAniIntObject(ani_env* env, ani_object &object, ani_int value)
{
    ani_status aniResult = ANI_ERROR;
    ani_class clsInt = nullptr;
    ani_method ctor;
    aniResult = env->FindClass("std.core.Int", &clsInt);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "FindClass error. result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Class_FindMethod(clsInt, "<ctor>", "i:", &ctor);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "Class_FindMethod error. result: %{public}d.", aniResult);
        return;
    }
    aniResult = env->Object_New(clsInt, ctor, &object, value);
    if (aniResult != ANI_OK) {
        EVENT_LOGE(LOG_TAG_CES_ANI, "Object_New error. result: %{public}d.", aniResult);
        return;
    }
}
```

`frameworks/extension/src/ani/ani_common_event_utils.cpp:73` 中存在同一实现。尤其在 `FindClass` 或 `Class_FindMethod` 失败时，`object` 从未传给任何可能写入它的 API，辅助函数返回后仍保留调用方局部变量的未初始化状态。`Object_New` 失败时，辅助函数同样没有设置安全的失败值，也没有让调用方停止后续转换。

### 三个调用点无条件调用 Setter

**位置**: `frameworks/extension/src/ani/ani_common_event_utils.cpp:123`

```cpp
ani_object codeObject;
CreateAniIntObject(env, codeObject, commonEventData.GetCode());
CallSetter(env, cls, ani_data, Builder::BuildSetterName("code").c_str(), codeObject);
```

静态订阅扩展随后仍调用 `onReceiveEvent`，因此包装失败不会中止整个事件对象转换。

**位置**: `interfaces/kits/ani/common_event/src/ani_common_event_utils.cpp:383`

```cpp
ani_object userIdObject;
CreateAniIntObject(env, userIdObject, subscriber->GetSubscribeInfo().GetUserId());
CallSetter(env, cls, infoObject, Builder::BuildSetterName("userId").c_str(), userIdObject);

ani_object priorityObject;
CreateAniIntObject(env, priorityObject, subscriber->GetSubscribeInfo().GetPriority());
CallSetter(env, cls, infoObject, Builder::BuildSetterName("priority").c_str(), priorityObject);
```

同文件的 `ConvertCommonEventDataToEts` 还存在一个未被原始 3 条报告单独计数的同根因变体：

```cpp
ani_object codeObject;
CreateAniIntObject(env, codeObject, commonEventData.GetCode());
CallSetter(env, cls, ani_data, Builder::BuildSetterName("code").c_str(), codeObject);
```

`CallSetter` 只检查 Setter 查找和调用的返回值。它不会验证传入的 `value`，也不会把调用失败传回上层。`getSubscribeInfo` 最终仍返回已创建的订阅信息对象。

## 影响

- 当 `std.core.Int` 的类查找、构造函数查找或对象创建失败时，事件数据的 `code`，或订阅信息的 `userId`、`priority`，可能无法正确写入 ArkTS 对象。
- Setter 失败不会停止转换。上层仍可能收到缺少整数属性的部分对象，导致事件回调或订阅信息与原生数据不一致。
- 在没有自动变量初始化保护的构建中，读取并传递未初始化的 `ani_object` 指针属于 C++ 未定义行为，可能向 ANI 运行时传入无效引用。
- OpenHarmony 标准系统的默认 `ohos_shared_library` 构建配置会把未初始化的普通局部变量置零，且这两个 target 没有覆盖该配置。在该配置下，风险会缩小为向 Setter 传入空引用以及转换结果不完整；这项编译器保护不能替代明确的源码错误处理。

本次没有执行 ANI 故障注入或运行时触发。当前证据不支持稳定崩溃、权限提升、信息泄露或可由普通应用触发的拒绝服务结论。

## 触发条件

1. 代码进入静态订阅扩展的事件数据转换，或 ANI 公共接口的订阅信息转换。
2. `CreateAniIntObject` 在 `FindClass("std.core.Int")`、`Class_FindMethod` 或 `Object_New` 中返回非 `ANI_OK`。
3. 调用方继续执行 `CallSetter`，并在 Setter 调用失败后继续向上层传递已创建的事件数据或订阅信息对象。

这些失败通常表示 ANI 类元数据不可用、构造函数解析失败或对象分配失败。尚未发现普通应用可以通过 Common Event 输入稳定控制这些条件的路径。

## 修复建议

建议让 `CreateAniIntObject` 明确返回成功状态，并在函数入口先把输出引用设置为 `nullptr`。只有在 `Object_New` 返回 `ANI_OK` 且输出对象非空时才返回成功：

```cpp
bool AniCommonEventUtils::CreateAniIntObject(ani_env* env, ani_object& object, ani_int value)
{
    object = nullptr;
    ani_class clsInt = nullptr;
    ani_method ctor = nullptr;
    if (env->FindClass("std.core.Int", &clsInt) != ANI_OK || clsInt == nullptr) {
        return false;
    }
    if (env->Class_FindMethod(clsInt, "<ctor>", "i:", &ctor) != ANI_OK || ctor == nullptr) {
        return false;
    }
    return env->Object_New(clsInt, ctor, &object, value) == ANI_OK && object != nullptr;
}
```

四个调用点应初始化局部引用，并仅在辅助函数成功时调用 Setter。若整数属性是转换结果的必要部分，应让当前转换整体失败并向上层返回错误；若允许缺省该可选属性，也应显式跳过 Setter，而不是继续传递无有效值的引用。两套重复实现需要采用一致的失败处理方式。

## 参考

- [CWE-457: Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
