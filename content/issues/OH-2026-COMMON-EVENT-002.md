---
id: OH-2026-COMMON-EVENT-002
date: "2026-08-31"
repo: notification_common_event_service
repo_url: https://gitcode.com/openharmony/notification_common_event_service
title: "静态订阅扩展重复加载后未保存或释放 dlopen 引用"
severity: LOW
cwe: CWE-775
cwe_name: Missing Release of File Descriptor or Handle after Effective Lifetime
status: SUBMITTED
gitcode_issue_type: "缺陷"
issue_url: https://gitcode.com/openharmony/notification_common_event_service/issues/1265
report_count: 1
affected_version: "6f5e69cb84cf9e779810a17694779dc62b02850d"
component: Static Subscriber Extension Loader
language: C++
file_paths:
  - frameworks/extension/src/loader/static_subscriber_extension_module_loader.cpp
author: Zirui
vendor: public
---

## 漏洞概述

`CreateStsExtension` 成功加载静态订阅扩展动态库后，只返回库内创建的 `StaticSubscriberExtension*`，没有保存对应的 `dlopen` handle。每次重新创建扩展都会增加动态加载器引用计数，但后续没有与扩展实例生命周期绑定的释放路径。

## 根本原因

**位置**：`frameworks/extension/src/loader/static_subscriber_extension_module_loader.cpp`

失败路径会调用 `dlclose`，成功路径则丢失 handle：

```cpp
void *handle = dlopen(modulePath.c_str(), RTLD_NOW);
auto create = reinterpret_cast<CreateExtensionFunc>(dlsym(handle, symbol));
auto *extension = create();
return extension; // handle 未保存，后续无法在实例销毁时 dlclose
```

成功后不能立即关闭 handle，否则扩展实例的虚函数和析构代码可能已经被卸载。缺失的是模块引用所有者，而不是简单漏写一次 `dlclose`。

## 影响

- 重复创建 ETS 静态订阅扩展会持续累积动态库引用计数。
- 资源保留发生在承载扩展的应用进程，长期运行或反复创建时会增加进程资源占用。
- 同一路径通常复用已有映像，因此影响小于重复映射整份动态库，但资源生命周期缺陷仍然成立。

## 触发条件

同一宿主进程反复创建并销毁 ETS 静态订阅扩展实例。每次成功创建都取得新的加载引用，而现有对象或模块缓存没有保存和释放该引用。

## 修复建议

让模块对象或扩展实例的自定义 deleter 持有 handle，并在最后一个扩展实例销毁后执行 `dlclose`。不得在创建成功后立即关闭仍被实例使用的动态库。

## 参考

- [CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime](https://cwe.mitre.org/data/definitions/775.html)
