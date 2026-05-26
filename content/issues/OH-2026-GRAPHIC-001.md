---
id: OH-2026-GRAPHIC-001
date: "2026-05-11"
repo: graphic_graphic_surface
repo_url: https://gitcode.com/openharmony/graphic_graphic_surface
title: "NativeWindow API va_arg 指针未校验"
cwe: CWE-457
cwe_name: Use of Uninitialized Variable
status: SUBMITTED
language: "C++"
issue_url: https://gitcode.com/openharmony/graphic_graphic_surface/issues/980
author: Zirui
---

## 漏洞概述

`HandleNativeWindowSetSurfaceAppFrameworkType` 通过 `va_arg` 从 variadic argument 获取 `char*` 指针。虽然代码检查了 nullptr，但如果调用者传入一个非空但无效的指针（悬空、已释放、或未初始化），`std::string` 构造函数会读取未初始化内存，可能导致信息泄露或崩溃。

## 漏洞详情

### 问题代码

**文件**: `surface/src/native_window.cpp`

```cpp
static void HandleNativeWindowSetSurfaceAppFrameworkType(OHNativeWindow *window, va_list args)
{
    char* appFrameworkType = va_arg(args, char*);    // L397
    if (appFrameworkType != nullptr) {                // L398: 仅检查 nullptr
        std::string typeStr(appFrameworkType);         // L399: 未校验指针内容有效性
        window->surface->SetSurfaceAppFrameworkType(typeStr);
    }
}
```

### 问题分析

该函数作为 NativeWindow 公共 API 的内部 handler，通过 `va_list` 接收参数。调用链为：

```
OH_NativeWindow_SetSurfaceAppFrameworkType(window, type)
  → Dispatch(window, args)
    → HandleNativeWindowSetSurfaceAppFrameworkType(window, args)
```

**风险路径**：
1. 调用者传入未初始化的 `char*`（非 nullptr） → `std::string` 构造函数读取随机内存
2. 调用者传入指向已释放内存的 `char*` → 读取已释放内存（use-after-free）
3. 调用者传入非 null-terminated 的 `char*` → `std::string` 读取越界

**影响**：
- `std::string` 构造函数从无效指针读取 → **段错误/崩溃**
- 如果读取的内存恰好不触发崩溃 → 可能将内部内存内容传入 `SetSurfaceAppFrameworkType`，造成**信息泄露**
- 由于是公共 API，攻击者可通过构造恶意参数触发

## 触发条件

1. 调用 `OH_NativeWindow_SetSurfaceAppFrameworkType(window, invalid_ptr)` 其中 `invalid_ptr` 非空但无效
2. 需要 NativeWindow 句柄的访问权限（通常需要应用沙箱内的权限）

## 修复建议

```cpp
static void HandleNativeWindowSetSurfaceAppFrameworkType(OHNativeWindow *window, va_list args)
{
    char* appFrameworkType = va_arg(args, char*);
    if (appFrameworkType == nullptr) {
        return;
    }
+   // 防御性校验：确保指针指向有效的 null-terminated 字符串
+   size_t len = strnlen(appFrameworkType, MAX_FRAMEWORK_TYPE_LEN);
+   if (len == 0 || len >= MAX_FRAMEWORK_TYPE_LEN) {
+       BLOGE("Invalid appFrameworkType: invalid length");
+       return;
+   }
    std::string typeStr(appFrameworkType);
    window->surface->SetSurfaceAppFrameworkType(typeStr);
}
```

## 涉及文件

- `surface/src/native_window.cpp` (lines 395-402)
- `surface/include/native_window.h` (API 声明)

## 参考

- CWE-457: Use of Uninitialized Variable
- CWE-20: Improper Input Validation
