---
id: OH-2026-SECCOMP-003
date: "2026-05-07"
repo: security_security_component_manager
repo_url: https://gitcode.com/openharmony/security_security_component_manager
title: "WindowInfoHelper::TryGetWindowInfo 在 find_if lambda 中解引用可能为空的 sptr"
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_security_component_manager/issues/395
author: Zirui
---

---

## 漏洞概述

`WindowInfoHelper::TryGetWindowInfo` 在 `std::find_if` 的 lambda 中直接访问 `info->wid_`，但 `infos` 向量中的 `sptr<Rosen::AccessibilityWindowInfo>` 元素可能为 nullptr。null check（`*iter == nullptr`）在 `find_if` 之后才执行，此时 lambda 已经对 null 元素进行了解引用。

## 漏洞详情

### 问题代码

**文件**: `services/security_component_service/sa/sa_main/window_info_helper.cpp:33-48`

```cpp
bool WindowInfoHelper::TryGetWindowInfo(int32_t windowId, sptr<Rosen::AccessibilityWindowInfo>& windowInfo)
{
    std::vector<sptr<Rosen::AccessibilityWindowInfo>> infos;
    if (Rosen::WindowManager::GetInstance().GetAccessibilityWindowInfo(infos) != Rosen::WMError::WM_OK) {
        SC_LOG_ERROR(LABEL, "Get AccessibilityWindowInfo failed");
        return false;
    }
    auto iter = std::find_if(infos.begin(), infos.end(),
        [windowId](const sptr<Rosen::AccessibilityWindowInfo> info) {
            return windowId == info->wid_;  // ← 若 info 为 null sptr，崩溃
        });
    if ((iter == infos.end()) || (*iter == nullptr)) {  // ← null check 太晚
        return false;
    }
    windowInfo = *iter;
    return true;
}
```

### 分析

- `GetAccessibilityWindowInfo` 返回的向量中可能包含 null sptr 元素
- Line 43 的 `(*iter == nullptr)` 检查证明开发者预期向量中可能有 null 元素
- 但 `find_if` 的 lambda（line 40-41）在遍历过程中已经对每个元素调用 `info->wid_`
- 如果 null 元素出现在目标元素之前，lambda 会先解引用 null → 崩溃

### 触发条件

1. `GetAccessibilityWindowInfo` 返回的向量中包含 null sptr 元素
2. `find_if` 遍历到该 null 元素时调用 `info->wid_` → SIGSEGV
3. 取决于窗口管理器的实现是否会在向量中放入 null 元素

### 影响

- security_component_service 服务进程崩溃
- 安全组件窗口信息查询失败
- 依赖安全组件的 UI 功能不可用

## 修复建议

```cpp
    auto iter = std::find_if(infos.begin(), infos.end(),
        [windowId](const sptr<Rosen::AccessibilityWindowInfo> info) {
-           return windowId == info->wid_;
+           return info != nullptr && windowId == info->wid_;
        });
-   if ((iter == infos.end()) || (*iter == nullptr)) {
+   if (iter == infos.end()) {
        return false;
    }
```

## 涉及文件

- `services/security_component_service/sa/sa_main/window_info_helper.cpp` (line 40-41) — lambda 中缺失 null check
