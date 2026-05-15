---
id: OH-2026-SECCOMP-002
date: "2026-05-07"
repo: security_security_component_manager
repo_url: https://gitcode.com/openharmony/security_security_component_manager
title: "SecCompClient::GetInstance 在 OOM 时解引用空指针"
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/security_security_component_manager/issues/395
author: Zirui
---

---

## 漏洞概述

`SecCompClient::GetInstance()` 使用 `new (std::nothrow)` 分配实例，当内存不足时返回 nullptr 并赋值给 `instance`。后续 `return *instance` 解引用 nullptr 导致崩溃。由于使用了 `std::nothrow`，开发者明确预期分配可能失败，但未处理失败情况。

## 漏洞详情

### 问题代码

**文件**: `frameworks/inner_api/security_component/src/sec_comp_client.cpp:43-54`

```cpp
SecCompClient& SecCompClient::GetInstance()
{
    static SecCompClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            SecCompClient* tmp = new (std::nothrow)SecCompClient();
            instance = std::move(tmp);  // ← tmp 可能为 nullptr
        }
    }
    return *instance;  // ← OOM 时解引用 nullptr → 崩溃
}
```

### 分析

- 使用 `new (std::nothrow)` 明确表示开发者预期分配可能失败
- 但分配失败后 `instance` 被赋值为 nullptr
- `return *instance` 解引用 nullptr → 未定义行为（通常 SIGSEGV）
- 由于 `instance` 是 static 变量，首次 OOM 后所有后续调用也会崩溃

### 触发条件

1. 系统内存压力大，`new (std::nothrow)` 返回 nullptr
2. 任何调用 `SecCompClient::GetInstance()` 的代码路径触发崩溃
3. 嵌入式/IoT 设备上更容易触发

### 影响

- 调用进程崩溃（SIGSEGV）
- 所有使用安全组件客户端 SDK 的应用受影响
- OOM 条件下级联崩溃

## 修复建议

方案 A：移除 `std::nothrow`，让 OOM 抛出 `std::bad_alloc`（由上层处理）：

```cpp
SecCompClient& SecCompClient::GetInstance()
{
    static SecCompClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
-           SecCompClient* tmp = new (std::nothrow)SecCompClient();
+           SecCompClient* tmp = new SecCompClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}
```

方案 B：保留 `std::nothrow` 但处理失败：

```cpp
SecCompClient& SecCompClient::GetInstance()
{
    static SecCompClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            SecCompClient* tmp = new (std::nothrow)SecCompClient();
+           if (tmp == nullptr) {
+               SC_LOG_ERROR(LABEL, "Failed to allocate SecCompClient");
+               // 选择：abort() 或返回 static dummy（取决于架构决策）
+           }
            instance = std::move(tmp);
        }
    }
    return *instance;
}
```

## 涉及文件

- `frameworks/inner_api/security_component/src/sec_comp_client.cpp` (line 49-53) — OOM 未处理
