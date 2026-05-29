---
id: OH-2026-SECCOMP-001
date: "2026-05-07"
repo: security_security_component_manager
repo_url: https://gitcode.com/openharmony/security_security_component_manager
title: "FirstUseDialog::SendSaveEventHandler 未检查 secHandler_ 空指针"
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: CONFIRMED_FIXED
language: "C++"
issue_url: https://gitcode.com/openharmony/security_security_component_manager/issues/395
author: Zirui
---


## 漏洞概述

`FirstUseDialog::SendSaveEventHandler` 直接调用 `secHandler_->ProxyPostTask(delayed)` 而未检查 `secHandler_` 是否为 nullptr。同类中其他函数（如 `NotifyFirstUseDialog` line 520）对 `secHandler_` 有 nullptr 检查，证明该成员可能为空。

## 漏洞详情

### 问题代码

**文件**: `services/security_component_service/sa/sa_main/first_use_dialog.cpp:469-477`

```cpp
void FirstUseDialog::SendSaveEventHandler(void)
{
    std::function<void()> delayed = ([this]() {
        this->SaveFirstUseRecord();
    });

    SC_LOG_INFO(LABEL, "Delay first_use_record json");
    secHandler_->ProxyPostTask(delayed);  // ← 无 null check
}
```

### 对比：同类正确实现

**文件**: `first_use_dialog.cpp:520-523`

```cpp
int32_t FirstUseDialog::NotifyFirstUseDialog(...)
{
    // ...
    if (secHandler_ == nullptr) {  // ← 正确：检查了 nullptr
        SC_LOG_ERROR(LABEL, "event handler invalid.");
        return SC_SERVICE_ERROR_VALUE_INVALID;
    }
    // ...
}
```

### 触发条件

1. `FirstUseDialog` 对象的 `secHandler_` 成员未初始化或已被置空
2. 调用 `SendSaveEventHandler` 时解引用 nullptr → SIGSEGV
3. 可能在服务初始化阶段或异常恢复路径中触发

### 影响

- security_component_service 服务进程崩溃
- 安全组件首次使用记录丢失
- 服务重启期间安全组件功能不可用

## 修复建议

```cpp
void FirstUseDialog::SendSaveEventHandler(void)
{
    std::function<void()> delayed = ([this]() {
        this->SaveFirstUseRecord();
    });

    SC_LOG_INFO(LABEL, "Delay first_use_record json");
+   if (secHandler_ == nullptr) {
+       SC_LOG_ERROR(LABEL, "secHandler_ is nullptr in SendSaveEventHandler");
+       return;
+   }
    secHandler_->ProxyPostTask(delayed);
}
```

## 涉及文件

- `services/security_component_service/sa/sa_main/first_use_dialog.cpp` (line 476) — 缺失 null check
