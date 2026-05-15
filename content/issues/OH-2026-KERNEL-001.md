---
id: OH-2026-KERNEL-001
date: "2026-05-03"
repo: kernel_liteos_a
repo_url: https://gitcode.com/openharmony/kernel_liteos_a
title: "LiteIPC LiteIpcTaskInit 返回值未检查导致 NULL 指针解引用"
severity: HIGH
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: CONFIRMED_REAL
issue_url: https://gitcode.com/openharmony/kernel_liteos_a/issues/1067
finding_count: 1
author: fermat-hkrc
---

您好，

在对 kernel_liteos_a 进行安全审计时，我们发现 LiteIPC 模块中多处调用 `LiteIpcTaskInit()` 后未检查返回值，当内存分配失败时将导致 NULL 指针解引用，特此报告。

## 问题描述

### 1. LiteIpcRead 中的 NULL 指针解引用

```c
// kernel/extended/liteipc/hm_liteipc.c:1153-1168
LITE_OS_SEC_TEXT STATIC UINT32 LiteIpcRead(IpcContent *content)
{
    ...
    LosTaskCB *tcb = OS_TCB_FROM_TID(selfTid);
    if (tcb->ipcTaskInfo == NULL) {
        tcb->ipcTaskInfo = LiteIpcTaskInit();  // LOS_MemAlloc 失败时返回 NULL
    }
    // 未检查返回值！
    listHead = &(tcb->ipcTaskInfo->msgListHead);  // NULL 指针解引用
```

`LiteIpcTaskInit()` 内部通过 `LOS_MemAlloc()` 分配内存，当系统内存不足时将返回 `NULL`。但调用方未对返回值进行任何检查，随后直接通过 `tcb->ipcTaskInfo->msgListHead` 访问成员，触发 NULL 指针解引用。

### 2. HandleSvc 中的相同问题

```c
// kernel/extended/liteipc/hm_liteipc.c:780-782
// HandleSvc 函数中同样存在 LiteIpcTaskInit() 返回值未检查的问题
```

### 3. LiteIpcWrite 中的相同问题

```c
// kernel/extended/liteipc/hm_liteipc.c:1075-1086
// LiteIpcWrite 函数中同样存在 LiteIpcTaskInit() 返回值未检查的问题
```

## 触发条件

1. 系统处于内存压力状态（如大量进程并发执行 IPC 操作）
2. 调用 `LiteIpcRead`、`HandleSvc` 或 `LiteIpcWrite` 时，对应任务的 `ipcTaskInfo` 为 NULL
3. `LiteIpcTaskInit()` 内部的 `LOS_MemAlloc()` 因内存不足而失败，返回 NULL
4. 后续代码解引用 NULL 指针，导致内核崩溃（kernel panic）

## 影响

- **内核崩溃（DoS）**: NULL 指针解引用将导致 LiteOS-A 内核崩溃，系统不可用
- **影响范围广**: 涉及 LiteIPC 的三个核心函数（Read/Write/HandleSvc），涵盖 IPC 读写和消息处理的完整路径
- **攻击可构造**: 攻击者可通过大量分配内存制造内存压力环境，再触发 IPC 操作来可靠地触发此漏洞

## 建议修复

在所有 `LiteIpcTaskInit()` 调用后添加 NULL 检查：

```c
// LiteIpcRead 修复示例
LITE_OS_SEC_TEXT STATIC UINT32 LiteIpcRead(IpcContent *content)
{
    ...
    LosTaskCB *tcb = OS_TCB_FROM_TID(selfTid);
    if (tcb->ipcTaskInfo == NULL) {
        tcb->ipcTaskInfo = LiteIpcTaskInit();
+       if (tcb->ipcTaskInfo == NULL) {
+           return -ENOMEM;
+       }
    }
    listHead = &(tcb->ipcTaskInfo->msgListHead);
```

`HandleSvc` 和 `LiteIpcWrite` 中的相同调用点也需要添加同样的 NULL 检查，返回适当的错误码以告知调用方内存分配失败。

## 涉及文件

- `kernel/extended/liteipc/hm_liteipc.c` (line 780-782, 1075-1086, 1153-1168)

感谢您的关注！
