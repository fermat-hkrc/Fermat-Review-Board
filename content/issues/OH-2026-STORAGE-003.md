---
id: OH-2026-STORAGE-003
date: "2026-08-18"
repo: filemanagement_storage_service
repo_url: https://gitcode.com/openharmony/filemanagement_storage_service
title: "存储空闲空间查询失败后记录未初始化输出值"
severity: LOW
cwe: CWE-457
cwe_name: Use of Uninitialized Variable
status: CONFIRMED_FIXED
gitcode_issue_type: "缺陷"
report_count: 1
affected_version: "38f4e18628953fedc48e2664b38c57009bf4446f"
component: Storage statistics manager
language: C++
file_paths:
  - services/storage_manager/storage/src/storage_total_status_service.cpp
  - services/storage_manager/storage/src/storage_monitor_service.cpp
author: Zirui
vendor: public
---

## 当前状态

历史版本中的未初始化值读取真实。当前复核提交 `ed50e0173ce700c1d613efb5f3ad63a7c63e1e25` 已在 `GetRawFreeSize` 失败后立即返回，不再记录或使用未赋值的 `freeSize`。该控制流修复由提交 `c4884ee1` 引入，因此本项标记为已修复，不提交新的上游 Issue。

## 漏洞概述

`StorageTotalStatusService::GetFreeSize` 通过 `statvfs("/data")` 查询空闲空间。当 `statvfs` 失败时，底层 `GetSizeOfPath` 直接返回错误，不写入输出引用 `freeSize`。上层虽然记录了查询失败，却没有立即返回，随后仍把 `freeSize` 作为公开整数写入一条内容标记为“success”的日志。

产品内的周期存储监控路径以未初始化的局部变量调用该函数。`StorageManagerProvider::OnStart` 启动 `StorageMonitorService`，其 `MonitorAndManageStorage` 声明 `int64_t freeSize;` 后直接传入 `GetFreeSize`。因此在 `/data` 查询失败时，当前源码存在一条明确的“未初始化调用方变量—失败不写输出—继续记录输出值”路径。

相关源文件在启用 `storage_service_storage_statistics_manager` 特性时进入 `storage_manager` 共享库，该目标由组件 `service_group` 纳入产品。受影响提交 `38f4e18628953fedc48e2664b38c57009bf4446f` 以及已核对的 `OpenHarmony-v6.0-Beta1`、`OpenHarmony-v6.0-Release` 包含同一失败路径；当前复核提交已经修复。

本次没有对 `/data` 执行卸载、权限故障或 I/O 故障注入。普通应用能否稳定使系统服务的 `statvfs("/data")` 失败尚未确认。

## 根本原因

### statvfs 失败时不写输出引用

**位置**: `services/storage_manager/storage/src/storage_total_status_service.cpp:175`

```cpp
int32_t StorageTotalStatusService::GetSizeOfPath(const char *path, int32_t type, int64_t &size)
{
    struct statvfs diskInfo;
    int ret = statvfs(path, &diskInfo);
    if (ret != E_OK) {
        return E_STATVFS;
    }
    // 只有成功后才对 size 赋值
    if (type == static_cast<int32_t>(StorageStatType::FREE)) {
        size = (int64_t)diskInfo.f_frsize * (int64_t)diskInfo.f_bavail;
    }
    return E_OK;
}
```

该接口没有在入口初始化 `size`，也没有约定错误返回时输出值必定保持安全状态。

### GetFreeSize 在错误分支后继续读取输出值

**位置**: `services/storage_manager/storage/src/storage_total_status_service.cpp:82`

```cpp
int32_t StorageTotalStatusService::GetFreeSize(int64_t &freeSize)
{
    int32_t ret = GetSizeOfPath(PATH_DATA, static_cast<int32_t>(StorageStatType::FREE), freeSize);
    if (ret != E_OK) {
        LOGE("GetFreeSize failed, please check");
        StorageRadar::ReportGetStorageStatus("GetFreeSize", DEFAULT_USERID, ret, "setting");
    }
    LOGE("StorageTotalStatusService::GetFreeSize success, (/data)freeSize=%{public}lld",
        static_cast<long long>(freeSize));
    return ret;
}
```

失败分支没有 `return`，无条件日志同时产生两项问题：读取可能未被写入的引用，并把失败操作错误标记为成功。

### 周期监控调用方没有初始化 freeSize

**位置**: `services/storage_manager/storage/src/storage_monitor_service.cpp:149`

```cpp
void StorageMonitorService::MonitorAndManageStorage()
{
    // ...
    int64_t freeSize;
    err = StorageTotalStatusService::GetInstance().GetFreeSize(freeSize);
    if ((err != E_OK) || (freeSize < 0)) {
        LOGE("Get device free size failed.");
        return;
    }
    // ...
}
```

调用方的条件使用短路求值；当 `err != E_OK` 时，它不会继续计算 `freeSize < 0`。但未初始化值已经在 `GetFreeSize` 返回前被日志参数读取。已检查的 JS、Taihe、CJ 和 DFX 调用位置大多会值初始化输出并在错误时停止使用结果，这降低了外部接口路径的影响，但不能消除周期监控中的当前生产调用链。

## 影响

- 在没有自动变量初始化保护的构建中，把未初始化的 `int64_t` 作为日志参数读取属于 C++ 未定义行为，并可能把无意义的栈值写入系统日志。
- 若构建配置把普通局部变量初始化为零，该路径通常会记录 `freeSize=0`；未定义值风险会减小，但失败操作仍被额外记录为“success”，干扰存储故障诊断。
- `GetFreeSize` 的输出约定不完整。新的直接调用方如果忽略错误码或复用旧值，可能把失败前的值误当作本次查询结果。

当前在树调用方会检查错误码，未发现错误结果继续进入清理阈值计算的路径。本次证据不支持稳定敏感信息泄露、权限提升或进程拒绝服务结论。

## 触发条件

1. 产品启用存储统计管理特性并启动 `StorageMonitorService`。
2. 周期监控调用 `GetFreeSize`，传入尚未初始化的 `freeSize` 局部变量。
3. `statvfs("/data")` 因文件系统状态、权限或底层 I/O 异常返回失败。
4. `GetSizeOfPath` 返回 `E_STATVFS` 且不写输出引用。
5. `GetFreeSize` 继续执行无条件日志并读取 `freeSize`。

`/data` 在正常运行的标准系统中通常存在，因此该错误路径预期只在存储或系统状态异常时进入。外部调用者对失败条件的可控性尚未确认。

## 修复建议

建议在 `GetFreeSize` 入口建立明确的失败输出值，并在查询失败后立即返回。成功日志只应位于成功分支：

```cpp
int32_t StorageTotalStatusService::GetFreeSize(int64_t &freeSize)
{
    freeSize = 0;
    int32_t ret = GetSizeOfPath(PATH_DATA, static_cast<int32_t>(StorageStatType::FREE), freeSize);
    if (ret != E_OK) {
        LOGE("GetFreeSize failed, ret=%{public}d", ret);
        StorageRadar::ReportGetStorageStatus("GetFreeSize", DEFAULT_USERID, ret, "setting");
        return ret;
    }
    LOGI("StorageTotalStatusService::GetFreeSize success, (/data)freeSize=%{public}lld",
        static_cast<long long>(freeSize));
    return E_OK;
}
```

`MonitorAndManageStorage` 中的标量局部变量也应使用 `{0}` 或 `= 0` 初始化，作为调用方防御。其他带输出引用的 `GetSizeOfPath` 包装函数应采用相同约定：失败时不读取输出，或在入口设置文档化的安全默认值。

## 参考

- [CWE-457: Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
- [GetFreeSize 与 GetSizeOfPath（当前基线）](https://gitcode.com/openharmony/filemanagement_storage_service/blob/38f4e18628953fedc48e2664b38c57009bf4446f/services/storage_manager/storage/src/storage_total_status_service.cpp#L82-L195)
- [周期监控调用位置（当前基线）](https://gitcode.com/openharmony/filemanagement_storage_service/blob/38f4e18628953fedc48e2664b38c57009bf4446f/services/storage_manager/storage/src/storage_monitor_service.cpp#L149-L163)
- [失败后无条件日志引入提交](https://gitcode.com/openharmony/filemanagement_storage_service/commit/487292f06c6c35cf6f17a56fc8222c7fd0524711)
- [周期监控路径引入提交](https://gitcode.com/openharmony/filemanagement_storage_service/commit/1ca2fa76e6b8c1517ab71c164333c4ad000a47d9)
