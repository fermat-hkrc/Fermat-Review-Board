---
id: OH-2026-STORAGE-001
date: "2026-06-15"
repo: storage_service
repo_url: https://gitcode.com/openharmony/filemanagement_storage_service
title: "VolumeExternal::Unmarshalling 反序列化失败时空指针解引用导致服务崩溃"
severity: MEDIUM
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: PENDING
language: "C++"
component: storage_manager
file_paths:
  - services/storage_manager/src/volume/volume_external.cpp:139
author: Zirui
has_poc: true
---

## 漏洞概述

`VolumeExternal::Unmarshalling()` 调用 `VolumeCore::Unmarshalling(parcel)` 获取基类对象指针后，未检查返回值即直接解引用传入 `VolumeExternal` 构造函数。当 Parcel 数据格式错误导致 `VolumeCore::Unmarshalling` 返回 `nullptr` 时，解引用空指针触发 SIGSEGV，导致 storage_manager_service 崩溃。

## 根本原因

**位置**: `services/storage_manager/src/volume/volume_external.cpp:139`

```cpp
VolumeExternal *VolumeExternal::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<VolumeCore> volumeCorePtr(VolumeCore::Unmarshalling(parcel));
    VolumeExternal* obj = new (std::nothrow) VolumeExternal(*volumeCorePtr);
    //                                                      ^^^^^^^^^^^^^^
    //   volumeCorePtr 可能为 nullptr → 解引用触发 SIGSEGV
    if (!obj) {
        return nullptr;
    }
    obj->flags_ = parcel.ReadInt32();
    obj->fsType_ = parcel.ReadInt32();
    obj->fsUuid_ = parcel.ReadString();
    obj->path_ = parcel.ReadString();
    obj->description_ = parcel.ReadString();
    return obj;
}
```

`VolumeCore::Unmarshalling` 需要从 Parcel 中顺序读取 8 个字段（String id, Int32 type, String diskId, Int32 state, Bool errorFlag, String fsType, String extraInfo, Uint32 partitionNum），任何字段读取失败都会导致返回 `nullptr`。

**问题**:
1. `VolumeCore::Unmarshalling` 在 Parcel 数据不完整时返回 `nullptr`
2. 代码直接 `*volumeCorePtr` 解引用，无 null 检查
3. 攻击者可构造截断的 Parcel 数据触发此路径

## 影响

- **服务崩溃 (DoS)**：storage_manager_service 进程异常终止
- **存储功能不可用**：崩溃后无法进行卷挂载/卸载、格式化等操作
- **持续 DoS**：反复发送畸形 IPC 消息可阻止服务恢复

## 触发条件

1. 攻击者向 storage_manager_service 发送 IPC 请求
2. 请求触发 `VolumeExternal::Unmarshalling` 对客户端提供的 Parcel 进行反序列化
3. Parcel 中 VolumeCore 部分数据截断或格式错误
4. `VolumeCore::Unmarshalling` 返回 nullptr
5. 空指针解引用 → SIGSEGV

## 修复建议

```diff
 VolumeExternal *VolumeExternal::Unmarshalling(Parcel &parcel)
 {
     std::unique_ptr<VolumeCore> volumeCorePtr(VolumeCore::Unmarshalling(parcel));
+    if (!volumeCorePtr) {
+        return nullptr;
+    }
     VolumeExternal* obj = new (std::nothrow) VolumeExternal(*volumeCorePtr);
```

## 参考

- [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
