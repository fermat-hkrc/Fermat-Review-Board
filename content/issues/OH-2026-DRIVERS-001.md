---
id: OH-2026-DRIVERS-001
date: "2026-05-07"
repo: drivers_interface
repo_url: https://gitcode.com/openharmony/drivers_interface
title: "Camera HAL ReadMetadata 系列函数空指针解引用"
severity: MEDIUM
cwe: CWE-476
cwe_name: NULL Pointer Dereference
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/drivers_interface/issues/1235
author: fermat-hkrc
---

## 漏洞概述

在 OpenHarmony 的 Camera HAL 层，`metadata_utils.cpp` 中的 6 个 `ReadMetadata*` 函数在调用 `MessageParcel::ReadUnpadBuffer` 后，均未检查返回值是否为空指针。当 IPC 消息中的 camera metadata 数据不完整（声明的 count 大于实际数据量）时，`ReadUnpadBuffer` 返回 `nullptr`，该空指针直接传入 `memcpy_s` 导致进程崩溃。

## 漏洞详情

### 问题代码

**文件**: `camera/metadata/src/metadata_utils.cpp`

以 `ReadMetadataUInt8` 为例（其余 5 个函数完全相同的模式）：

```cpp
// Lines 591-599
static void ReadMetadataUInt8(camera_metadata_item_t &entry, MessageParcel &data)
{
    entry.data.u8 = new(std::nothrow) uint8_t[entry.count];
    if (entry.data.u8 != nullptr) {
        size_t dataSize = entry.count * sizeof(uint8_t);
        const uint8_t* ptr = data.ReadUnpadBuffer(dataSize);
        // ⚠️ ptr 可能为 nullptr，但未检查！
        memcpy_s(entry.data.u8, dataSize, ptr, dataSize);  // ← ptr=nullptr 时 SIGSEGV
    }
}
```

### 受影响的全部函数

| 函数 | 行号 | 数据类型 | 单元素大小 |
|---|---|---|---|
| `ReadMetadataUInt8` | 591 | uint8_t | 1 |
| `ReadMetadataInt32` | 601 | int32_t | 4 |
| `ReadMetadataUInt32` | 611 | uint32_t | 4 |
| `ReadMetadataFloat` | 621 | float | 4 |
| `ReadMetadataInt64` | 631 | int64_t | 8 |
| `ReadMetadataDouble` | 641 | double | 8 |

所有函数的问题模式完全一致：
```cpp
const uint8_t* ptr = data.ReadUnpadBuffer(dataSize);
// 无 NULL 检查
memcpy_s(entry.data.XXX, dataSize, ptr, dataSize);
```

### 调用链

```cpp
// Lines 670-700
bool MetadataUtils::ReadMetadata(camera_metadata_item_t &entry, MessageParcel &data)
{
    if (entry.count > MAX_SUPPORTED_ITEMS) {
        entry.count = MAX_SUPPORTED_ITEMS;  // 上界限制
    }
    switch (entry.data_type) {
        case META_TYPE_BYTE:    ReadMetadataUInt8(entry, data);   break;
        case META_TYPE_INT32:   ReadMetadataInt32(entry, data);   break;
        case META_TYPE_UINT32:  ReadMetadataUInt32(entry, data);  break;
        case META_TYPE_FLOAT:   ReadMetadataFloat(entry, data);   break;
        case META_TYPE_INT64:   ReadMetadataInt64(entry, data);   break;
        case META_TYPE_DOUBLE:  ReadMetadataDouble(entry, data);  break;
        case META_TYPE_RATIONAL: ReadMetadataRational(entry, data); break;
    }
    return true;
}

// Lines 318-359
void MetadataUtils::ReadCameraMetadata(MessageParcel &data, 
    common_metadata_header_t *meta, uint32_t tagCount)
{
    for (uint32_t i = 0; i < tagCount; i++) {
        camera_metadata_item_t item;
        item.index = data.ReadUint32();
        item.item = data.ReadUint32();
        item.data_type = data.ReadUint32();
        item.count = data.ReadUint32();    // ← 攻击者可控
        if (item.count > MAX_SUPPORTED_ITEMS) {
            item.count = MAX_SUPPORTED_ITEMS;
        }
        ReadMetadata(item, data);           // ← 进入漏洞函数
    }
}
```

**完整入口**：
```
CameraMetadata::Unmarshalling (camera_metadata_info.cpp)
  → MetadataUtils::ReadCameraMetadata (metadata_utils.cpp:318)
    → MetadataUtils::ReadMetadata (metadata_utils.cpp:670)
      → ReadMetadataUInt8/Int32/... (metadata_utils.cpp:591+)  ← 崩溃点
```

## 攻击场景

### 场景：恶意 Camera Metadata IPC 消息

```
攻击者 / 异常 Camera HAL                  Camera 服务进程
    |                                         |
    | 1. 构造恶意 Camera Metadata              |
    |    tagCount = 1                          |
    |    item[0].data_type = META_TYPE_INT32   |
    |    item[0].count = 100                   |
    |    实际写入数据 = 仅 4 字节（1 个 int32）  |
    |                                         |
    | 2. 通过 IPC 发送                         |
    |---------------------------------------> |
    |                                         | 3. ReadCameraMetadata 被调用
    |                                         |    item.count = 100
    |                                         |    → ReadMetadataInt32(item, data)
    |                                         |    → dataSize = 100 * 4 = 400 字节
    |                                         |    → new int32_t[100] → 成功
    |                                         |    → ReadUnpadBuffer(400) → nullptr
    |                                         |      （Parcel 中只剩 4 字节）
    |                                         |    → memcpy_s(dst, 400, nullptr, 400)
    |                                         |                        ^^^^^^^
    |                                         |                        SIGSEGV
```

### 自然触发场景

1. **Camera HAL 返回不完整数据**：硬件异常导致 metadata 采集中断
2. **Parcel 数据截断**：跨进程传输中内存不足导致部分数据丢失
3. **多 tag 消耗**：一个 Metadata 有多个 tag，前面的 tag 消耗了大部分 Parcel 空间，后面的 tag 数据不足

## 触发条件

1. 目标进程接收包含 Camera Metadata 的 IPC 消息
2. 消息中某个 metadata item 的 `count` 声明的元素数量大于 Parcel 中实际剩余数据量
3. `ReadUnpadBuffer` 因数据不足返回 nullptr

**注意**：`count` 受 `MAX_SUPPORTED_ITEMS` 上限限制（不会触发巨量分配），但 Parcel 中的实际数据量是由发送方控制的，可以构造 count 合法但数据不足的情况。

## 影响分析

- **Camera 服务崩溃**：处理畸形 metadata 时 SIGSEGV，Camera 功能不可用
- **应用崩溃**：使用 Camera API 的应用进程在反序列化 metadata 时崩溃
- **影响范围**：所有使用 Camera HAL 的进程（camera_host, camera_service 等）
- **攻击面**：Camera HAL IPC 通信（通常限于系统级 HAL 进程间）

## 修复建议

对所有 `ReadMetadata*` 函数统一添加 NULL 检查：

```cpp
static void ReadMetadataUInt8(camera_metadata_item_t &entry, MessageParcel &data)
{
    entry.data.u8 = new(std::nothrow) uint8_t[entry.count];
    if (entry.data.u8 != nullptr) {
        size_t dataSize = entry.count * sizeof(uint8_t);
        const uint8_t* ptr = data.ReadUnpadBuffer(dataSize);
+       if (ptr == nullptr) {
+           METADATA_ERR_LOG("ReadUnpadBuffer failed for UInt8, count=%{public}zu", entry.count);
+           delete[] entry.data.u8;
+           entry.data.u8 = nullptr;
+           return;
+       }
        memcpy_s(entry.data.u8, dataSize, ptr, dataSize);
    }
}
```

对 `ReadMetadataInt32`, `ReadMetadataUInt32`, `ReadMetadataFloat`, `ReadMetadataInt64`, `ReadMetadataDouble` 做同样修改。

## 涉及文件

- `camera/metadata/src/metadata_utils.cpp` (lines 591, 601, 611, 621, 631, 641)
- `camera/metadata/include/metadata_utils.h`

