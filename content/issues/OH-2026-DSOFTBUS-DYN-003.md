---
id: OH-2026-DSOFTBUS-DYN-003
date: "2026-04-29"
repo: communication_dsoftbus
repo_url: https://gitcode.com/openharmony/communication_dsoftbus
title: "GetInfoFromSplitKey 中 atol() 返回值未验证直接用于 strcpy_s"
cwe: CWE-20
cwe_name: Improper Input Validation
status: SUBMITTED
language: "C++"
issue_url: https://gitcode.com/openharmony/communication_dsoftbus/issues/9228
author: Zirui
---

下列还有几个类似问题，也请您可以看看：

# GetInfoFromSplitKey 中 atol() 返回值未验证直接用于 strcpy_s

**CWE**: CWE-20 (Improper Input Validation)

## 问题描述

```cpp
// lnn_data_cloud_sync.c:402
static int32_t GetInfoFromSplitKey(/* ... */)
{
    // ...
    int64_t accountId = atol(splitKey[0]);   // line 407: atol() 对非数字输入返回 0，对超范围输入行为未定义
    strcpy_s(info->accountId, ...);           // line 408: splitKey 内容直接拷贝，无长度验证
    strcpy_s(info->deviceUdid, ...);          // line 412: 同上
}
```

`atol()` 对非数字字符串返回 0，对超出 `long` 范围的输入行为未定义（C 标准）。`splitKey` 数组元素直接传入 `strcpy_s`，若源字符串长度超过目标缓冲区，`strcpy_s` 会截断并返回错误码，但该返回值未被检查。

### 调用链

Pipeline 分析显示此函数被以下路径调用：
- `HandleDBAddChangeInternal` → `GetInfoFromSplitKey`
- `HandleDBUpdateChangeInternal` → `GetInfoFromSplitKey`
- `HandleDBDeleteChangeInternal` → `GetInfoFromSplitKey`

这些函数处理数据库变更事件，`splitKey` 来源于数据库 key 的分割结果。若数据库内容被篡改或格式异常，可触发此问题。

## 影响

- `atol()` 对异常输入的未定义行为可能导致逻辑错误
- `strcpy_s` 返回值未检查，截断后的数据可能导致后续操作使用不完整的标识符

## 建议修复

```c
// 将 atol 替换为 strtol 并检查转换结果
char *endptr;
errno = 0;
long accountId = strtol(splitKey[0], &endptr, 10);
if (errno != 0 || *endptr != '\0') {
    LNN_LOGE("invalid accountId format");
    return SOFTBUS_INVALID_PARAM;
}

// 检查 strcpy_s 返回值
if (strcpy_s(info->accountId, sizeof(info->accountId), splitKey[0]) != EOK) {
    LNN_LOGE("accountId too long");
    return SOFTBUS_INVALID_PARAM;
}
```
