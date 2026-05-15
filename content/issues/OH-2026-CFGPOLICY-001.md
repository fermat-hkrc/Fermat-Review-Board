---
id: OH-2026-CFGPOLICY-001
date: "2026-05-08"
repo: customization_config_policy
repo_url: https://gitcode.com/openharmony/customization_config_policy
title: "CJ_GetCfgDirList / CJ_GetCfgFiles Use-After-Free"
cwe: CWE-416
cwe_name: Use After Free
status: SUBMITTED
issue_url: https://gitcode.com/openharmony/customization_config_policy/issues/162
author: Zirui
---

## 漏洞概述

`CJ_GetCfgDirList` 和 `CJ_GetCfgFiles` 将 `CfgDir->paths[]` / `CfgFiles->paths[]` 的原始 `char*` 指针存入 `vector`，然后调用 `FreeCfgDirList` / `FreeCfgFiles` 释放底层内存。随后 `MallocCStringArr` 对 vector 中的悬空指针执行 `strlen` 和 `strcpy_s`，触发 use-after-free。

## 漏洞详情

### 问题代码

**文件**: `interfaces/kits/cj/src/config_policy_ffi.cpp`

```cpp
// CJ_GetCfgDirList — Lines 57-78
RetDataCStringArr CJ_GetCfgDirList()
{
    RetDataCStringArr ret = { .code = SUCCESS_CODE, .size = 0, .data = { .head = nullptr, .size = 0 } };
    CfgDir *cfgDir = GetCfgDirList();
    std::vector<const char*> dirList;
    if (cfgDir != nullptr) {
        for (size_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; i++) {
            if (cfgDir->paths[i] != nullptr) {
                dirList.push_back(cfgDir->paths[i]);  // ⚠️ 存入原始指针，无拷贝
            }
        }
        FreeCfgDirList(cfgDir);  // ⚠️ 释放 realPolicyValue → 所有 paths[] 指针失效
    }
    ret.data.head = MallocCStringArr(dirList);  // ⚠️ strlen/strcpy_s 读取已释放内存
    ret.data.size = static_cast<int64_t>(dirList.size());
    return ret;
}
```

### 调用链

```
CJ_GetCfgDirList
  → GetCfgDirList()              // 分配 CfgDir，paths[] 指向 realPolicyValue 内部
  → dirList.push_back(paths[i])  // 存入原始指针
  → FreeCfgDirList(cfgDir)       // 释放 realPolicyValue → paths[] 全部悬空
  → MallocCStringArr(dirList)    // 对悬空指针调用 strlen + strcpy_s → UAF
```

### 根因

`GetCfgDirList` 返回的 `CfgDir` 结构中，所有 `paths[i]` 都是指向同一个 `realPolicyValue` 字符串内部的指针（通过 `strchr` 分割）。`FreeCfgDirList` 释放 `realPolicyValue`，所有 `paths[]` 同时失效。

同样，`CJ_GetCfgFiles` 中 `CfgFiles->paths[i]` 是 `strdup` 返回的独立字符串，`FreeCfgFiles` 逐个 `free`，效果一样。

### 同族函数

| 函数 | 行号 | 状态 |
|---|---|---|
| `CJ_GetCfgDirList` | 57 | **UAF** |
| `CJ_GetCfgFiles` | 80 | **UAF** |

## 影响分析

- **每次调用必定触发** — 不是竞态或边界条件，是正常执行路径上的 bug
- **读取已释放内存** — `strlen` 和 `strcpy_s` 读取悬空指针
- **可能结果**：
  - 读到旧数据（内存未被覆盖时）→ 看似正常但不可靠
  - 读到垃圾数据 → 返回乱码路径
  - 内存已被重新分配 → 崩溃 (SIGSEGV)
  - 堆损坏 → 后续操作崩溃

## 修复建议

```cpp
RetDataCStringArr CJ_GetCfgDirList()
{
    RetDataCStringArr ret = { .code = SUCCESS_CODE, .size = 0, .data = { .head = nullptr, .size = 0 } };
    CfgDir *cfgDir = GetCfgDirList();
-   std::vector<const char*> dirList;
+   std::vector<std::string> dirList;  // 改用 string 拷贝
    if (cfgDir != nullptr) {
        for (size_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; i++) {
            if (cfgDir->paths[i] != nullptr) {
-               dirList.push_back(cfgDir->paths[i]);
+               dirList.push_back(std::string(cfgDir->paths[i]));
            }
        }
        FreeCfgDirList(cfgDir);  // 现在安全：string 已拷贝数据
    }
-   ret.data.head = MallocCStringArr(dirList);
+   // MallocCStringArr 也需要适配 std::vector<std::string>
+   ret.data.head = MallocCStringArrFromStrings(dirList);
    ret.data.size = static_cast<int64_t>(dirList.size());
    return ret;
}
```

或者更简单的修法：在 `FreeCfgDirList` 之前完成所有 `strdup`：

```cpp
    if (cfgDir != nullptr) {
        for (size_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; i++) {
            if (cfgDir->paths[i] != nullptr) {
                dirList.push_back(strdup(cfgDir->paths[i]));  // 拷贝
            }
        }
        FreeCfgDirList(cfgDir);  // 安全
    }
```

**注意**：`CJ_GetCfgFiles` 需要做同样修复。

## 涉及文件

- `interfaces/kits/cj/src/config_policy_ffi.cpp` (lines 57-78, 80-103)
- `interfaces/kits/cj/src/config_policy_ffi.h`

## 参考

- CWE-416: Use After Free
- CWE-825: Expired Pointer Dereference
