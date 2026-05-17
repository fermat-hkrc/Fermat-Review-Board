---
id: OH-2026-PERMLITE-005
date: "2026-05-17"
repo: security_permission_lite
repo_url: https://gitcode.com/openharmony/security_permission_lite
title: "ParsePermissions 服务端整数溢出导致堆破坏"
severity: HIGH
cwe: CWE-190
cwe_name: Integer Overflow or Wraparound
status: PENDING
component: pms_impl
file_paths:
  - services/pms/src/pms_impl.c:183
author: Zirui
has_poc: true
---

## 漏洞概述

服务端 `pms_impl.c` 的 `ParsePermissions()` 在解析权限 JSON 数组时，使用 `int allocSize = sizeof(PermissionSaved) * pSize` 计算分配大小。`pSize` 来自 JSON 数组长度，无上限检查。当 pSize 超过 10,737,418 时，乘法结果溢出 `int` 范围，导致后续 `HalMalloc` 分配远小于预期的缓冲区，`strcpy_s` 写入时发生堆越界。

客户端 `perm_client.c` 的同名函数有 `PERMISSION_NUM_MAX=1000` 保护。服务端版本**没有此检查**。

## 问题代码

```c
// pms_impl.c:175-190
static PermissionSaved *ParsePermissions(const char *jsonStr, int *pNum)
{
    cJSON *root = cJSON_Parse(jsonStr);
    // ...
    int pSize = cJSON_GetArraySize(permissions);
    // NO bounds check on pSize — client version has: if (pSize > 1000) return ERROR;
    int allocSize = sizeof(PermissionSaved) * pSize;  // ← CWE-190: integer overflow
    PermissionSaved *perms = (PermissionSaved *)HalMalloc(allocSize);
    // ...
    for (int i = 0; i < pSize; i++) {
        // cJSON_GetArrayItem → ParseNewPermissionsItem → strcpy_s into perms[i]
        // When allocSize < pSize * sizeof(PermissionSaved), this writes past buffer
    }
}
```

对比客户端保护：

```c
// perm_client.c:214
if (pSize > PERMISSION_NUM_MAX) {  // PERMISSION_NUM_MAX = 1000
    return PERM_ERRORCODE_INVALID_PARAMS;
}
```

## 触发条件

1. 攻击者能向权限存储路径写入文件（通过另一个文件写入漏洞或物理访问设备）
2. 构造一个包含 >10,737,418 个数组项的 JSON 权限文件（约 1 GB）
3. 触发 `QueryPermission()` 调用（正常的权限查询流程）

触发路径：

```
攻击者写入恶意权限文件 → QueryPermission("target_pkg")
  → QueryPermissionString → ReadString → ParsePermissions (pms_impl.c)
  → cJSON_GetArraySize 返回超大值 → sizeof(PermissionSaved) * pSize 溢出
  → HalMalloc 分配小缓冲区 → strcpy_s 循环写入 → 堆越界写入
```

## 影响

- **堆缓冲区溢出**：溢出的乘法使分配远小于实际需要，后续逐项拷贝造成堆越界写入
- **攻击前提**：需要能向 `/data/misc/permission/` 目录写入文件（通常需要 root 或另一个文件写入漏洞）
- **影响范围**：所有使用服务端 ParsePermissions 的 OpenHarmony 设备

## PoC 验证

使用 OHOS GN 构建系统编译真实源码为静态库（Target-Compile 方法）：

```
pms_impl.a ← pms_impl.c + perm_operate.c（服务端真实代码）
cjson_static.a ← cJSON.c
libsec_static.a ← memset_s 等安全函数
```

测试驱动链接上述 .a 库，调用 `QueryPermission()`：

- 正常路径（3 个权限项）：`ret=0, permNum=3` — 通过
- 整数溢出触发：`200 × 10,737,419 = -2,147,483,496 (int overflow)`

ASan 输出：

```
ERROR: AddressSanitizer: requested allocation size 0xffffffff80000098
exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 in malloc
    #1 in main
SUMMARY: AddressSanitizer: allocation-size-too-big
```

完整 PoC 代码和构建脚本见 `content/pocs/OH-2026-PERMLITE-005/`。

## 修复建议

```diff
 // pms_impl.c:175-190
 static PermissionSaved *ParsePermissions(const char *jsonStr, int *pNum)
 {
     cJSON *root = cJSON_Parse(jsonStr);
     // ...
     int pSize = cJSON_GetArraySize(permissions);
+    if (pSize <= 0 || pSize > PERMISSION_NUM_MAX) {
+        cJSON_Delete(root);
+        return NULL;
+    }
     int allocSize = sizeof(PermissionSaved) * pSize;
     // ...
```

添加与客户端相同的 `PERMISSION_NUM_MAX=1000` 上限检查，防止整数溢出和过度分配。
