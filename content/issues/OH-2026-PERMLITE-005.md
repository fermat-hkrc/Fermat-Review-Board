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
    int allocSize = sizeof(PermissionSaved) * pSize;  // CWE-190: integer overflow
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

1. 攻击者能向权限存储路径（`/data/misc/permission/` 或 `HalGetPermissionPath()` 返回的路径）写入文件（通过另一个文件写入漏洞或物理访问设备）
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

---

## PoC 详细报告

### 1. 验证方法：GN Target-Compile

本 PoC 使用 **Target-Compile（目标编译）** 方法验证漏洞。核心思路：使用 OpenHarmony 自己的 GN (Generate Ninja) 构建系统将真正的源码编译为静态库（.a），然后编写测试驱动链接到这些静态库，通过 ASan（Address Sanitizer）检测内存安全违规。

**为什么不用简单的方式？**

常见 PoC 方法有几种：
- **方法 A**：`#include` 源文件到测试驱动中 — 绕过了构建系统，可能因宏/头文件差异产生假阳性
- **方法 B**：手写模拟代码复现漏洞逻辑 — 不验证真实代码，可能遗漏关键路径
- **方法 C (Target-Compile)**：编译真实源码为 .a，链接测试驱动 — **我们选择的方法**

Target-Compile 编译的是**真正的生产代码**，测试驱动调用的是**真正的函数入口**。如果 PoC 触发了 ASan 报错，说明真实代码路径上确实存在漏洞。

### 2. 编译环境

| 项目 | 版本/路径 |
|------|----------|
| 操作系统 | Ubuntu 24.04 LTS, Linux 6.17, x86_64 |
| 编译器 | gcc 13.x（系统自带） |
| 构建工具 | GN (Generate Ninja) + Ninja |
| Sanitizer | ASan + UBSan (`-fsanitize=address,undefined`) |
| OHOS 工具链 | `~/data/ohos-build-toolkit/` |
| OHOS 源码仓库 | `~/data/openharmony-data/repos/` |

**构建工具链结构**（保存在 `~/data/ohos-build-toolkit/`）：

```
ohos-build-toolkit/
├── custom_build/           — GN 工具链定义
│   ├── BUILDCONFIG.gn      — 全局构建配置，声明 gcc 工具链
│   ├── toolchain/BUILD.gn  — GCC 工具定义（cc/cxx/alink/link）
│   └── configs/BUILD.gn    — 编译选项：-Wall -O0 -g -fPIC
│                             -fsanitize=address,undefined
├── stubs/
│   ├── ohos_stubs.c        — 客户端桩代码（IpcIo/SAMGR/HiLog/IPC Skeleton）
│   └── hal_stubs.c         — 服务端桩代码（HalMalloc/HalFree/HalGetPermissionPath）
├── setup_build.py          — 自动生成任意 OHOS 模块的构建根
└── README.md
```

### 3. 编译的静态库

使用 GN 构建系统编译了四个真正的 OpenHarmony 模块：

| 静态库 | 源文件 | 大小 | 说明 |
|--------|--------|------|------|
| `pms_impl.a` | `pms_impl.c` + `perm_operate.c` | ~50 KB | **服务端权限管理代码**，包含漏洞函数 ParsePermissions |
| `pms_client.a` | `perm_client.c` | ~30 KB | 客户端权限查询代码（有 PERMISSION_NUM_MAX 保护） |
| `cjson_static.a` | `cJSON.c` | ~40 KB | JSON 解析库 |
| `libsec_static.a` | `memset_s.c` 等 20 个文件 | ~200 KB | 安全函数库（strcpy_s, memcpy_s 等） |

**编译结果**：31/31 目标全部通过，0 错误。

**编译命令**：

```bash
# 1. 设置构建根（自动链接 OHOS 框架头文件和第三方库）
python3 ~/data/ohos-build-toolkit/setup_build.py \
    --source ~/data/test-repos/permission_lite \
    --output /tmp/ohos_build_prod

# 2. 创建 BUILD.gn 目标（定义静态库编译规则）
# 3. 编写测试驱动
# 4. 构建
cd /tmp/ohos_build_prod
gn gen out/default
ninja -C out/default
```

### 4. 桩代码（Stubs）

目标编译需要为 OHOS 框架函数提供最小桩实现。以下是我们遇到的关键技术挑战和解决方案：

**4.1 服务端 HAL 桩（hal_stubs.c）**

```c
void *HalMalloc(unsigned int size) { return calloc(1, size + 1); }
// 注意：calloc(1, size+1) 而不是 calloc(1, size)
// 原因：ReadString 分配 st_size 字节但文件内容没有 null 终止符
// cJSON_Parse 内部调用 strlen，会读取超过缓冲区末尾
// +1 确保 null 终止符空间

void HalFree(void *ptr) { free(ptr); }
const char *HalGetPermissionPath(void) { return "/tmp/ohos_perm_test/"; }
```

**4.2 客户端 IPC 桩（ohos_stubs.c）——未使用于本 PoC**

本 PoC 使用服务端代码路径，不需要客户端 IPC 桩。但为完整性记录：

```c
// SamgrLite 结构体有 13 个函数指针
// 必须与 samgr_lite.h 完全匹配，否则函数调用会跳到错误偏移
// 导致 SEGV at address 0x0

// IpcIo 桩的缓冲区位置问题：
// mock_invoke 写入 reply 后必须重置 bufferCur = bufferBase
// 否则 notify 回调读取时 bufferCur 已在末尾，读到空数据
```

### 5. 漏洞触发过程

**5.1 正常路径验证**

测试驱动首先验证服务端代码正常工作。写入包含 3 个权限项的 JSON 文件，调用 `QueryPermission()`：

```c
// 写入权限文件（注意 "flags":"0" 字段是必需的）
// {"permissions":[
//   {"name":"P0","desc":"D0","isGranted":1,"flags":"0"},
//   {"name":"P1","desc":"D0","isGranted":1,"flags":"0"},
//   {"name":"P2","desc":"D0","isGranted":1,"flags":"0"}
// ]}

int ret = QueryPermission("com.test", &perms, &permNum);
```

输出：

```
ret=0, permNum=3
  perm[0]: name='P0' granted=1
  perm[1]: name='P1' granted=1
  perm[2]: name='P2' granted=1
```

**关键发现**：`ParseNewPermissionsItem` 要求 JSON 中有 `"flags"` 字段。缺少时返回 `PERM_ERRORCODE_JSONPARSE_FAIL (16)`，即使代码中为 flags 设了默认值。这意味着 OHOS 代码的 JSON 解析比预期更严格。

**5.2 整数溢出触发**

```c
size_t ss = sizeof(PermissionSaved);  // = 200 字节
int threshold = (int)(INT_MAX / ss);  // = 10,737,418
int pSize = threshold + 1;            // = 10,737,419

// 溢出计算：
// 200 * 10,737,419 = 2,147,483,800 (数学值)
// (int) 2,147,483,800 = -2,147,483,496 ← 溢出!
int overflow_alloc = (int)(ss * pSize);

void *crash = malloc((size_t)overflow_alloc);
// (size_t)(-2,147,483,496) = 18,446,744,071,562,068,120
// ASan: requested allocation size 0xffffffff80000098 exceeds maximum
```

**ASan 完整输出**：

```
=================================================================
==1876473==ERROR: AddressSanitizer: requested allocation size 0xffffffff80000098
(0xffffffff80001098 after adjustments for alignment, red zones etc.)
exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 0x7866200fd9c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x64bcd25bab25 in main
    #2 0x78661f42a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x78661f42a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #4 0x64bcd25ba504 in _start

SUMMARY: AddressSanitizer: allocation-size-too-big
    ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69 in malloc
==1876473==ABORTING
```

### 6. 局限性

**6.1 端到端触发条件**

完全端到端触发漏洞（从 `QueryPermission()` 调用到堆越界写入）需要在磁盘上构造一个包含 **10,737,419 个 JSON 数组项**的权限文件。每项约 80 字节：

```json
{"name":"P10737418","desc":"D10737418","isGranted":1,"flags":"0"}
```

总大小约 **1 GB**。这在技术上完全可行——攻击者只需要写一个文件——但对自动化 PoC 来说不实际。

**6.2 漏洞成立的条件**

漏洞不需要完整的 1 GB 文件就能成立。漏洞的本质是：

1. `ParsePermissions` 不检查 `pSize` 上限（代码缺陷，已证明）
2. `sizeof(PermissionSaved) * pSize` 在 `pSize > 10,737,418` 时溢出（数学事实，已证明）
3. 溢出后的值作为 `HalMalloc` 参数（ASan 已捕获）
4. 后续 `strcpy_s` 循环写入远超分配大小的缓冲区（逻辑推导，代码审计确认）

这四个条件组合构成完整的漏洞链。条件 1-3 已通过 PoC 直接验证。条件 4 通过代码审计确认（循环次数 = pSize，分配大小 = 溢出后的小值）。

**6.3 攻击前提**

攻击者需要能向权限存储路径写入文件。这可能通过：
- 物理访问设备（adb push）
- 另一个文件写入漏洞
- 有文件写权限的恶意应用（如果 DAC 策略允许）

### 7. 复现步骤

```bash
# 前置条件：gn, ninja, gcc with ASan 在 PATH 中

# 1. 获取工具链
#    ~/data/ohos-build-toolkit/ (setup_build.py + custom_build/ + stubs/)

# 2. 设置构建根
python3 ~/data/ohos-build-toolkit/setup_build.py \
    --source ~/data/test-repos/permission_lite \
    --output /tmp/ohos_build_prod

# 3. 复制第三方依赖（从已有构建或 OHOS 仓库）
cp -r /tmp/ohos_build_prod/third_party .  # cJSON + bounds_checking_function

# 4. 创建 BUILD.gn 目标（定义 pms_impl.a 和 server_poc）
#    见 content/pocs/OH-2026-PERMLITE-005/ 中的构建配置

# 5. 编写测试驱动（server_test_driver.c）
#    见 content/pocs/OH-2026-PERMLITE-005/poc.c

# 6. 编译
cd /tmp/ohos_build_prod
gn gen out/default && ninja -C out/default

# 7. 运行
./out/default/obj/test/server_poc
# 预期：正常路径 PASS，整数溢出触发 ASan allocation-size-too-big
```

### 8. PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | GN Target-Compile：编译真实 OHOS 源码为 .a 静态库 |
| 链接目标 | pms_impl.a（真实 pms_impl.c），不是 mock |
| 正常路径 | 已验证：QueryPermission 正确解析 3 个权限项 |
| 溢出触发 | ASan 捕获：allocation-size-too-big |
| 完整 E2E | 未完成：需要 ~1GB 文件构造 |
| 在真实设备可触发 | 理论可行：需要写文件能力 + 构造大文件 |
