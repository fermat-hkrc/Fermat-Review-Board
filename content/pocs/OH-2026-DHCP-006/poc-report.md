# 验证报告：公开 kits/c 头文件不能由 C11 包含

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 公开入口 | `interfaces/kits/c/dhcp_c_api.h` |
| 编译语言 | C11 |
| driver 内容 | 仅 `#include "dhcp_c_api.h"` 与空 `main` |
| 判定标准 | 公共 C API 头应可由标准 C11 翻译单元解析 |

## 2. 验证方法

`build.sh` 使用：

```text
clang -std=c11 -Wall -Werror -fsyntax-only
```

编译仅包含公开头文件的 `driver.c`。`-fsyntax-only` 保证测试停留在声明解析阶段，不涉及链接、运行、业务代码或任何平台替身。

## 3. 完整触发链

```text
driver.c
  → #include "dhcp_c_api.h"
    → 包含 dhcp_result_event.h
      → 解析 bool isOptSuc;                   // C 中未声明 bool
    → 继续解析 dhcp_c_api.h
      → const RouterConfig &config             // C++ 引用
      → const IpCacheInfo &ipCacheInfo         // C++ 引用
      → bool bIpv4 = true                      // 默认参数
  → C11 前端拒绝该翻译单元
```

## 4. 实际结果

```text
dhcp_result_event.h:61:5: error: unknown type name 'bool'
dhcp_c_api.h:48:54: error: expected ')'
dhcp_c_api.h:56:68: error: expected ')'
dhcp_c_api.h:65:54: error: unknown type name 'bool'
```

| 类别 | 期望 | 实际 |
| --- | --- | --- |
| C boolean 声明 | 可见 `bool` 定义 | `bool` 未声明 |
| 参数传递 | C 指针或值语义 | 出现 C++ 引用 `&` |
| 可选参数 | C 调用点显式传参 | 出现 C++ 默认参数 |

## 5. 结论与边界

该验证明确证明 C11 兼容性失败。它不说明 C++ 编译器无法使用这些声明；C++ 可以理解引用和默认参数，问题在于这些声明位于名为 `kits/c` 的公开接口中并阻止 C 调用方构建。

## 6. 修复后的回归判定

- 仅包含头文件的 C11 driver 必须通过；
- 使用 `StartDhcpClient`、`DealWifiDhcpCache` 和 `StopDhcpClient` 的 C11 driver 必须通过编译；
- C API 层应使用 `<stdbool.h>`、指针参数和显式布尔参数；
- C++ 包装接口可以单独测试，但不得污染 C ABI 声明。

## 7. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.c` | 最小正常 C 消费者 |
| `build.sh` | C11 语法检查与诊断筛选 |
| `output.txt` | 原始关键编译诊断 |
