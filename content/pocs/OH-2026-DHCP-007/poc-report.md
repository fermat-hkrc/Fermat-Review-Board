# 验证报告：Lite DHCP 生产翻译单元无法编译

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 配置 | `OHOS_ARCH_LITE` |
| 验证对象 | 三个生产 `.cpp` 翻译单元 |
| 方法 | 对每个单元独立执行 C++17 语法检查 |
| 判定标准 | Lite 生产源应能在其声明匹配的头文件环境中完成编译 |

这个问题在编译阶段停止，因此不存在可替代的“运行时触发程序”。`compile-matrix.md` 明确列出每个翻译单元、配置和诊断判定。

## 2. 编译环境与最小适配边界

构建定义 `OHOS_ARCH_LITE` 并添加目标仓库的 Lite 头文件搜索路径。少量兼容头只补足 OpenHarmony 平台类型，使 C++ 前端能够到达被测生产代码；它们不会定义 `clientProxy`、`WifiScanProxy`、`mRemoteDied` 或 `state` 等被测标识符。

每个文件独立检查，避免第一个文件的错误阻止其余错误呈现。

## 3. 完整触发链

```text
Lite 产品构建
  → 编译器定义 OHOS_ARCH_LITE
  → 进入 DHCP 的 Lite 条件分支
    ├─ dhcp_server_impl.cpp
    │   → serverProxy 已声明，但 clientProxy 被引用
    ├─ dhcp_server_callback_stub_lite.cpp
    │   → 构造函数、IpcIo 指针表达式和 state 名称不匹配
    └─ dhcp_server_proxy_lite.cpp
        → WifiScanProxy / mRemoteDied 不在 Lite 声明中
  → 语义编译拒绝翻译单元
```

## 4. 实际结果

```text
dhcp_server_impl: rejected by compiler
dhcp_server_callback_stub_lite: rejected by compiler
dhcp_server_proxy_lite: rejected by compiler
dhcp_server_impl.cpp:60:9: error: use of undeclared identifier 'clientProxy'
dhcp_server_callback_stub_lite.cpp:135:92: error: no member named 'GetRawDataSize' in 'IpcIo'
dhcp_server_callback_stub_lite.cpp:138:27: error: use of undeclared identifier 'state'
dhcp_server_proxy_lite.cpp:153:6: error: use of undeclared identifier 'WifiScanProxy'
dhcp_server_proxy_lite.cpp:207:79: error: use of undeclared identifier 'mRemoteDied'
```

| 翻译单元 | 期望 | 实际 |
| --- | --- | --- |
| `dhcp_server_impl.cpp` | Lite 初始化代码通过 | 因 `clientProxy` 被拒绝 |
| `dhcp_server_callback_stub_lite.cpp` | Lite callback 代码通过 | 因指针访问与 `state` 被拒绝 |
| `dhcp_server_proxy_lite.cpp` | Lite proxy 代码通过 | 因类名与成员名被拒绝 |

## 5. 结论与边界

该验证确认 Lite 条件编译分支不可构建。它不依赖静态结果猜测，也不声称标准构建同样失败；未定义 `OHOS_ARCH_LITE` 时，编译器不会进入这些分支。

## 6. 修复后的回归判定

- 三个文件在 `OHOS_ARCH_LITE` 下均通过独立语法检查；
- 完整 Lite 目标完成编译；
- 修复后执行 `DhcpServerImpl::Init`、status callback 与 remote-death 路径的单元测试；
- 标准配置仍应保持原有构建通过。

## 7. 文件说明

| 文件 | 用途 |
| --- | --- |
| `build.sh` | Lite 宏、头文件搜索路径和逐单元编译检查 |
| `compile-matrix.md` | 每个生产单元的目标诊断与边界说明 |
| `output.txt` | 已观察到的关键编译诊断 |
