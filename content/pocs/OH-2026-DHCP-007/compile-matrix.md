# 编译检查矩阵

该条没有运行时 driver，因为源文件在进入 Lite 运行路径前已经无法通过编译。`build.sh` 对每个生产翻译单元独立执行语法检查，以避免一个文件的第一处错误掩盖其他文件的证据。

| 生产翻译单元 | 条件 | 需要观察的诊断 | 判定 |
| --- | --- | --- | --- |
| `frameworks/native/src/dhcp_server_impl.cpp` | `OHOS_ARCH_LITE` | `clientProxy` 未声明 | 该 Lite 初始化单元应被拒绝 |
| `frameworks/native/src/dhcp_server_callback_stub_lite.cpp` | `OHOS_ARCH_LITE` | `GetRawDataSize`、`state` 或成员初始化不匹配 | 该 Lite callback 单元应被拒绝 |
| `frameworks/native/src/dhcp_server_proxy_lite.cpp` | `OHOS_ARCH_LITE` | `WifiScanProxy`、`mRemoteDied` 未声明 | 该 Lite proxy 单元应被拒绝 |

适配头仅用于提供 OpenHarmony 平台类型的最小声明；被检查的三个 `.cpp` 文件、条件编译分支和报错标识符均来自目标仓库。
