# 验证报告

## 验证范围

- 生产源文件：`frameworks/native/src/dhcp_client_proxy_lite.cpp` 与 `services/dhcp_client/src/dhcp_client_stub_lite.cpp`
- 入口：`DhcpClientProxy::StartDhcpClient`
- 方法：编译真实 Lite proxy 和真实 Lite stub，使用最小 IPC 框架替身把 proxy 请求送达 stub。

## 触发链

1. driver 以正常 `RouterConfig` 调用真实 proxy 的启动接口。
2. proxy 写入配置字段，但没有写入 stub 后续读取的 `SvcIdentity`。
3. stub 的 `ReadRemoteObject` 失败，在 reply 写入失败码，未调用真实启动函数。
4. proxy 忽略 `retCode`，并向 driver 返回成功值。

## 判定条件

调用结果应与服务端启动调用次数一致。实际结果为 `proxy_result=0`、`server_start_calls=0`，即调用方看到成功而服务端未启动。

## 边界说明

替身仅提供 Lite IPC 运行环境；请求写入、请求读取、reply 处理和返回值判断均来自生产 proxy 与 stub。
