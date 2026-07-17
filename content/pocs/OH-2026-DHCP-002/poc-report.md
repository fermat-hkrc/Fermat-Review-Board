# 验证报告

## 验证范围

- 生产源文件：`services/dhcp_server/src/dhcp_server_callback_proxy.cpp` 与 `frameworks/native/src/dhcp_server_callback_stub.cpp`
- 入口：服务端回调 proxy 到客户端回调 stub 的 IPC 调用。
- 方法：编译两个真实端点，用最小 IPC 边界替身传递上线、租约变化和服务退出事件。

## 触发链

1. 真实 proxy 发送成功回调，写入接口名后写入设备数。
2. 真实 stub 按设备数后接口名的顺序读取，造成字段错位。
3. driver 依次发送成功、租约变化和服务退出事件。
4. stub 的租约变化和服务退出处理路径直接返回，未调用已注册回调。

## 判定条件

接口名应为 `wlan0`、设备数应为 `1`，且三类回调各应送达一次。实际结果为接口名为空、设备数为 `6`、租约与退出事件送达次数均为 `0`。

## 边界说明

替身仅提供 IPC 编解码环境；字段写入、字段读取和回调分派均来自生产源文件。该验证覆盖了完整的 proxy 到 stub 传输链。
