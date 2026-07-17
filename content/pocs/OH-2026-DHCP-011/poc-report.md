# 验证报告

## 验证范围

- 生产源文件：`services/dhcp_client/src/dhcp_client_state_machine.cpp` 与 `services/dhcp_client/src/dhcp_options.cpp`
- 入口：`DhcpClientStateMachine::DhcpDecline`
- 方法：构造地址冲突后的正常 Decline 上下文，并在发送边界检查真实生成的 DHCP 报文选项。

## 触发链

1. 客户端地址冲突路径调用真实 `DhcpDecline`。
2. 真实函数先加入 Requested IP Address 和 Server Identifier。
3. 同一函数再次加入完全相同的两项。
4. 发送边界捕获到包含重复选项的报文。

## 判定条件

每个选项应各出现一次。实际结果为 `requested_ip_options=2`、`server_id_options=2`。

## 边界说明

替身只观察发送出的报文；状态机中的报文初始化、选项追加和序列化均来自生产源文件。
