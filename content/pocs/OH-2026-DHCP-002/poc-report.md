# 验证报告：DHCP Server 成功回调字段顺序不一致

## 1. 目标与版本

| 项目 | 内容 |
| --- | --- |
| 目标仓库 | communication_dhcp |
| 目标版本 | GitCode master，f52429ee1873c13c8ed55bde0cb9914b2dfedc43 |
| 发送端 | DhcpServerCallbackProxy |
| 接收端 | DhcpServreCallBackStub |
| 输入 | 接口 wlan0、一个站点 |
| 判定 | 回调必须收到 wlan0 和恰好一个相同站点 |

## 2. 使用的生产代码

构建链接真实的：

- services/dhcp_server/src/dhcp_server_callback_proxy.cpp
- frameworks/native/src/dhcp_server_callback_stub.cpp

driver 只提供 callback 注册、一个站点对象和 in-process IPC 端点。字段写入、字段读取和生产 stub 的分发逻辑均来自目标仓库。

## 3. 触发过程

    proxy.OnServerSuccess("wlan0", oneStation)
      -> proxy 写入 string ifname
      -> proxy 写入 int station count
      -> production stub 先 ReadInt32 作为 count
      -> production stub 再 ReadString 作为 ifname
      -> RecordingCallback 记录收到的值

## 4. 实际结果

    success_callback=1 ifname='' station_count=6 expected_ifname='wlan0' expected_count=1

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 回调是否到达 | 1 | 1 |
| 接口名 | wlan0 | 空字符串 |
| 站点数量 | 1 | 6 |

数值 6 来自字符串 framing 被当作整数读取。本验证的判定是接收结果不等于发送结果，而不依赖该具体数值。

## 5. 结论

同一条生产 callback 消息的写入与读取顺序不一致。保持相同输入时，修复后应收到 wlan0 和恰好一个站点。
