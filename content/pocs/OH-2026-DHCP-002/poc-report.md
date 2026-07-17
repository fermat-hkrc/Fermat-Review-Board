# 验证报告：DHCP Server callback IPC 错位与未交付事件

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 发送端 | `DhcpServerCallbackProxy` |
| 接收端 | `DhcpServreCallBackStub` |
| 输入 | 接口 `wlan0`、一个站点、一个 lease 字符串 |
| 判定标准 | 上线回调应保留接口名和 1 个站点；lease 与退出回调应各到达一次 |

## 2. 使用的生产代码与边界替身

构建链接以下两个真实翻译单元：

- `services/dhcp_server/src/dhcp_server_callback_proxy.cpp`
- `frameworks/native/src/dhcp_server_callback_stub.cpp`

driver 只提供注册 callback、一个站点对象和 in-process IPC 端点。平台替身负责编解码 parcel 并把 production proxy 的 `SendRequest` 交给 production stub；字段写入、字段读取和 callback 分发均来自上述生产文件。

## 3. 输入构造

```cpp
proxy.OnServerSuccess("wlan0", stations);  // stations.size() == 1
proxy.OnServerLeasesChanged("wlan0", leases);
proxy.OnServerSerExitChanged("wlan0");
```

站点包含合法的设备名、MAC 和 IPv4 字符串。`RecordingCallback` 记录实际收到的接口名、站点数和三个回调次数。

## 4. 完整触发链

```text
OnServerSuccess("wlan0", oneStation)
  → production proxy 写入：exception=0, string "wlan0", int 1, station fields
  → SendRequest
  → production stub 的 RemoteOnServerSuccess
    → 先 ReadInt32() 作为 size                 // 读取了字符串 framing
    → 再 ReadString() 作为 ifName               // 已经偏移
    → 以错误 size 读取站点
  → RecordingCallback::OnServerSuccess

OnServerLeasesChanged / OnServerSerExitChanged
  → production proxy 记录日志后直接 return
  → 没有 SendRequest
  → RecordingCallback 不会被调用
```

## 5. 实际结果

```text
success_callback=1 ifname='' station_count=6 expected_ifname='wlan0' expected_count=1 leases_delivered=0 exit_delivered=0 expected_each=1
```

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 成功回调是否到达 | 1 | 1 |
| 成功回调接口名 | `wlan0` | 空字符串 |
| 成功回调站点数 | 1 | 6 |
| lease 回调次数 | 1 | 0 |
| exit 回调次数 | 1 | 0 |

数值 6 来自字符串在 parcel 中的编码数据被误读为整数；测试不依赖该具体值，判定是“不是原始 1”。

## 6. 结论与边界

该验证覆盖 production proxy 到 production stub 的完整 callback 路径，确认一个字段顺序不一致和两个完全未发送的事件。它不检查 DHCP 地址池分配，也不要求伪造外部 IPC 消息；三种事件均由正常服务端通知 API 触发。

## 7. 修复后的回归判定

修复后保持相同输入：

- `OnServerSuccess` 必须回调 `ifname="wlan0"` 和恰好 1 个内容一致的站点；
- `OnServerLeasesChanged` 必须回调 1 次并保留 lease 数据；
- `OnServerSerExitChanged` 必须回调 1 次并保留接口名；
- 分别测试 0、1 和多个站点，验证字段顺序不会再次漂移。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 真实回调端点的注册、三种正常事件输入与结果记录 |
| `build.sh` | 编译生产 proxy、生产 stub 与 IPC 边界 driver |
| `output.txt` | 本次端到端观察结果 |
