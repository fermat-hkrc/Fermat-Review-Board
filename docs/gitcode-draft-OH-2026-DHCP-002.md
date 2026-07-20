# DHCP Server OnServerSuccess 回调 IPC 字段顺序不一致导致设备信息错误

以下“正文”是提交到 GitCode Issue 描述框的内容。

## 正文

## 问题概述

在 `communication_dhcp` 的非 Lite 回调路径中，
`DhcpServerCallbackProxy::OnServerSuccess` 与
`DhcpServreCallBackStub::RemoteOnServerSuccess` 对同一条 IPC 消息的业务字段使用了相反的顺序。

发送端先写入接口名，再写入站点数量；接收端却先读取站点数量，再读取接口名。读取游标从第一个业务字段开始偏移，导致应用注册的 `OnServerSuccess` 回调接收到错误的接口名和站点列表。

该问题存在于已验证的 `master`：

```text
f52429ee1873c13c8ed55bde0cb9914b2dfedc43
```

## 问题详情

### 问题代码

**发送端**

文件：`services/dhcp_server/src/dhcp_server_callback_proxy.cpp`

```cpp
// Lines 76-83
data.WriteInt32(0);
data.WriteString(ifname);
data.WriteInt32(stationInfos.size());
for (auto stationInfo: stationInfos) {
    data.WriteString(stationInfo.deviceName);
    data.WriteString(stationInfo.macAddr);
    data.WriteString(stationInfo.ipAddr);
}
```

公共异常字段之后，发送端的业务字段顺序为：

```text
ifname -> stationInfos.size() -> station fields
```

**接收端**

文件：`frameworks/native/src/dhcp_server_callback_stub.cpp`

```cpp
// Lines 157-170
int DhcpServreCallBackStub::RemoteOnServerSuccess(
    uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    int size = data.ReadInt32();
    if (size < 0 || size > MAXIMUM_SIZE) {
        reply.WriteInt32(0);
        return DHCP_E_SUCCESS;
    }

    std::string ifName = data.ReadString();
    std::vector<DhcpStationInfo> stationInfos;
    for (int i = 0; i < size; i++) {
        std::string deviceName = data.ReadString();
        std::string macAddress = data.ReadString();
        std::string ipAddress = data.ReadString();
        // ...
    }
    OnServerSuccess(ifName, stationInfos);
    // ...
}
```

接收端的业务字段读取顺序为：

```text
station count -> ifname -> station fields
```

### 字段对应关系

`OnRemoteRequest` 已经正确读取 interface token 和异常字段。问题只发生在随后的业务字段部分：

| 消息位置 | 发送端写入 | 接收端读取 | 结果 |
| --- | --- | --- | --- |
| 1 | interface token | `ReadInterfaceToken()` | 一致 |
| 2 | 异常字段 `0` | `ReadInt32()` | 一致 |
| 3 | `WriteString(ifname)` | `ReadInt32()` 作为 `size` | 错位 |
| 4 | `WriteInt32(stationInfos.size())` | `ReadString()` 作为 `ifName` | 错位 |
| 5 | 站点字段 | 按错误的 `size` 循环读取 | 持续偏移 |

### 完整调用链

该路径由正常 DHCP 租约确认触发：

```text
DHCP 客户端完成租约申请
  -> MessageProcess 返回 REPLY_ACK
  -> NotifyConnetDeviceChanged(replyType, ctx)
  -> srvIns->deviceConnectFun(ctx->ifname)
  -> DeviceConnectCallBack(ifname)
  -> DhcpServerServiceImpl::DeviceInfoCallBack(ifname)
  -> GetDhcpClientInfos / ConvertLeasesToStationInfos
  -> IDhcpServerCallBack::OnServerSuccess(ifname, stationInfos)
  -> DhcpServerCallbackProxy::OnServerSuccess
  -> DhcpServreCallBackStub::RemoteOnServerSuccess
  -> 应用注册的 OnServerSuccess 回调
```

相关位置：

- `services/dhcp_server/src/dhcp_s_server.cpp:554-588`
- `services/dhcp_server/src/dhcp_server_service_impl.cpp:208, 232-251, 291-303`
- `services/dhcp_server/src/dhcp_server_callback_proxy.cpp:76-83`
- `frameworks/native/src/dhcp_server_callback_stub.cpp:43, 62-63, 157-200`

### 根本原因

同一个回调协议的序列化与反序列化逻辑分散在两个文件中，但没有共享字段布局定义，也没有成对测试保证字段顺序一致。

`RemoteOnServerSuccess` 读取 `size` 时，当前游标实际位于 `ifname` 的序列化数据处；随后读取 `ifName` 时，游标已经不再位于原始站点数量字段。后续循环次数和站点字段均基于已经偏移的游标。

## 触发条件

1. 使用编译 `MessageParcel` 回调实现的非 Lite 路径。
2. DHCP Server 已为目标接口注册 `OnServerSuccess` 回调。
3. DHCP 客户端正常完成租约申请，服务端产生 `REPLY_ACK`。
4. 服务端能够取得至少一个站点记录并进入 `DeviceInfoCallBack`。

不需要构造非正常 IPC 数据，也不依赖异常系统状态。

## 影响分析

- 回调订阅者收到的接口名可能为空或与发送端不一致。
- 站点数量可能与服务端实际站点数量不一致。
- 后续设备名、MAC 地址和 IP 地址可能被错误解析。
- 在常见接口名输入下，`size` 仍可能落在 `MAXIMUM_SIZE` 范围内，函数继续执行并返回成功，调用侧无法通过返回值识别数据已经失真。
- DHCP Server 已取得正确租约信息，但应用侧无法获得同等语义的数据。

## 验证结果

最小联调直接编译目标仓库中的生产 `DhcpServerCallbackProxy` 与生产 `DhcpServreCallBackStub`。测试端只提供进程内 IPC 端点和记录应用回调结果的对象，不替换字段写入或读取逻辑。

输入：

```text
ifname = wlan0
station count = 1
```

回调结果：

```text
success_callback=1 ifname='' station_count=6
expected_ifname='wlan0' expected_count=1
```

回调能够到达，但接口名和站点数量均不等于发送端数据。数值 `6` 来自字符串编码信息被按整数读取；问题判定不依赖该固定数值。

## 修复建议

在 `RemoteOnServerSuccess` 中按发送端顺序读取字段：

```cpp
std::string ifName = data.ReadString();
int size = data.ReadInt32();
if (size < 0 || size > MAXIMUM_SIZE) {
    reply.WriteInt32(0);
    return DHCP_E_SUCCESS;
}
```

建议增加 proxy/stub 成对回归测试，至少覆盖一个站点和多个站点，并校验接口名、数量及每个字段均与发送端一致。

## 涉及文件

- `services/dhcp_server/src/dhcp_s_server.cpp`
- `services/dhcp_server/src/dhcp_server_service_impl.cpp`
- `services/dhcp_server/src/dhcp_server_callback_proxy.cpp`
- `frameworks/native/src/dhcp_server_callback_stub.cpp`
