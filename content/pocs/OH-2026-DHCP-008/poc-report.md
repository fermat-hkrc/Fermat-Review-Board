# 验证报告：Lite StartDhcpClient 的请求错位与假成功

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 调用端 | `DhcpClientProxy::StartDhcpClient` |
| 服务端 | `DhcpClientStub::OnStartDhcpClient` |
| 输入 | 正常 `RouterConfig`：`ifname="wlan0"`、合法 BSSID |
| 判定标准 | proxy 返回成功时，服务端 `StartDhcpClient` 必须实际执行一次 |

## 2. 使用的生产代码与边界替身

构建直接链接：

- `frameworks/native/src/dhcp_client_proxy_lite.cpp`
- `services/dhcp_client/src/dhcp_client_stub_lite.cpp`

driver 提供最小 in-process `IClientProxy::Invoke`，把 production proxy 产生的请求交给 production stub，再把 production stub 写入的 reply 交回 production proxy 的回调。`TestServerStub` 仅覆盖业务 `StartDhcpClient` 来递增计数；它不改变请求读取、reply 编码或 proxy 返回值判断。

`callback_shim.cpp` 只满足 proxy 中静态 callback 对象的链接依赖，测试请求本身不经过 callback 传输。

## 3. 输入构造

```cpp
RouterConfig config {};
config.ifname = "wlan0";
config.bssid = "00:11:22:33:44:55";
const ErrCode result = proxy.StartDhcpClient(config);
```

这与普通 Lite 网络初始化调用相同：没有手工编辑 IPC 缓冲区，也没有注入传输失败。

## 4. 完整触发链

```text
driver 调用生产 DhcpClientProxy::StartDhcpClient(config)
  → proxy 写入：token、exception=0、ifname、bssid、5 个 bool
  → production DhcpClientStub::OnRemoteRequest
    → 验证 token 与 exception
    → OnStartDhcpClient
      → ReadRemoteObject(req, &sid)             // proxy 没有写入 SvcIdentity
      → 读取失败，reply 写入 exception=0 / retCode=DHCP_E_FAILED
      → 未调用 TestServerStub::StartDhcpClient
  → production proxy 接收 reply
    → 检查 owner.exception
    → 忽略 owner.retCode
    → return DHCP_E_SUCCESS
```

## 5. 实际结果

```text
proxy_result=0 server_start_calls=0 expected_result=0 expected_calls=1
```

| 观察项 | 期望 | 实际 |
| --- | ---: | ---: |
| 调用方结果 | 0 仅当服务已启动 | 0 |
| 服务端 `StartDhcpClient` 调用次数 | 1 | 0 |
| IPC 传输 | 成功 | 成功 |

driver 只有在“proxy 成功且服务端实际调用一次”时才返回失败；当前退出成功记录的正是两者不一致。

## 6. 结论与边界

该验证确认两个独立但连续的协议问题：请求端缺少 stub 要求的 `SvcIdentity`，以及返回端未传播 `retCode`。它不依赖恶意消息；正常 `RouterConfig` 已足够进入错误路径。因为 stub 在 identity 读取失败后立即返回，后续配置字段的业务赋值不属于本报告的验证结论。

## 7. 修复后的回归判定

- 正常启动时服务端调用次数为 1，proxy 返回业务结果；
- 服务端主动返回失败时，proxy 必须返回同一失败码；
- 若 `SvcIdentity` 是协议必需字段，proxy 必须写入它；若不是，stub 不得读取它；
- 传输失败与业务失败必须在 API 结果中区分。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 正常 RouterConfig、最小传输边界与服务调用计数 |
| `callback_shim.cpp` | 与本请求无关的静态 callback 链接适配 |
| `build.sh` | 编译两个生产 Lite 端点和 driver |
| `output.txt` | 调用方返回值与服务端实际调用次数 |
