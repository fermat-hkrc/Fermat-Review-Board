# 验证报告：DHCP 成功回调导出未初始化计数

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `DhcpClientCallBack::OnIpSuccessChanged` |
| 生产转换函数 | `ResultInfoCopy`、`ResultInfoCopyExt` |
| 正常输入 | 成功状态、接口 `wlan0`、一个 DNS 地址 `8.8.8.8` |
| 判定标准 | 公开回调中的 `dnsList.dnsNumber` 必须等于实际输入 DNS 条目数 1 |

## 2. 使用的生产代码与测试控制

测试编译并调用生产 `frameworks/native/src/dhcp_event.cpp`。driver 通过该文件声明的公开 callback 类注册应用回调，再以一个正常 DHCP 成功结果调用 `OnIpSuccessChanged`。

为使“未初始化”在一次构建中稳定可见，`build.sh` 仅向编译器增加 `-ftrivial-auto-var-init=pattern`。该选项会为未显式初始化的自动变量填入固定模式；它不会修改生产 `OnIpSuccessChanged`、`ResultInfoCopy` 或 `ResultInfoCopyExt` 的源代码。这个控制用于证明字段没有被代码置零，不用于声称设备运行时必然出现同一数值。

## 3. 输入构造

```cpp
DhcpClientCallBack callback;
const ClientCallBack appCallback { ReceiveDhcpResult, nullptr };
callback.RegisterCallBack("wlan0", &appCallback);

OHOS::DHCP::DhcpResult result;
result.vectorDnsAddr.emplace_back("8.8.8.8");
callback.OnIpSuccessChanged(0, "wlan0", result);
```

`ReceiveDhcpResult` 是已注册应用回调，它读取生产转换后结构中的 `result->dnsList.dnsNumber`。输入不存在损坏 DHCP option 或异常 IPC 数据。

## 4. 完整触发链

```text
driver 提供 1 个 DNS 地址
  → 生产 OnIpSuccessChanged(0, "wlan0", result)
    → 声明 DhcpResult dhcpResult;              // 未进行值初始化
    → ResultInfoCopy(dhcpResult, result)
      → ResultInfoCopyExt(...)
        → dhcpResult.dnsList.dnsNumber++
    → 已注册 ClientCallBack::OnIpSuccessChanged(..., &dhcpResult)
      → driver 读取 dnsNumber
```

生产代码只按数组下标写入 DNS 字符串，但以 `++` 增加 `dnsNumber`；它没有在声明或复制前把该字段设置为 0。

## 5. 实际结果

```text
callback status=0 ifname=wlan0 dnsCount=2863311531
```

| 观察项 | 期望 | 实际 |
| --- | ---: | ---: |
| 输入 DNS 条目数 | 1 | 1 |
| 回调 `dnsNumber` | 1 | 2863311531 |
| 回调接口名 | `wlan0` | `wlan0` |

固定模式值 `2863311530` 经一次 `++` 形成 `2863311531`，与生产代码的计数操作一致。

## 6. 结论与边界

该验证证明未初始化计数字段进入了真实公开成功回调，并会影响应用侧可见元数据。自然运行环境中的初始字节取决于栈内容，可能不是本输出中的数值；可确认的事实是该值在代码中未被初始化且随后被当作计数使用。

本次 driver 覆盖 DNS 路径。相同结构中的 `addrList.addrNumber` 还被生产代码用于边界检查和数组下标，应作为修复后的独立回归项。

## 7. 修复后的回归判定

将局部对象改为 `DhcpResult dhcpResult {};` 后，保持相同输入：

- 回调 `dnsNumber` 必须为 1；
- 空 DNS 列表必须返回 0；
- 多 DNS 与 IPv6 地址列表必须从 0 连续计数；
- 固定自动变量初始化开关不应再影响任何导出计数。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 注册公开 callback 并构造正常成功 DHCP 结果 |
| `build.sh` | 编译生产 `dhcp_event.cpp` 与可复现初始化模式 |
| `output.txt` | 本次回调观察结果 |
