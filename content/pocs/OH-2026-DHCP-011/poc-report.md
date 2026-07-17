# 验证报告：DHCPDECLINE 包含重复 Requested IP 与 Server Identifier

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `DhcpClientStateMachine::DhcpDecline` |
| 关联生产代码 | `dhcp_client_state_machine.cpp`、`dhcp_options.cpp` |
| 输入 | 一个事务 ID、请求地址和服务端地址 |
| 判定标准 | 最终 DHCPDECLINE 中 option 50 和 option 54 各出现一次 |

## 2. 使用的生产代码与观察边界

`harness.cpp` 通过 include path 直接包含生产 `dhcp_client_state_machine.cpp`。它链接生产 `dhcp_options.cpp`，因此 packet 初始化、Client Identifier 写入和四次 `AddOptValueToOpts` 均来自目标仓库。

唯一观察边界是 `SendToDhcpPacket`：替身复制生产已经构造好的 `DhcpPacket`，不更改其任何 option。driver 随后按 DHCP option 编码遍历该副本，统计 code 50 与 code 54 的出现次数。

## 3. 输入构造

```cpp
DhcpClientStateMachine state("test0");
state.m_cltCnf.ifaceIndex = 1;
// 填充有效接口 MAC 后：
state.DhcpDecline(0x10203040, 0x0a000002, 0x0a000001);
```

调用使用一个常规 transaction ID、客户端请求地址和 server identifier。它不直接编辑 `packet.options`；该数组完全由生产 `DhcpDecline` 填充。

## 4. 完整触发链

```text
driver 调用 production DhcpClientStateMachine::DhcpDecline
  → memset packet
  → GetPacketHeaderInfo(packet, DHCP_DECLINE)
  → AddClientIdToOpts(packet)
  → AddOptValueToOpts(option 50, clientIp)
  → AddOptValueToOpts(option 54, serverIp)
  → AddOptValueToOpts(option 50, clientIp)     // 第二次
  → AddOptValueToOpts(option 54, serverIp)     // 第二次
  → SendToDhcpPacket(packet, ...)
    → 测试观察副本
  → driver 按 option TLV 遍历并计数
```

## 5. 实际结果

```text
decline_result=0 requested_ip_options=2 server_id_options=2 expected_each=1
```

| 观察项 | 期望 | 实际 |
| --- | ---: | ---: |
| `DhcpDecline` 返回值 | 0 | 0 |
| Requested IP Address，code 50 | 1 个 | 2 个 |
| Server Identifier，code 54 | 1 个 | 2 个 |

driver 将“成功返回且两个计数均为 2”视为触发成功，因此不会把单纯的状态机失败误认为重复 option。

## 6. 结论与边界

该验证确认了生产 DHCPDECLINE 构造路径中的重复追加。它不针对 DHCPDISCOVER、DHCPREQUEST 或 DHCPRELEASE；这些报文由其他状态机函数构造，不能由本测试推断。

## 7. 修复后的回归判定

删除重复两行后，保持相同输入：

- 函数应继续返回 0；
- option 50 计数必须为 1，值等于请求地址；
- option 54 计数必须为 1，值等于服务端地址；
- Client Identifier 仍按现有行为写入；
- 通过 `Declining` 状态入口再执行一次，以确认状态转换未受影响。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `harness.cpp` | 编译生产状态机并在发送边界观察最终 packet |
| `driver.cpp` | 调用 `DhcpDecline` 并按 TLV 统计 option 出现次数 |
| `build.sh` | 编译生产状态机、生产 option 代码与 driver |
| `output.txt` | 本次 packet option 计数 |
