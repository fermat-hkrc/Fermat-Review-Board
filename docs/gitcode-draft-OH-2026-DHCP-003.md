# DHCP Option Overload 扩展字段选项解析仍读取主 options 区域

以下“正文”是提交到 GitCode Issue 描述框的内容。

## 正文

## 问题概述

`GetDhcpOption` 已实现 DHCP Option Overload 的字段切换：当主 `options` 区中的 option 52 指定 `file` 或 `sname` 承载额外选项时，主循环会把当前扫描指针切换到对应字段。

但是，字段切换后用于确认选项代码和长度的 `CheckOptionsData` 仍然自行固定读取 `packet->options`。因此主循环扫描的是 `file` 或 `sname`，校验函数检查的却是主 `options` 区域，二者不再指向同一段数据。

位于扩展字段中的合法配置项无法被识别。DNS 解析路径直接使用该通用函数；未找到 DNS option 时，客户端会改用默认 DNS 配置。

## 问题详情

### 问题代码

文件：`services/dhcp_client/src/dhcp_options.cpp`

`GetDhcpOption` 使用 `pOption` 维护当前扫描字段：

```cpp
const uint8_t *pOption = packet->options;
int nIndex = 0;
int maxLen = DHCP_OPT_SIZE;

// 遇到 option 52 后，读取到 END_OPTION 时切换到 file
pOption = packet->file;
nIndex = 0;
maxLen = DHCP_BOOT_FILE_LENGTH;
```

但循环顶部调用的辅助函数没有接收当前 `pOption`：

```cpp
int nRet = CheckOptionsData(packet, code, nIndex, maxLen);
```

`CheckOptionsData` 内部重新选择了主字段：

```cpp
static int CheckOptionsData(const struct DhcpPacket *packet,
    int code, int index, int maxLen)
{
    // ...
    const uint8_t *pOption = packet->options;
    if (pOption[index + DHCP_OPT_CODE_INDEX] != code) {
        return DHCP_OPT_NULL;
    }
    // ...
}
```

因此，当外层 `pOption` 已经指向 `packet->file` 时，`CheckOptionsData` 仍在 `packet->options[index]` 比较 option code。

### 正常调用链

```text
DHCP 客户端接收 DHCP_ACK
  -> DhcpAckOrNakPacketHandle
  -> ParseDhcpAckPacket
  -> ParseNetworkDnsInfo
  -> GetDhcpOption(packet, DOMAIN_NAME_SERVER_OPTION, &len)
  -> option 52 指定 FILE_FIELD
  -> 当前扫描指针切换到 packet->file
  -> CheckOptionsData 仍读取 packet->options
  -> DNS option 未找到
  -> SetIpv4DefaultDns
```

相关位置：

- `services/dhcp_client/src/dhcp_client_state_machine.cpp:1228-1255`
- `services/dhcp_client/src/dhcp_client_state_machine.cpp:1289-1312`
- `services/dhcp_client/src/dhcp_client_state_machine.cpp:934-945`
- `services/dhcp_client/src/dhcp_options.cpp:46-69`
- `services/dhcp_client/src/dhcp_options.cpp:153-202`

### 可复现输入

以下是 RFC 2132 Option Overload 定义的正常布局：

```text
packet.options = [52, 1, FILE_FIELD, END]
packet.file    = [6, 4, 8, 8, 8, 8, END]
```

其中：

- option `52` 表示 `file` 字段承载额外选项；
- option `6` 是 DNS Server；
- DNS 值为 `8.8.8.8`。

使用生产 `dhcp_options.cpp` 解析上述报文：

```text
valid overload DNS parsed=0 value=0
```

期望结果应为成功找到 DNS option，并得到 `8.8.8.8`。

## 根本原因

字段切换状态只保存在 `GetDhcpOption` 的局部变量 `pOption` 中，但辅助函数未接收该变量，而是重新从 `packet->options` 开始读取。

`pOption` 与 `maxLen` 本应始终表示同一字段：

```text
packet->options + DHCP_OPT_SIZE
packet->file    + DHCP_BOOT_FILE_LENGTH
packet->sname   + DHCP_HOST_NAME_LENGTH
```

当前代码只更新了外层的 `pOption` 和 `maxLen`，没有让辅助校验逻辑同步切换。

## 触发条件

1. DHCP 客户端收到 DHCP_ACK。
2. DHCP 服务端使用 option 52 声明 `file` 或 `sname` 包含额外选项。
3. 目标配置项位于被声明的扩展字段中。
4. 客户端通过 `GetDhcpOption` 读取该配置项。

该报文布局由 [RFC 2132 Section 9.3](https://datatracker.ietf.org/doc/html/rfc2132#section-9.3) 定义，不需要使用异常报文。

## 影响分析

- 位于 `file` 或 `sname` 中的 DNS、路由等配置项可能被忽略。
- 客户端可继续获得地址，但网络配置可能与 DHCP 服务端提供的配置不一致。
- DNS option 未找到时，`ParseNetworkDnsInfo` 明确调用 `SetIpv4DefaultDns`。
- 只在主 `options` 区放置选项的 DHCP 服务端不受影响，因此问题会随网络环境而变化。

## 修复建议

让辅助函数使用当前扫描字段，而不是自行固定为 `packet->options`：

```cpp
static int CheckOptionsData(const uint8_t *pOption,
    int code, int index, int maxLen)
{
    if (index >= maxLen - DHCP_OPT_DATA_INDEX) {
        return DHCP_OPT_FAILED;
    }
    if (pOption[index + DHCP_OPT_CODE_INDEX] != code) {
        return DHCP_OPT_NULL;
    }
    if (index + DHCP_OPT_LEN_INDEX +
        pOption[index + DHCP_OPT_LEN_INDEX] >= maxLen) {
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}
```

调用点传入当前 `pOption`：

```cpp
int nRet = CheckOptionsData(pOption, code, nIndex, maxLen);
```

`CheckOptSoverloaded` 也建议接收当前字段指针，保证读取指针、边界和 option 数据始终来自同一字段。

## 回归测试建议

1. DNS 位于主 `options` 区，保持现有结果。
2. option 52 指定 `FILE_FIELD`，DNS 位于 `file`。
3. option 52 指定 `SNAME_FIELD`，DNS 位于 `sname`。
4. option 52 同时指定两个字段。
5. 扩展字段中存在不完整 option 时，应在该字段边界内拒绝，不得回读主字段同一偏移。

## 涉及文件

- `services/dhcp_client/src/dhcp_options.cpp`
- `services/dhcp_client/src/dhcp_client_state_machine.cpp`
