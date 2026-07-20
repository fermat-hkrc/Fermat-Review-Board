# DHCP Host Name 由长名称更新为短名称后保留旧后缀

以下“正文”是提交到 GitCode Issue 描述框的内容。

## 正文

## 问题概述

DHCP Server 在处理已有租约的 DHCP REQUEST 时，会将 Host Name option 写入 `AddressBinding::deviceName`。

`GetHostNameOption` 仅复制本次 option 的实际长度，既不清空旧缓冲区，也不在新名称末尾写入字符串结束符。当同一租约先使用较长名称、后续更新为较短名称时，旧名称的尾部仍保留在 `deviceName` 中。

例如，同一租约先写入 `long-name`，后写入 `x`，最终读取到的是：

```text
xong-name
```

而不是：

```text
x
```

## 问题详情

### 问题代码

文件：`services/dhcp_server/src/dhcp_s_server.cpp`

```cpp
int GetHostNameOption(PDhcpMsgInfo received, AddressBinding *bindin)
{
    // ...
    PDhcpOption optHostName = GetOption(&received->options, HOST_NAME_OPTION);
    if (optHostName) {
        if (optHostName->length >= DEVICE_NAME_STRING_LENGTH) {
            return REPLY_NONE;
        }
        if (memcpy_s(bindin->deviceName, DEVICE_NAME_STRING_LENGTH,
            (char*)optHostName->data, optHostName->length) != EOK) {
            return REPLY_NONE;
        }
        DHCP_LOGI("GetHostNameOption deviceName:%{public}s", bindin->deviceName);
    }
    return REPLY_NAK;
}
```

`AddressBinding::deviceName` 是可复用的字符数组：

```cpp
char deviceName[DEVICE_NAME_STRING_LENGTH];
```

当第一次写入 `long-name` 后，数组内容为：

```text
l o n g - n a m e \0
```

第二次只复制 `x` 的一个字节后，数组内容变为：

```text
x o n g - n a m e \0
```

当前函数的长度校验只能保证复制范围不超过数组，不会删除新名称之后的旧字节，也不会移动结束符。

### 正常调用链

```text
同一客户端已有 DHCP 租约
  -> 客户端后续发送 DHCP REQUEST
  -> OnReceivedRequest 找到 binding 和 lease
  -> ParseDhcpOption(received, lease)
  -> GetHostNameOption(received, lease)
  -> 仅覆盖 deviceName 前 N 个字节
  -> SaveBindingRecoders 写入租约记录
  -> GetDhcpClientInfos / DeviceInfoCallBack 返回错误名称
```

相关位置：

- `services/dhcp_server/src/dhcp_s_server.cpp:1239-1260`
- `services/dhcp_server/src/dhcp_s_server.cpp:1342-1355`
- `services/dhcp_server/src/dhcp_s_server.cpp:1358-1395`
- `services/dhcp_server/src/dhcp_binding.cpp:103-105`
- `services/dhcp_server/src/dhcp_server_service_impl.cpp:232-251`
- `services/dhcp_server/src/dhcp_server_service_impl.cpp:624-671`

### 验证结果

对同一个 `AddressBinding` 连续调用生产 `GetHostNameOption`：

```text
第一次 Host Name：long-name
第二次 Host Name：x
```

实际输出：

```text
hostname_after_short_update='xong-name' expected='x'
```

该结果来自生产 `dhcp_s_server.cpp` 与生产 option 链表查询逻辑。

## 根本原因

DHCP Host Name option 使用显式长度表示内容，不保证带有 C 字符串结束符。内部保存到 `deviceName` 时，代码将其作为 C 字符串使用，但没有将长度边界转换为新的 `\0` 终止位置。

同一个 `AddressBinding` 在租约续期和更新过程中会被重复使用，因此旧内容不会自然消失。

## 触发条件

1. DHCP Server 中存在该客户端的已有 `binding` 和 `lease`。
2. 客户端后续发送合法 DHCP REQUEST。
3. 第一次 Host Name 长于第二次 Host Name。
4. 第二次请求仍携带 Host Name option。

不需要超长名称、不完整报文或特殊内存状态。

## 影响分析

- 租约记录中的设备名称不能反映最新 Host Name。
- `WriteAddressBinding` 使用 `%s` 序列化 `deviceName`，因此旧后缀会进入租约文件。
- `GetDhcpClientInfos` 读取租约文件，`DeviceInfoCallBack` 再将名称转换为站点信息并通知订阅者。
- 管理页面、设备列表、日志或依赖 DHCP 客户端信息的上层组件可能显示拼接后的错误名称。

该问题是租约元数据一致性问题；本条不包含数组越界或异常内存访问的结论。

## 修复建议

在复制前清空目标数组，并在复制后显式写入结束符：

```cpp
if (optHostName->length >= DEVICE_NAME_STRING_LENGTH) {
    return REPLY_NONE;
}

if (memset_s(bindin->deviceName, DEVICE_NAME_STRING_LENGTH, 0,
    DEVICE_NAME_STRING_LENGTH) != EOK) {
    return REPLY_NONE;
}

if (memcpy_s(bindin->deviceName, DEVICE_NAME_STRING_LENGTH,
    optHostName->data, optHostName->length) != EOK) {
    return REPLY_NONE;
}

bindin->deviceName[optHostName->length] = '\0';
```

现有的 `< DEVICE_NAME_STRING_LENGTH` 检查应保留，确保结束符索引始终在数组范围内。

## 回归测试建议

1. 首次写入名称。
2. 长名称更新为短名称。
3. 短名称更新为长名称。
4. 等长名称更新。
5. 经 `OnReceivedRequest -> ParseDhcpOption` 的已有租约路径。
6. 验证保存后的 lease 文件及 `GetDhcpClientInfos` 返回的名称均与最新 Host Name 一致。

## 涉及文件

- `services/dhcp_server/src/dhcp_s_server.cpp`
- `services/dhcp_server/include/dhcp_binding.h`
- `services/dhcp_server/src/dhcp_binding.cpp`
- `services/dhcp_server/src/dhcp_server_service_impl.cpp`
