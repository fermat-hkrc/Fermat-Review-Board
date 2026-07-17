# 验证报告：较短 Host Name 覆盖后遗留旧后缀

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `GetHostNameOption` |
| 生产文件 | `services/dhcp_server/src/dhcp_s_server.cpp` |
| 初始值 | `AddressBinding::deviceName = "long-name"` |
| 更新值 | 合法 Host Name option `"x"` |
| 判定标准 | 更新后 `deviceName` 必须仅为 `"x"` |

## 2. 使用的生产代码与边界

driver 构造一个标准 DHCP option 链和一个 `AddressBinding`，两次调用真实 `GetHostNameOption`。生产 `dhcp_s_server.cpp` 和 option 查找实现 `dhcp_option.cpp` 均参与链接。driver 没有手工写入 `binding.deviceName` 的第二次结果，也没有复制生产的 `memcpy_s` 逻辑。

## 3. 输入构造

```text
第一次 Host Name option: "long-name"，长度 9
第二次 Host Name option: "x"，长度 1
目标 binding: 同一个 AddressBinding 实例
```

该顺序模拟已有 lease 在后续 DHCP REQUEST 中收到较短 Host Name。两次长度都小于 `DEVICE_NAME_STRING_LENGTH`，因此不经过超长拒绝分支。

## 4. 完整触发链

```text
第一次 production GetHostNameOption
  → memcpy_s(deviceName, ..., "long-name", 9)
  → deviceName = "long-name\0"

第二次 production GetHostNameOption
  → memcpy_s(deviceName, ..., "x", 1)
  → 只覆盖第一个字节
  → 未清空剩余字节，未写入新的 '\0'
  → deviceName = "xong-name\0"
```

## 5. 实际结果

```text
hostname_after_short_update='xong-name' expected='x'
```

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 初始名称 | `long-name` | `long-name` |
| 更新名称 | `x` | 输入为 `x` |
| 更新后的 C 字符串 | `x` | `xong-name` |

## 6. 结论与边界

该验证证明针对同一 lease 的短字符串更新会保留旧内容。首次写入、等长更新或更长更新可能看起来正常，因此测试必须使用“长到短”的真实状态变化。报告不涉及超长 option 或非法 DHCP 报文。

## 7. 修复后的回归判定

- 长名称到短名称更新后，字符串必须精确等于短名称；
- 短名称到长名称与等长更新保持正确；
- 读取 `deviceName` 的完整缓冲区应在新名称后立即出现终止符；
- 通过 `OnReceivedRequest` 的已有 lease 路径重复执行同一用例。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 构造一个 option 链、一个 lease 及长到短两次更新 |
| `build.sh` | 编译生产 server 与 option 代码 |
| `output.txt` | 更新后实际 C 字符串 |
