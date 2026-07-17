# 验证报告：Option Overload 切换后仍从主 fields 校验

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `GetDhcpOptionUint32` → `GetDhcpOption` |
| 生产文件 | `services/dhcp_client/src/dhcp_options.cpp` |
| 输入 | 合法 option 52 指向 `file`，DNS option 位于 `file` |
| 判定标准 | 解析器应找到 option 6，并返回 DNS 值 `8.8.8.8` |

## 2. 使用的生产代码与边界

driver 只初始化 `DhcpPacket` 的固定字节 fields，所有 Option Overload 切换、option 代码比较、长度检查和 uint32 值提取都由生产 `dhcp_options.cpp` 执行。适配头只提供项目依赖的基础声明，未替换 `GetDhcpOption` 或辅助校验函数。

## 3. 合法输入布局

```text
packet.options:
  [52, 1, FILE_FIELD, 255]
   │   │      │        └─ END
   │   │      └────────── file 字段承载扩展 options
   │   └───────────────── 长度 1
   └───────────────────── Option Overload

packet.file:
  [6, 4, 8, 8, 8, 8, 255]
   │  │  └─────────────── DNS 8.8.8.8
   │  └────────────────── 4 字节
   └───────────────────── Domain Name Server option
```

该数据满足“主 options 中声明重载、扩展字段中包含目标 option、每个字段以 END 结束”的正常解析场景。

## 4. 完整触发链

```text
driver 调用 GetDhcpOptionUint32(packet, option 6, &dns)
  → production GetDhcpOption
    → 初始 pOption = packet.options
    → 识别 option 52，记录 FILE_FIELD
    → 遇到主 fields END
    → pOption = packet.file, nIndex = 0, maxLen = DHCP_BOOT_FILE_LENGTH
    → CheckOptionsData(packet, option 6, 0, maxLen)
      → 辅助函数重新设置 pOption = packet->options
      → 看到 option 52，不是 option 6
      → 返回“未找到”
  → GetDhcpOptionUint32 返回 false
```

主循环的 `pOption` 与辅助函数内部的 `packet->options` 在最后一步指向不同内存区域，这是本验证的关键。

## 5. 实际结果

```text
valid overload DNS parsed=0 value=0
```

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 是否找到 DNS option | 1 | 0 |
| 解析的 DNS 值 | `0x08080808` | 0 |

driver 以“找到 option”作为成功条件，因此退出码为 0 表示真实解析器没有识别这个合法输入。

## 6. 结论与边界

该验证确认的是 `file` 重载字段的扫描错误。主 `options` fields 中的同类 option 不受这份输入证明的影响。测试也不假设任何特定 DHCP Server；它只要求服务端使用 RFC 2132 定义的 Option Overload 格式。

## 7. 修复后的回归判定

将当前 fields 指针传入 `CheckOptionsData` 与 `CheckOptSoverloaded` 后，保持本 driver：

- `parsed` 必须为 1；
- DNS 值必须等于输入的 `8.8.8.8`；
- 再增加 `SNAME_FIELD` 与同时使用 `FILE_FIELD | SNAME_FIELD` 的输入；
- 对扩展 fields 的越界长度保持拒绝，且不得回退读取主 fields 的同索引字节。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 以字节形式构造合法 Option Overload DHCP packet |
| `build.sh` | 编译生产 parser 与 driver |
| `output.txt` | 本次真实解析结果 |
