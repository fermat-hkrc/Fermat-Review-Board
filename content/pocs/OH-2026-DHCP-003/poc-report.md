# 验证报告：Option Overload 切换后仍校验主 options 区域

## 1. 目标与版本

| 项目 | 内容 |
| --- | --- |
| 目标仓库 | communication_dhcp |
| 目标版本 | GitCode master，f52429ee1873c13c8ed55bde0cb9914b2dfedc43 |
| 生产入口 | GetDhcpOptionUint32 -> GetDhcpOption |
| 生产文件 | services/dhcp_client/src/dhcp_options.cpp |
| 输入 | option 52 指向 file，DNS option 位于 file |
| 判定 | 解析器应找到 DNS 8.8.8.8 |

## 2. 输入布局

    packet.options = [52, 1, FILE_FIELD, END]
    packet.file    = [6, 4, 8, 8, 8, 8, END]

主 fields 声明 file 承载扩展 options；file 内的 option 6 是 DNS 8.8.8.8。

## 3. 触发过程

    GetDhcpOptionUint32(packet, option 6, &dns)
      -> production GetDhcpOption 识别 option 52
      -> 当前扫描指针切换到 packet.file
      -> CheckOptionsData 又固定读取 packet.options
      -> 主 fields 的 option 52 不是 option 6
      -> 返回未找到

driver 只构造 DhcpPacket。扫描、长度检查和数值读取均由生产 dhcp_options.cpp 完成。

## 4. 实际结果

    valid overload DNS parsed=0 value=0

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 是否找到 DNS option | 1 | 0 |
| DNS 值 | 0x08080808 | 0 |

## 5. 结论

当前字段已切换到 file，但辅助校验仍使用主 options。修复后，保持相同报文时 parsed 应为 1，DNS 值应为 8.8.8.8。
