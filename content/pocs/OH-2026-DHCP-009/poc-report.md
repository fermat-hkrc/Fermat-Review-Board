# 验证报告：较短 Host Name 更新后保留旧后缀

## 1. 目标与版本

| 项目 | 内容 |
| --- | --- |
| 目标仓库 | communication_dhcp |
| 目标版本 | GitCode master，f52429ee1873c13c8ed55bde0cb9914b2dfedc43 |
| 生产入口 | GetHostNameOption |
| 生产文件 | services/dhcp_server/src/dhcp_s_server.cpp |
| 初始名称 | long-name |
| 更新名称 | x |
| 判定 | 更新后 deviceName 必须仅为 x |

## 2. 触发过程

driver 对同一个 AddressBinding 两次调用生产 GetHostNameOption：

    第一次：memcpy_s(deviceName, ..., "long-name", 9)
    第二次：memcpy_s(deviceName, ..., "x", 1)

第二次复制只覆盖第一个字节，旧结束符和旧后缀仍在数组中。

## 3. 实际结果

    hostname_after_short_update='xong-name' expected='x'

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 更新名称 | x | 输入为 x |
| 更新后的 C 字符串 | x | xong-name |

## 4. 结论

短名称更新没有清除旧字节，也没有设置新的结束符。修复后，同一用例必须只输出 x。
