# 验证报告：网络序 IPv4 原始大小比较拒绝范围成员

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `IpInRange` |
| 生产文件 | `services/dhcp_server/src/address_utils.cpp` |
| 范围 | `192.168.1.250` 至 `192.168.2.10`，掩码 `/16` |
| 候选地址 | `192.168.2.1` |
| 判定标准 | 候选地址位于该点分十进制闭区间内，应返回 `DHCP_TRUE` |

## 2. 使用的生产代码与边界

driver 调用生产 `ParseIpAddr` 得到与 DHCP 代码一致的网络表示，再调用生产 `IpInRange`。没有自行计算整数地址、没有模拟 `IpInRange`，也没有替换网络地址比较。

## 3. 输入构造

```cpp
const uint32_t begin = ParseIpAddr("192.168.1.250");
const uint32_t end = ParseIpAddr("192.168.2.10");
const uint32_t candidate = ParseIpAddr("192.168.2.1");
const uint32_t netmask = ParseIpAddr("255.255.0.0");
const int result = IpInRange(candidate, begin, end, netmask);
```

三个地址都属于 `192.168.0.0/16`。候选地址大于起点且小于终点，这是文本 IPv4 顺序的正常地址池成员。

## 4. 完整触发链

```text
driver 调用生产 ParseIpAddr 四次
  → 生产 IpInRange(candidate, begin, end, mask)
    → NetworkAddress 确认三者同属 /16
    → 直接执行 candidate >= begin && candidate <= end
      （这些 uint32_t 仍为网络序表示）
  → 返回 DHCP_FALSE
```

小端处理器将网络字节表示作为本地整数比较时，字节的重要性与 IPv4 点分顺序不同；因此前置网段检查通过后，最后的原始数值比较仍可失败。

## 5. 实际结果

```text
range 192.168.1.250..192.168.2.10; candidate=192.168.2.1; result=0
```

| 观察项 | 期望 | 实际 |
| --- | --- | --- |
| 是否同属 `/16` | 是 | 生产函数的前置检查通过 |
| 是否位于配置闭区间 | 是 | 是（按 IPv4 语义） |
| `IpInRange` 返回 | `DHCP_TRUE` | 0 (`DHCP_FALSE`) |

## 6. 结论与边界

本次结果在小端验证环境出现，证明范围顺序比较使用了错误表示。它不表示不同网段地址也应被接受；不同网段仍应由生产函数前置检查拒绝。等值比较也不一定表现出问题，需使用跨低位字节排序边界的正常范围。

## 7. 修复后的回归判定

将三个用于大小比较的地址先转换到主机序后：

- 本输入必须返回 `DHCP_TRUE`；
- 起点和终点本身必须返回 `DHCP_TRUE`；
- 紧邻范围外的地址必须返回 `DHCP_FALSE`；
- 在小端和大端构建上运行同一矩阵，结果必须一致。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 构造跨 `/24` 边界但同属 `/16` 的正常地址池输入 |
| `build.sh` | 编译生产地址工具与 driver |
| `output.txt` | 本次真实范围判断结果 |
