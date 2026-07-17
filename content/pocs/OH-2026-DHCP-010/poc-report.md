# 验证报告：sendto 失败未传递为 DHCP Server 发送失败

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_dhcp` `f705027a799e8fe915417026b5c9d90628c40793` |
| 生产入口 | `TransmitOfferOrAckPacket` |
| 生产文件 | `services/dhcp_server/src/dhcp_s_server.cpp` |
| 输入 | 一份长度 300 的正常待发送 DHCP reply |
| 故障模型 | 系统 `sendto` 返回 `-1` |
| 判定标准 | 发送失败时该函数必须返回 `RET_FAILED` |

## 2. 使用的生产代码与替换边界

`harness.cpp` 通过 include path 直接包含生产 `dhcp_s_server.cpp`，因此被调用的 `TransmitOfferOrAckPacket` 函数体、`sendto` 返回值检查和返回码均为目标仓库代码。

只有系统调用边界通过链接器 `--wrap=sendto` 变为固定 `-1`：

```cpp
extern "C" ssize_t __wrap_sendto(...)
{
    return -1;
}
```

其余少量函数用于满足未执行分支的链接依赖；driver 选择 `broadCastFlagEnable = 0`，使生产函数进入直接 `sendto` 路径。

## 3. 输入构造

```cpp
ServerContext instance {};
instance.serverFd = 7;
instance.broadCastFlagEnable = 0;

DhcpServerContext context {};
context.instance = &instance;

DhcpMsgInfo reply {};
reply.length = 300;
return TransmitOfferOrAckPacket(&context, &reply);
```

`reply.length` 为正且低于生产代码允许的最大值，避免测试落入零长度或参数校验路径。

## 4. 完整触发链

```text
driver
  → production TransmitOfferOrAckPacket(&context, &reply)
    → 选择 broadcast sendto 路径
    → __wrap_sendto(...) = -1
    → if (!ret)                              // !(-1) == false
    → 跳过 RET_FAILED 分支
    → return RET_SUCCESS (0)
```

同一 `if (!ret)` 模式还存在于生产 `SendDhcpNak`，本 driver 聚焦于 OFFER/ACK 公共发送函数的实际返回行为。

## 5. 实际结果

```text
sendto_return=-1 handler_result=0 expected_failure
```

| 观察项 | 期望 | 实际 |
| --- | ---: | ---: |
| 系统发送结果 | -1 | -1 |
| production handler 结果 | 非零 `RET_FAILED` | 0 `RET_SUCCESS` |

driver 在 handler 正确报告失败时返回非零；当前退出成功表示错误检查被复现。

## 6. 结论与边界

该验证证明 `sendto=-1` 时的返回值误判。它不依赖任何 malformed DHCP packet，也不模拟网络协议状态。具体的真实失败原因可为套接字、接口或内核错误；共同点是 POSIX 返回负值。

## 7. 修复后的回归判定

- OFFER/ACK 路径在 `sendto=-1` 时返回 `RET_FAILED`；
- NAK 路径在 `sendto=-1` 时也返回 `RET_FAILED`；
- 正常返回 `reply.length` 时返回成功；
- 如平台允许正数短发送，必须报告失败或明确处理，不能只判断零。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `harness.cpp` | 包含生产发送函数并仅包装 `sendto` 失败边界 |
| `driver.cpp` | 设置正常 send context 并输出生产函数返回值 |
| `build.sh` | 带 `--wrap=sendto` 的完整编译和链接链 |
| `output.txt` | 本次发送失败与 handler 返回值 |
