# 验证报告：WriteNdefTag reply 字段含义不一致

## 1. 验证目标与判定标准

| 项目 | 内容 |
| --- | --- |
| 目标仓库版本 | `communication_connected_nfc_tag` `f6e27a0939cb605da53430b0249811d453604e21` |
| 生产入口 | `NfcTagProxy::WriteNdefTag` |
| 服务端处理 | `NfcTagStub::OnWriteNdefTag` |
| 正常输入 | 非空字符串 `"abc"`，长度为 3 |
| 判定标准 | 服务实现返回 `NFC_SUCCESS` 时，proxy 也必须返回 `NFC_SUCCESS` |

验证不检查 Tag 硬件本身。它检查已经成功完成的业务调用如何通过生产 IPC stub 和 proxy 把结果返回给调用方。

## 2. 使用的生产代码与边界替身

构建链接以下未改写的生产翻译单元：

- `services/src/nfc_tag_stub.cpp`
- `interfaces/inner_api/src/nfc_tag_proxy.cpp`

`driver.cpp` 只做两件事：提供一个 `WriteNdefTag` 始终返回 `NFC_SUCCESS` 的最小服务实现，以及从生产 `NfcTagProxy` 发起正常写入请求。测试目录中的 IPC 适配头只提供 `MessageParcel` / `IRemoteObject` 运行边界，使真实 proxy 能把请求送入真实 stub；它不实现或复制这两个生产方法的函数体。

## 3. 输入构造

```cpp
auto service = std::make_shared<TestTagService>();
NfcTagProxy proxy(service);
const auto result = proxy.WriteNdefTag("abc");
```

`"abc"` 满足服务端 `0 < dataLen <= NFC_TAG_MAX_LEN` 的正常参数校验。服务实现的业务返回值固定为 `NFC_SUCCESS`，因而任何非零 client 结果都不能由业务失败解释。

## 4. 完整触发链

```text
driver.cpp
  → 生产 NfcTagProxy::WriteNdefTag("abc")
    → 写入 interface token 与字符串
    → SendRequest(NFC_TAG_CMD_WRITE_NDEF_TAG)
      → 生产 NfcTagStub::OnWriteNdefTag(...)
        → dataLen = 3
        → TestTagService::WriteNdefTag(...) = NFC_SUCCESS (0)
        → reply.WriteInt32(dataLen)             // 写入 3
    → reply.ReadInt32()
    → ErrCode(3)
```

关键点是服务业务函数的返回值已经是 0，而被写进 reply 的是独立的输入长度 3。

## 5. 实际结果

```text
service_result=0 proxy_result=3 expected=0
```

| 观察项 | 期望 | 实际 |
| --- | ---: | ---: |
| 服务业务结果 | 0 | 0 |
| 调用方收到的 proxy 结果 | 0 | 3 |
| 输入长度 | 3 | 3 |

driver 仅在 proxy 意外返回 0 时失败，因此该输出是实际观察到的不一致，而不是字符串匹配。

## 6. 结论与边界

该验证证明，正常且成功的 3 字节写入会在 IPC 返回路径中被转换为错误结果。它不声称空字符串或超长字符串也会触发：那些输入在 stub 的参数校验处提前返回，属于不同路径。

## 7. 修复后的回归判定

将 stub 改为 `reply.WriteInt32(static_cast<int32_t>(ret))` 后，保持相同 driver：

- `service_result` 必须仍为 0；
- `proxy_result` 必须变为 0；
- 对其他合法非零长度输入，proxy 结果不得随长度变化。

## 8. 文件说明

| 文件 | 用途 |
| --- | --- |
| `driver.cpp` | 可查看的最小正常调用方与成功服务实现 |
| `build.sh` | 编译生产 stub、生产 proxy 和 driver 的完整命令链 |
| `output.txt` | 本次执行的原始一行结果 |
