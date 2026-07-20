# WriteNdefTag 成功后向应用返回输入长度而非服务结果

以下“正文”是提交到 GitCode Issue 描述框的内容。

## 正文

## 问题概述

`WriteNdefTag` 的服务端处理函数已经取得真实业务结果 `ret`，但写入 IPC reply 的并不是 `ret`，而是调用方输入字符串的长度 `dataLen`。

客户端 `NfcTagProxy::WriteNdefTag` 将 reply 中的第一个整数直接解释为 `ErrCode` 并返回。只要实际写入成功且输入长度大于零，应用收到的就是非零长度值，而不是 `NFC_SUCCESS`。

例如，服务端真实结果为 `0`、输入长度为 `3` 时：

```text
service_result=0
proxy_result=3
```

## 问题详情

### 问题代码

服务端文件：`services/src/nfc_tag_stub.cpp`

```cpp
ErrCode NfcTagStub::OnWriteNdefTag(uint32_t code,
    MessageParcel &data, MessageParcel &reply)
{
    std::string dataToWrite;
    if (!data.ReadString(dataToWrite)) {
        return NFC_IPC_READ_FAILED;
    }

    int32_t dataLen = static_cast<int32_t>(dataToWrite.length());
    if (dataLen > NFC_TAG_MAX_LEN || dataLen <= 0) {
        return NFC_INVALID_PARAMETER;
    }

    ErrCode ret = WriteNdefTag(dataToWrite);
    reply.WriteInt32(dataLen);
    return ret;
}
```

`ret` 是真实服务操作的返回值，但 reply 写入的是无关的 `dataLen`。

客户端文件：`interfaces/inner_api/src/nfc_tag_proxy.cpp`

```cpp
ErrCode NfcTagProxy::WriteNdefTag(const std::string &tagData)
{
    // ...
    int error = Remote()->SendRequest(
        NFC_TAG_CMD_WRITE_NDEF_TAG, data, reply, option);
    if (error != ERR_NONE) {
        return NFC_IPC_SEND_FAILED;
    }

    return ErrCode(reply.ReadInt32());
}
```

proxy 没有第二个结果字段，也不会重新调用服务端。reply 中的第一个整数就是上层收到的最终结果。

### 相邻实现对比

同一 stub 中的 `OnWriteNdefData` 使用的是正确字段：

```cpp
ErrCode ret = WriteNdefData(dataToWrite);
reply.WriteInt32(static_cast<int32_t>(ret));
return ret;
```

因此 `OnWriteNdefTag` 与相邻写入接口的 reply 协议不一致。

### 正常调用链

```text
应用调用 JS writeNdefTag
  -> frameworks/js/napi/nfc_napi_adapter.cpp
  -> NfcTagClient::WriteNdefTag
  -> NfcTagProxy::WriteNdefTag
  -> SendRequest(NFC_TAG_CMD_WRITE_NDEF_TAG)
  -> NfcTagStub::OnRemoteRequest
  -> NfcTagStub::OnWriteNdefTag
  -> NfcTagService::WriteNdefTag
  -> NfcTagHdiAdapter::WriteNdefTag
  -> HDI 写入成功并返回 NFC_SUCCESS
  -> stub 将 dataLen 写入 reply
  -> proxy 将 dataLen 作为 ErrCode 返回
  -> JS NAPI 将非零结果转换为业务错误
```

NAPI 层对非零结果的处理如下：

```cpp
if (context->errorCode_ == NFC_SUCCESS) {
    context->result_ = CreateUndefined(context->env_);
} else {
    int businessCode = FormatErrorCode(context->errorCode_);
    context->result_ = GenerateBusinessError(
        context->env_, businessCode, BuildErrorMessage(businessCode));
}
```

相关位置：

- `frameworks/js/napi/nfc_napi_adapter.cpp:98-147`
- `interfaces/inner_api/src/nfc_tag_client.cpp:131-140`
- `interfaces/inner_api/src/nfc_tag_proxy.cpp:111-140`
- `services/src/nfc_tag_stub.cpp:36-68`
- `services/src/nfc_tag_stub.cpp:96-110`
- `services/src/nfc_tag_service.cpp:192-199`

## 触发条件

1. NFC Tag 服务可用，调用方通过正常 `writeNdefTag` 接口发起写入。
2. 输入长度满足 `0 < dataLen <= NFC_TAG_MAX_LEN`。
3. 当前 Tag 和输入内容使服务端 `WriteNdefTag` 返回 `NFC_SUCCESS`。
4. 调用方依据接口返回结果判断写入是否完成。

问题发生在成功返回路径，不需要构造异常 IPC 数据。

## 验证结果

最小联调使用生产 `NfcTagProxy` 与生产 `NfcTagStub`。测试服务仅提供一个始终返回 `NFC_SUCCESS` 的 `WriteNdefTag` 实现，用于隔离并验证 reply 字段传递；请求与 reply 的序列化、分发和解析均来自目标仓库。

输入：

```text
data = "abc"
dataLen = 3
service return = NFC_SUCCESS (0)
```

实际输出：

```text
service_result=0 proxy_result=3 expected=0
```

该联调验证的是 IPC 返回协议。真实设备上的触发条件是一次正常成功的 NDEF 写入；只要服务返回 `NFC_SUCCESS`，当前 stub 都会把非零输入长度返回给调用方。

## 影响分析

- 成功写入会被应用侧误判为失败。
- 返回值随输入长度变化，不再代表服务端执行结果。
- JS 接口会将非零结果转换为业务错误。
- 用户可能看到失败提示，即使 Tag 写入已经完成。
- 上层若根据非零结果重试，可能对同一 Tag 重复执行写入。

本条只讨论成功后结果失真的路径，不包含空输入、超长输入或读取失败分支。

## 修复建议

服务端 reply 应写入真实业务返回值：

```cpp
ErrCode ret = WriteNdefTag(dataToWrite);
reply.WriteInt32(static_cast<int32_t>(ret));
return ret;
```

如果协议确实需要返回写入长度，应增加独立字段，并同步更新 proxy；不能复用结果码字段。

## 回归测试建议

1. 服务端返回 `NFC_SUCCESS`，输入为多个不同的合法非零长度，proxy 均应返回 `NFC_SUCCESS`。
2. 服务端返回非零结果，proxy 应返回同一结果。
3. JS `writeNdefTag` 成功路径应完成而不产生业务错误。
4. 空输入与超长输入应保持现有参数校验行为。

## 涉及文件

- `services/src/nfc_tag_stub.cpp`
- `interfaces/inner_api/src/nfc_tag_proxy.cpp`
- `interfaces/inner_api/src/nfc_tag_client.cpp`
- `frameworks/js/napi/nfc_napi_adapter.cpp`
