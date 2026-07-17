# 验证报告

## 验证范围

- 生产源文件：`services/src/nfc_tag_stub.cpp` 与 `interfaces/inner_api/src/nfc_tag_proxy.cpp`
- 入口：`NfcTagProxy::WriteNdefTag`
- 方法：编译真实 stub、真实 proxy 和最小 IPC 边界替身，再由 driver 发起一次有效 NDEF 写入调用。

## 触发链

1. driver 构造非空、有效长度的 NDEF 数据。
2. 真实 proxy 将请求发送到真实 stub。
3. 服务实现返回成功值 `0`。
4. stub 将 `dataLen` 写入 reply，真实 proxy 将该整数读作 `ErrCode`。

## 判定条件

服务结果应与调用方结果相同。实际结果为 `service_result=0`、`proxy_result=3`，说明同一 IPC reply 字段在两端被赋予了不同含义。

## 边界说明

替身仅覆盖 IPC 框架边界；业务调用、序列化、reply 写入和读取均来自生产源文件。该验证确认正常写入路径上的返回值不一致。
