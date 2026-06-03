# 分析溯源：CWE-476 — IPC 反序列化返回值被丢弃导致空指针解引用

## 规约来源

### 源 CVE：CVE-2023-24465（communication_wifi）

WLAN 组件服务接口接受外部数据时，`ReadCString` 在数据缺失时返回 NULL，调用方未检查直接赋给 `std::string`，触发空指针解引用。

**从该 CVE 学到的模式**：IPC 反序列化函数在数据缺失时返回 NULL/错误码，如果调用方不检查返回值就使用输出数据，则触发空指针解引用。

## 泛化后的规约

```yaml
# MS-06-A1: Null Pointer via Discarded Error Return
source_patterns:
- category: discarded_error_return
  patterns:
  - (void)GetIpcRequestParamByType
  - (void)GetAndValNullParam
- category: ipc_deserialization
  patterns:
  - ReadCString
  - ReadString*
  - ReadRemoteObject*
sink_patterns:
- category: member_access
  patterns:
  - ->member
  - ->method()
sanitizer_patterns:
- if (ptr != nullptr)
- if (ptr != NULL)
- if (!ptr) return
```

**规约类型**：TypestateSpec — 指针在 `null` 状态下被解引用（`null → in_use` 是 forbidden transition）

## 模式对比

| 维度 | CVE-2023-24465（已知） | OH-2026-DEVAUTH-001（新发现） |
|------|----------------------|---------------------------|
| 组件 | communication_wifi | security_device_auth |
| Source | `ReadCString()` 返回 nullptr | `GetIpcRequestParamByType()` 返回错误码 |
| 缺陷模式 | 返回值直接赋给 std::string | 返回值被 `(void)` 丢弃，输出指针保持 NULL |
| Sink | std::string 构造函数解引用 | 回调函数解引用 data 参数 |
| 修复 | `if (str != nullptr)` | `if (ret != HC_SUCCESS) return` |
| 影响范围 | 1 个函数 | 12 个回调桩函数 |

## 候选匹配过程

1. `OnTransmitStub` 中 `(void)GetIpcRequestParamByType(...)` 精确匹配 `discarded_error_return` source pattern
2. `callback.onTransmit(requestId, data, dataLen)` 匹配 sink pattern（`->method()`）
3. 路径上无 `if (data != NULL)` sanitizer → 生成候选
4. LLM 双轮验证一致判定 violation → 确认漏洞

## 结论

`device_auth` 中的 `(void)GetIpcRequestParamByType` 是 CVE-2023-24465 中 `ReadCString` 返回 NULL 模式的同构变体。知识库的 `discarded_error_return` category 正是从该 CVE 的修复 diff 中提取的经验，在新组件中成功发现了同类问题。
