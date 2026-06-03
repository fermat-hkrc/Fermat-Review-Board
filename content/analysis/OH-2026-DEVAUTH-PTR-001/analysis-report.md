# 分析溯源：CWE-822 — IPC 消息中读取不可信函数指针直接调用

## 规约来源

### 源 CVE：CVE-2024-29074（telephony_cellular_call）

Telephony 组件从 IPC 缓冲区通过 `ReadRawData` / `ReadBuffer` 读取原始数据，直接 `reinterpret_cast` 为结构体使用，攻击者可构造恶意数据控制程序行为。

**从该 CVE 学到的模式**：从 IPC 缓冲区读取的原始数据被直接类型转换使用，无任何验证。攻击者控制 IPC 消息内容即可控制转换后的值。

## 泛化后的规约

```yaml
# DF-06-A1: Untrusted Pointer via IPC Deserialization
TaintFlowSpec:
  sources:
  - ReadPointer
  - ReadRawData
  - ReadBuffer
  sinks:
  - reinterpret_cast
  - ProcCbHook
  - ((StubFunc)cbHook)(params)
  sanitizers: []
  check_mode: must_not_reach
  violation: "Untrusted IPC data reaches unsafe type cast / function pointer invocation"
```

**规约类型**：TaintFlowSpec — must_not_reach（不可信数据不应到达函数指针调用点）

## 模式对比

| 维度 | CVE-2024-29074（已知） | OH-2026-DEVAUTH-PTR-001（新发现） |
|------|----------------------|-------------------------------|
| 组件 | telephony_cellular_call | security_device_auth |
| Source | `ReadRawData()` 读取原始缓冲 | `ReadPointer()` 读取原始 uintptr_t |
| Sink | `reinterpret_cast` 为结构体 | `reinterpret_cast` 为函数指针并直接调用 |
| Sanitizer | 无 | 仅 `cbHook == 0x0` 非零检查（无效） |
| 严重程度 | 类型混淆 / 越界读 | **任意代码执行** |
| 加重因素 | — | 15 个桩函数均标注 `no_sanitize("cfi")` |

## 候选匹配过程

1. `StubDevAuthCb::OnRemoteRequest` 中 `data.ReadPointer()` 精确匹配 source pattern
2. 追踪数据流：`cbHook` → `DoCallBack` → `ProcCbHook` → `reinterpret_cast<...>(params.cbHook)` → 直接调用
3. 路径上 `cbHook == 0x0` 不构成有效 sanitizer（非零 ≠ 合法地址）→ 违反 must_not_reach
4. LLM 双轮验证一致判定 violation → 确认漏洞

## 结论

`device_auth` 中的 `ReadPointer` → `reinterpret_cast` → 函数调用是 CVE-2024-29074 中 `ReadRawData` → `reinterpret_cast` 模式的更极端变体。知识库将该模式泛化后，不仅覆盖了原始的数据类型混淆场景，还发现了直接函数指针注入这一更严重的攻击面。
