# 分析溯源：CWE-822 — IPC 消息中读取不可信函数指针直接调用

## 1. 检测引擎

| 项目 | 值 |
|------|---|
| 分析引擎 | `taint_flow_analysis` |
| 规约 ID | `DF-06-A1` |
| 规约类型 | TaintFlowSpec (must_not_reach) |
| 知识库文件 | `knowledge/root_causes/DF-06_untrusted_deserialization.yaml` |
| 候选生成器 | `spec_candidate_generator.py` |
| 优先级评分器 | `CandidatePrioritizer` |

## 2. 知识库 Evidence — 规约来源

本规约的 source/sink pattern 来源于 CVE-2024-29074（telephony_cellular_call）：

```yaml
# knowledge/root_causes/DF-06_untrusted_deserialization.yaml — evidence 节选
evidence:
- cve_id: CVE-2024-29074
  affected_repo: telephony_cellular_call
  description: IPC原始数据不安全反序列化，reinterpret_cast直接转换
  source_patterns:
  - ReadRawData
  - ReadBuffer
  sink_patterns:
  - reinterpret_cast
  - '*Stub::On*Request'
  sanitizer_patterns: []   # 无已知 sanitizer
  root_cause: DF-06        # Untrusted deserialization
```

**学到的模式**：从 IPC 缓冲区读取的原始数据被直接 `reinterpret_cast` 为结构体/指针使用，攻击者可构造恶意 IPC 数据控制程序行为。

## 3. 泛化后的规约定义

从 CVE-2024-29074 的 pattern 泛化，增加 `ReadPointer` 和函数指针调用作为更极端的变体：

```yaml
# DF-06-A1 — TaintFlowSpec 定义
analysis_approaches:
- approach_id: DF-06-A1
  engine: taint_flow_analysis
  spec_type: TaintFlowSpec
  check_mode: must_not_reach
  source_patterns:
  - category: ipc_raw_read
    patterns:
    - ReadPointer           # 直接读取指针值
    - ReadRawData           # 读取原始字节
    - ReadBuffer            # 读取缓冲区
    description: IPC functions that read raw/untyped data from message
  sink_patterns:
  - category: unsafe_cast_or_call
    patterns:
    - reinterpret_cast      # 不安全类型转换
    - '((StubFunc)*)(*)' # 函数指针调用
    - ProcCbHook            # 回调分发器
    description: Unsafe type cast or indirect function call
  sanitizer_patterns: []     # 无有效 sanitizer（非零检查不算）
  violation: "Untrusted IPC data reaches unsafe type cast / function pointer invocation"
```

**规约语义**：TaintFlowSpec — must_not_reach（从不可信 IPC 数据到函数指针调用的路径**不应存在**）

## 4. 候选匹配过程

`spec_candidate_generator.py` 扫描 `security_device_auth` 程序模型：

| 步骤 | 匹配内容 | 匹配方式 |
|------|---------|---------|
| 1. Source 匹配 | `data.ReadPointer()` in `StubDevAuthCb::OnRemoteRequest` | 精确匹配 `ReadPointer` in `ipc_raw_read` category |
| 2. Sink 匹配 | `reinterpret_cast<bool (*)(...)>(params.cbHook)` in `OnTransmitStub` | 精确匹配 `reinterpret_cast` in `unsafe_cast_or_call` category |
| 3. 路径追踪 | `ReadPointer` → `cbHook` → `DoCallBack` → `ProcCbHook` → `OnTransmitStub` → `reinterpret_cast` → 调用 | 完整污点传播路径 |
| 4. Sanitizer 检查 | `cbHook == 0x0` 仅检查非零 | 不构成有效 sanitizer（非零 ≠ 合法地址） |
| 5. 生成候选 | `StubDevAuthCb::OnRemoteRequest` → `ProcCbHook` 标记为 violation candidate | — |

## 5. 候选评分（CandidatePrioritizer）

| 评分因子 | 分值 | 说明 |
|---------|-----|------|
| graph_verdict=violation | +5 | 图分析确认从 ReadPointer 到 reinterpret_cast 的完整路径 |
| IPC 可达 | +3 | 通过 DEV_AUTH_CALLBACK_REQUEST IPC 直接触达 |
| spec_kind=taint_flow | +3 | TaintFlowSpec 权重 |
| 存在 taint path | +2 | 明确的 6 步污点传播链 |
| IPC pattern 匹配 | +1 | ReadPointer 精确匹配 IPC 读取模式 |
| **总分** | **14** | 远超阈值 ≥3，进入深度分析 |

## 6. LLM 属性推理验证

```
候选: StubDevAuthCb::OnRemoteRequest → ProcCbHook (ipc_callback_stub.cpp:55-80)
  ├─ 输入：
  │   ├─ 函数源码（OnRemoteRequest + DoCallBack + ProcCbHook + OnTransmitStub）
  │   ├─ 规约定义（DF-06-A1 TaintFlowSpec must_not_reach）
  │   ├─ 历史证据（CVE-2024-29074 的 ReadRawData + reinterpret_cast 模式）
  │   └─ 角色语义：
  │       - source = "从 IPC 消息中读取的原始数据/指针值"
  │       - sink = "将数据作为函数指针调用或不安全类型转换"
  │       - sanitizer = "无（非零检查不构成地址合法性验证）"
  │
  ├─ 首轮判定：VIOLATION
  │   理由：ReadPointer(data) 读取攻击者完全控制的 uintptr_t 值，
  │         经 DoCallBack → ProcCbHook → OnTransmitStub 传递后，
  │         通过 reinterpret_cast 转为函数指针并直接调用。
  │         且所有 15 个桩函数标注 __attribute__((no_sanitize("cfi")))，
  │         编译器控制流完整性保护被显式禁用。
  │
  └─ 二轮（对抗性验证）：VIOLATION（维持）
      对抗性问题："cbHook == 0x0 检查是否足以阻止攻击？"
      回答：否 — 非零不等于合法函数地址，攻击者选择任何非零值即可绕过
      对抗性问题："IPC 权限是否限制了攻击面？"
      回答：需要 TOKEN_NATIVE，但非 root — 本地提权场景可利用
      最终裁决：CONFIRMED VIOLATION
```

## 7. 模式对比

| 维度 | CVE-2024-29074（已知） | OH-2026-DEVAUTH-PTR-001（新发现） |
|------|----------------------|-------------------------------|
| 组件 | telephony_cellular_call | security_device_auth |
| Source | `ReadRawData()` 读取原始缓冲 | `ReadPointer()` 读取原始 uintptr_t |
| Sink | `reinterpret_cast` 为结构体 | `reinterpret_cast` 为函数指针并直接调用 |
| Sanitizer | 无 | 仅 `cbHook == 0x0`（无效） |
| 严重程度 | 类型混淆 / 越界读 | **任意代码执行** |
| 加重因素 | — | 15 个桩函数 CFI 显式禁用 |

## 8. 结论

`taint_flow_analysis` 引擎通过 `DF-06-A1` 规约，将 CVE-2024-29074 的 `ReadRawData → reinterpret_cast` 模式泛化后，在 `security_device_auth` 中发现了更极端的变体 — 不仅是数据类型转换，而是直接将 IPC 值作为函数指针调用。候选评分 14 分（最高级别），LLM 双轮验证一致确认。泛化后的规约覆盖了原始 CVE 未涉及的函数指针注入攻击面。
