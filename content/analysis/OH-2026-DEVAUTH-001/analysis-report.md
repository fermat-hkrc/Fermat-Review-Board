# 分析溯源：CWE-476 — IPC 回调参数提取失败导致空指针解引用

## 1. 检测引擎

| 项目 | 值 |
|------|---|
| 分析引擎 | `null_analysis` |
| 规约 ID | `MS-06-A1` |
| 规约类型 | TypestateSpec |
| 知识库文件 | `knowledge/root_causes/MS-06_null_pointer_deref.yaml` |
| 候选生成器 | `spec_candidate_generator.py` |
| 优先级评分器 | `CandidatePrioritizer` |

## 2. 知识库 Evidence — 规约来源

本规约的 source pattern 来源于 CVE-2023-24465（communication_wifi）：

```yaml
# knowledge/root_causes/MS-06_null_pointer_deref.yaml — evidence 节选
evidence:
- cve_id: CVE-2023-24465
  affected_repo: communication_wifi
  description: WLAN组件服务接口接受外部数据时存在空指针引用
  source_patterns:
  - ReadCString              # IPC 反序列化函数可返回 NULL
  sink_patterns:
  - std::string constructor  # 解引用 NULL 指针
  sanitizer_patterns:
  - '!= nullptr'
```

**学到的模式**：IPC 反序列化函数（ReadCString、ReadString 等）在数据缺失时返回 NULL。如果调用方不检查返回值就使用输出数据，则触发空指针解引用。

## 3. 泛化后的规约定义

从 CVE-2023-24465 的修复 diff 中，提取并泛化为两个 source category：

```yaml
# MS-06-A1 — analysis_approaches 节选
analysis_approaches:
- approach_id: MS-06-A1
  engine: null_analysis
  pattern_type: null_check
  source_patterns:
  - category: ipc_deserialization
    patterns:
    - ReadCString
    - ReadString*
    - ReadRemoteObject*
    - ReadParcelable*
    - ReadBuffer*
    description: IPC deserialization functions that may return NULL for missing/invalid data
  - category: discarded_error_return
    patterns:
    - (void)GetIpcRequestParamByType    # ← CVE-2023-24465 同类模式的变体
    - (void)GetAndValNullParam
    description: Functions whose return value is discarded with (void) cast
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

**规约语义**：TypestateSpec — 指针在 `null` 状态下被解引用是 forbidden transition（`null → in_use`）

## 4. 候选匹配过程

`spec_candidate_generator.py` 扫描 `security_device_auth` 程序模型：

| 步骤 | 匹配内容 | 匹配方式 |
|------|---------|---------|
| 1. Source 匹配 | `(void)GetIpcRequestParamByType(...)` in `OnTransmitStub` | 精确匹配 `discarded_error_return` category |
| 2. Sink 匹配 | `onTransmitHook(requestId, data, dataLen)` | 匹配 `->method()` pattern |
| 3. Sanitizer 检查 | 路径上无 `if (data != NULL)` 检查 | 无匹配 → 缺失 sanitizer |
| 4. 生成候选 | `OnTransmitStub` 标记为 violation candidate | — |

## 5. 候选评分（CandidatePrioritizer）

| 评分因子 | 分值 | 说明 |
|---------|-----|------|
| graph_verdict=violation | +5 | 图分析确认 null→in_use 路径存在 |
| IPC 可达 | +3 | 通过 DEV_AUTH_CALLBACK_REQUEST IPC 接口暴露 |
| 存在 taint path | +2 | 从 GetIpcRequestParamByType 输出到回调参数的数据流 |
| spec_kind=typestate | +2 | 规约类型权重 |
| **总分** | **12** | 远超阈值 ≥3，进入深度分析 |

## 6. LLM 属性推理验证

```
候选: OnTransmitStub (ipc_adapt.c:479-497)
  ├─ 输入：
  │   ├─ 函数源码（完整 OnTransmitStub 实现）
  │   ├─ 规约定义（MS-06-A1 TypestateSpec）
  │   ├─ 历史证据（CVE-2023-24465 的 ReadCString 模式）
  │   └─ 角色语义：
  │       - source = "返回值被 (void) 丢弃的参数提取函数"
  │       - sink = "解引用或传入回调的指针参数"
  │       - sanitizer = "对指针的 NULL 检查"
  │
  ├─ 首轮判定：VIOLATION
  │   理由：GetIpcRequestParamByType 的返回值被 (void) 丢弃，
  │         当 PARAM_TYPE_COMM_DATA 不在 cache 中时返回 HC_ERROR，
  │         但 data 指针保持 NULL，直接传入 onTransmitHook 回调
  │
  └─ 二轮（对抗性验证）：VIOLATION（维持）
      对抗性问题："是否存在外部保证 cache 中一定包含 PARAM_TYPE_COMM_DATA？"
      回答：无 — IPC 消息内容由发送方控制，无强制约束
      最终裁决：CONFIRMED VIOLATION
```

## 7. 模式对比

| 维度 | CVE-2023-24465（已知） | OH-2026-DEVAUTH-001（新发现） |
|------|----------------------|---------------------------|
| 组件 | communication_wifi | security_device_auth |
| Source | `ReadCString()` 返回 nullptr | `GetIpcRequestParamByType()` 返回错误码被 (void) 丢弃 |
| 缺陷模式 | 返回值直接赋给 std::string | 返回值被丢弃，输出指针保持 NULL |
| Sink | std::string 构造函数 | 回调函数 onTransmitHook(data) |
| 修复 | `if (str != nullptr)` | `if (ret != HC_SUCCESS) return` |
| 影响范围 | 1 个函数 | 12 个回调桩函数（OnTransmitStub, OnSessKeyStub, ...） |

## 8. 结论

`null_analysis` 引擎通过 `MS-06-A1` 规约，将 CVE-2023-24465 的 `ReadCString` 返回 NULL 模式泛化为 `discarded_error_return` category 后，在 `security_device_auth` 的 12 个 IPC 回调桩函数中发现了同构问题。候选评分 12 分（远超阈值），LLM 双轮验证一致确认 violation。知识从 `communication_wifi` 成功迁移到 `device_auth`。
