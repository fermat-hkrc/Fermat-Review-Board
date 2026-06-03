# 分析溯源：CWE-862 — RESTORE_CODE 路径跳过权限检查

## 1. 检测引擎

| 项目 | 值 |
|------|---|
| 分析引擎 | `taint_flow_analysis` |
| 规约 ID | `AC-TAINT-A1` |
| 规约类型 | TaintFlowSpec (must_pass_through) |
| 知识库文件 | `knowledge/root_causes/AC-01_missing_authorization.yaml` |
| 候选生成器 | `spec_candidate_generator.py` |
| 优先级评分器 | `CandidatePrioritizer` |

## 2. 知识库 Evidence — 规约来源

本规约的 source/sink/sanitizer 三元组来源于两个高危权限绕过 CVE：

```yaml
# knowledge/root_causes/AC-01_missing_authorization.yaml — evidence 节选
evidence:
- cve_id: CVE-2022-42488
  affected_repo: startup_init_lite
  description: 参数服务缺少权限校验，任意应用可修改系统参数
  source_patterns:
  - '*Stub::OnRemoteRequest'
  - SetParameter
  sink_patterns:
  - SetParameter
  - system property write
  sanitizer_patterns:
  - CheckParamPermission*
  - VerifyAccessToken*
  cvss: 8.4

- cve_id: CVE-2022-38700
  affected_repo: multimedia_camera_framework
  description: 相机服务权限绕过，应用可未经授权访问摄像头
  source_patterns:
  - '*Stub::OnRemoteRequest'
  - OpenCamera
  sink_patterns:
  - OpenCamera
  sanitizer_patterns:
  - CheckPermission*
  - VerifyClient*
  cvss: 8.8
```

**学到的模式**：OpenHarmony IPC 服务的标准安全架构是 `OnRemoteRequest → CheckPermission → 业务处理`。当某个请求分发路径跳过 `CheckPermission*` 直接到达业务方法时，构成权限绕过。

## 3. 泛化后的规约定义

从两个 CVE 中提取的 sanitizer 模式被合并为统一的权限检查 category：

```yaml
# AC-TAINT-A1 — TaintFlowSpec 定义
analysis_approaches:
- approach_id: AC-TAINT-A1
  engine: taint_flow_analysis
  spec_type: TaintFlowSpec
  check_mode: must_pass_through
  source_patterns:
  - category: ipc_entry
    patterns:
    - '*Stub::OnRemoteRequest'        # 所有 IPC Stub 入口
    - '*Service::OnRemoteRequest'      # 所有 IPC Service 入口
    description: IPC request entry points
  sink_patterns:
  - category: protected_operation
    patterns:
    - Execute*Cmd                      # 执行命令类操作
    - Open*                            # 打开资源类操作
    - Set*                             # 设置/修改类操作
    - Reload*Db                        # 数据库重载类操作
    - Start*                           # 启动类操作
    description: Operations that require authorization
  sanitizer_patterns:
  - category: permission_check
    patterns:
    - CheckPermission*                 # ← 从 CVE-2022-42488/38700 提取
    - VerifyAccessToken*
    - GetCallingUid*
    - CheckParamPermission*
    description: Authorization verification functions
  violation: "IPC request reaches protected operation without passing through permission check"
```

**规约语义**：TaintFlowSpec — must_pass_through（从 IPC 入口到达 protected_operation 的路径上**必须经过**权限检查 sanitizer）

## 4. 候选匹配过程

`spec_candidate_generator.py` 扫描 `security_device_auth` 程序模型：

| 步骤 | 匹配内容 | 匹配方式 |
|------|---------|---------|
| 1. Source 匹配 | `ServiceDevAuth::OnRemoteRequest` | 后缀匹配 glob `*Service::OnRemoteRequest` |
| 2. Sink 匹配 | `ExecuteAccountAuthCmd(osAccountId, UPGRADE_DATA, ...)` | 前缀匹配 `Execute*Cmd` in `protected_operation` |
| 3. 路径追踪 | `OnRemoteRequest` → `isRestoreCall==true` → `HandleRestoreCall` → `ExecuteAccountAuthCmd` | 分支路径追踪 |
| 4. Sanitizer 检查 | 该路径上无 `CheckPermission*` / `VerifyAccessToken*` | 无匹配 → 违反 must_pass_through |
| 5. 对照验证 | 正常路径 `HandleDeviceAuthCall` → `CheckPermission(methodId)` | 同一入口的其他分支正确包含 sanitizer |
| 6. 生成候选 | `HandleRestoreCall` 路径标记为 violation candidate | — |

## 5. 候选评分（CandidatePrioritizer）

| 评分因子 | 分值 | 说明 |
|---------|-----|------|
| graph_verdict=violation | +5 | 图分析确认 Restore 分支缺少 CheckPermission |
| IPC 可达 | +3 | 通过 code=14701 IPC 直接触达 |
| spec_kind=taint_flow | +3 | TaintFlowSpec 权重 |
| 存在 taint path | +2 | 从 OnRemoteRequest 到 ExecuteAccountAuthCmd 的明确路径 |
| IPC pattern 匹配 | +1 | OnRemoteRequest 匹配 IPC 入口模式 |
| **总分** | **14** | 远超阈值 ≥3，进入深度分析 |

## 6. LLM 属性推理验证

```
候选: ServiceDevAuth::OnRemoteRequest → HandleRestoreCall (ipc_dev_auth_stub.cpp:320-335)
  ├─ 输入：
  │   ├─ 函数源码（OnRemoteRequest + HandleRestoreCall + HandleDeviceAuthCall）
  │   ├─ 规约定义（AC-TAINT-A1 TaintFlowSpec must_pass_through）
  │   ├─ 历史证据（CVE-2022-42488 的 SetParameter 无检查 + CVE-2022-38700 的 OpenCamera 无检查）
  │   └─ 角色语义：
  │       - source = "IPC 请求入口（OnRemoteRequest）"
  │       - sink = "需要授权的特权操作（ExecuteAccountAuthCmd, ReloadOsAccountDb）"
  │       - sanitizer = "权限验证函数（CheckPermission, VerifyAccessToken）"
  │
  ├─ 首轮判定：VIOLATION
  │   理由：OnRemoteRequest 中 isRestoreCall==true 分支直接调用 HandleRestoreCall，
  │         HandleRestoreCall 执行 ExecuteAccountAuthCmd + ReloadOsAccountDb 两个特权操作，
  │         但整个路径上无任何 CheckPermission* 调用。
  │         对比：同一函数的正常路径 HandleDeviceAuthCall 在 line 277 正确调用了 CheckPermission。
  │
  └─ 二轮（对抗性验证）：VIOLATION（维持）
      对抗性问题："接口令牌 'OHOS.Updater.RestoreData' 是否构成充分的权限控制？"
      回答：否 — 接口令牌是编译时静态常量，可从公开共享库逆向获取，
            不等同于运行时权限验证（无 GetCallingTokenID、无 APL 等级检查）
      对抗性问题："该路径是否仅在 OTA 升级等受限场景调用？"
      回答：无代码约束 — 任何能发送 IPC 的进程只要知道 code=14701 + 令牌字符串即可触发
      最终裁决：CONFIRMED VIOLATION
```

## 7. 模式对比

| 维度 | CVE-2022-42488 | CVE-2022-38700 | OH-2026-DEVAUTH-RESTORE-001 |
|------|---------------|---------------|---------------------------|
| 组件 | startup_init_lite | multimedia_camera | security_device_auth |
| 入口 | OnRemoteRequest | OnRemoteRequest | OnRemoteRequest |
| 直达 Sink | SetParameter | OpenCamera | ExecuteAccountAuthCmd + ReloadOsAccountDb |
| 缺失 Sanitizer | CheckParamPermission | CheckPermission | CheckPermission |
| 影响 | 修改系统参数 | 未授权访问摄像头 | 重置账户认证数据库 |
| CVSS | 8.4 | 8.8 | — |

## 8. 结论

`taint_flow_analysis` 引擎通过 `AC-TAINT-A1` 规约，将 CVE-2022-42488 和 CVE-2022-38700 中"`OnRemoteRequest` 路径缺少 `CheckPermission`"的模式形式化为 `must_pass_through` 约束后，在 `security_device_auth` 的 `HandleRestoreCall` 路径中发现了完全相同的缺陷。候选评分 14 分，LLM 双轮验证一致确认。对抗性验证排除了"接口令牌足够安全"的反论。三个组件共享同一缺陷模式，证明权限检查缺失在 OpenHarmony 中是系统性问题。
