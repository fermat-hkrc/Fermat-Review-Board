# 分析溯源：CWE-862 — RESTORE_CODE 路径跳过权限检查

## 规约来源

### 源 CVE：CVE-2022-42488（startup_init_lite）+ CVE-2022-38700（multimedia_camera_framework）

两个高危权限绕过漏洞共享同一缺陷模式：`OnRemoteRequest` 中存在分支路径直达业务方法，跳过了 `CheckPermission*` 权限验证链。

- **CVE-2022-42488**：参数服务缺少权限校验，任意应用可修改系统参数（CVSS 8.4）
- **CVE-2022-38700**：相机服务权限绕过，应用可未经授权访问摄像头（CVSS 8.8）

**从这两个 CVE 学到的模式**：OpenHarmony IPC 服务的标准安全架构是 `OnRemoteRequest → CheckPermission → 业务处理`。当某个请求分发路径跳过 `CheckPermission*` 直接到达业务方法时，构成权限绕过。

## 泛化后的规约

```yaml
# AC-TAINT-A1: Missing Authorization on IPC Path
TaintFlowSpec:
  sources:
  - category: ipc_entry
    patterns:
    - '*Stub::OnRemoteRequest'
    - '*Service::OnRemoteRequest'
  sinks:
  - category: protected_operation
    patterns:
    - Execute*Cmd
    - Open*
    - Set*
    - Reload*Db
  sanitizers:
  - category: permission_check
    patterns:
    - CheckPermission*
    - VerifyAccessToken*
    - GetCallingUid*
  check_mode: must_pass_through
  violation: "IPC request reaches protected operation without passing through permission check"
```

**规约类型**：TaintFlowSpec — must_pass_through（请求到达 sink 前必须经过权限检查 sanitizer）

## 模式对比

| 维度 | CVE-2022-42488 | CVE-2022-38700 | OH-2026-DEVAUTH-RESTORE-001 |
|------|---------------|---------------|---------------------------|
| 组件 | startup_init_lite | multimedia_camera | security_device_auth |
| 入口 | OnRemoteRequest | OnRemoteRequest | OnRemoteRequest |
| 直达 Sink | SetParameter | OpenCamera | ExecuteAccountAuthCmd |
| 缺失 Sanitizer | CheckParamPermission | CheckPermission | CheckPermission |
| 影响 | 修改系统参数 | 未授权访问摄像头 | 重置账户认证数据 |

## 候选匹配过程

1. `ServiceDevAuth::OnRemoteRequest` 匹配 source（glob `*Service::OnRemoteRequest`）
2. 追踪 `isRestoreCall == true` 分支 → `HandleRestoreCall` → `ExecuteAccountAuthCmd` 匹配 sink
3. 该路径无 `CheckPermission*` sanitizer → 违反 must_pass_through
4. 对照组：同一 `OnRemoteRequest` 的正常路径 `HandleDeviceAuthCall` 正确调用 `CheckPermission` → 确认不是设计意图
5. LLM 双轮验证一致判定 violation → 确认漏洞

## 结论

`device_auth` 的 `HandleRestoreCall` 路径与 CVE-2022-42488、CVE-2022-38700 共享完全相同的缺陷模式：IPC 分发器中存在特殊分支绕过权限检查直达特权操作。AC-TAINT 规约从两个已知 CVE 中提取的 `must_pass_through` 模式，在第三个组件中成功发现了同构问题，证明权限检查缺失在 OpenHarmony 中是系统性问题。
