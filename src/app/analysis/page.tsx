import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Analysis Methodology - Fermat Review Board",
  description:
    "How Fermat uses property modeling to extract vulnerability patterns from historical CVEs and discover new vulnerabilities",
};

export default function AnalysisPage() {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-white mb-2">
          Analysis Methodology
        </h1>
        <p className="text-[#a3a3a3] text-lg">
          性质建模（Property Modeling）是 Fermat 的核心分析方法。从已知 CVE 提取漏洞模式 → 泛化为形式化规约 → 用规约在新组件中发现同构漏洞。本页展示完整的端到端流程，以 device_auth 中发现的三个漏洞为实例。
        </p>
      </div>

      {/* Pipeline Overview */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          1. 端到端流程
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-sm text-[#a3a3a3]">
            <div className="space-y-1">
              <div className="text-white">{"知识库 (YAML)"}</div>
              <div className="text-[#737373]">{"    ↓ 从历史 CVE 提取 source/sink/sanitizer patterns"}</div>
              <div className="text-white">{"性质规约 (Spec)"}</div>
              <div className="text-[#737373]">{"    ↓ 泛化为 TaintFlowSpec / TypestateSpec / AssertionSpec"}</div>
              <div className="text-white">{"候选发现"}</div>
              <div className="text-[#737373]">{"    ↓ pattern matching + 污点流分析"}</div>
              <div className="text-white">{"属性推理验证"}</div>
              <div className="text-[#737373]">{"    ↓ LLM 双轮对抗性验证"}</div>
              <div className="text-green-400">{"确认的新漏洞 → PoC 验证 → 提单"}</div>
            </div>
          </div>
        </div>
        <div className="bg-[#141414] border border-blue-500/30 rounded-lg p-5">
          <p className="text-[#d4d4d4] text-sm">
            <strong className="text-blue-400">核心理念：</strong>安全漏洞存在可复现的结构化模式。同一类缺陷在不同组件中以相似形式出现。从已知漏洞中提取模式，形式化后可以自动发现尚未被报告的同类问题。
          </p>
        </div>
      </section>

      {/* Section 2: Knowledge Base */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          2. 知识库结构
        </h2>
        <p className="text-[#a3a3a3] mb-4">
          每个安全性质对应一个 YAML 文件，包含三个核心部分：
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div className="bg-[#141414] border border-[#262626] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-2">evidence</h3>
            <p className="text-[#a3a3a3] text-sm">历史漏洞实例（CVE、已确认案例），提供具体的 source/sink/sanitizer 模式</p>
          </div>
          <div className="bg-[#141414] border border-[#262626] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-2">analysis_approaches</h3>
            <p className="text-[#a3a3a3] text-sm">分析方法，定义如何将该类漏洞建模为形式化规约</p>
          </div>
          <div className="bg-[#141414] border border-[#262626] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-2">role_semantics</h3>
            <p className="text-[#a3a3a3] text-sm">对 source/sink/sanitizer 角色的语义定义，指导推理引擎判断边界情况</p>
          </div>
        </div>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6">
          <h3 className="text-[#d4d4d4] font-medium mb-3 text-sm">示例：MS-06_null_pointer_deref.yaml</h3>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3] overflow-x-auto">
            <div className="text-blue-400">{"analysis_approaches:"}</div>
            <div>{"- approach_id: MS-06-A1"}</div>
            <div>{"  engine: null_analysis"}</div>
            <div>{"  source_patterns:"}</div>
            <div>{"  - category: discarded_error_return"}</div>
            <div>{"    patterns:"}</div>
            <div>{"    - (void)GetIpcRequestParamByType"}</div>
            <div>{"    - (void)GetAndValNullParam"}</div>
            <div>{"  - category: ipc_deserialization"}</div>
            <div>{"    patterns:"}</div>
            <div>{"    - ReadCString"}</div>
            <div>{"    - ReadString*"}</div>
            <div>{"    - ReadRemoteObject*"}</div>
            <div>{"  sink_patterns:"}</div>
            <div>{"  - category: member_access"}</div>
            <div>{"    patterns:"}</div>
            <div>{"    - ->member"}</div>
            <div>{"    - ->method()"}</div>
            <div>{"  sanitizer_patterns:"}</div>
            <div>{"  - if (ptr != nullptr)"}</div>
            <div>{"  - if (ptr != NULL)"}</div>
          </div>
        </div>
      </section>

      {/* Section 3: Spec Types */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          3. 三种规约类型
        </h2>

        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-3">TaintFlowSpec — 数据流污点规约</h3>
          <p className="text-[#a3a3a3] text-sm mb-3">追踪不可信数据从 source 到 sink 的传播路径。两种检查模式：</p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3] mb-3">
            <div>{"┌──────────┐         ┌─────────────┐         ┌──────────┐"}</div>
            <div>{"│  Source  │ ──────→ │  Sanitizer  │ ──────→ │   Sink   │"}</div>
            <div>{"│ (污点源) │         │  (净化函数)  │         │ (危险操作) │"}</div>
            <div>{"└──────────┘         └─────────────┘         └──────────┘"}</div>
            <div className="mt-2 text-red-400">{"must_not_reach:    Source ──→ Sink 路径存在 = VIOLATION"}</div>
            <div className="text-amber-400">{"must_pass_through: Source ──→ Sink 缺少 Sanitizer = VIOLATION"}</div>
          </div>
          <p className="text-[#737373] text-xs">适用：不可信指针解引用（must_not_reach）、权限检查缺失（must_pass_through）</p>
        </div>

        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-3">TypestateSpec — 类型状态规约</h3>
          <p className="text-[#a3a3a3] text-sm mb-3">将对象生命周期建模为有限状态机，定义禁止的状态转换。</p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3]">
            <div>{"         malloc()          ->member         free()"}</div>
            <div>{"[null] ─────────→ [allocated] ────→ [in_use] ────→ [freed]"}</div>
            <div>{"  │                                                    │"}</div>
            <div className="text-red-400">{"  │  ->member (FORBIDDEN: null → in_use)               │"}</div>
            <div className="text-red-400">{"  └─ ─ ─ ─ ─ ─ VIOLATION ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘"}</div>
          </div>
          <p className="text-[#737373] text-xs mt-3">适用：空指针解引用（null→in_use）、UAF（freed→in_use）</p>
        </div>

        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6">
          <h3 className="text-white font-semibold mb-3">AssertionSpec — 支配关系规约</h3>
          <p className="text-[#a3a3a3] text-sm mb-3">验证 sanitizer 是否支配 sink（在所有路径上，sanitizer 都先于 sink 执行）。</p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3]">
            <div>{"              ┌─── path A: CheckPermission() → ExecuteCmd() ✓"}</div>
            <div>{"OnRemoteReq ──┤"}</div>
            <div className="text-red-400">{"              └─── path B: ExecuteCmd()  ← 无 CheckPermission = VIOLATION"}</div>
          </div>
          <p className="text-[#737373] text-xs mt-3">适用：权限检查缺失（必须在所有路径上调用权限验证函数）</p>
        </div>
      </section>

      {/* Section 4: Case Studies */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          4. 案例分析：从历史 CVE 到新发现
        </h2>
        <p className="text-[#a3a3a3] mb-6">
          以下三个案例展示了知识库如何从已知漏洞提取模式，并在 <code className="text-blue-400">security_device_auth</code> 中发现同构的新漏洞。
        </p>

        {/* Case 1 */}
        <div className="bg-[#141414] border border-green-500/30 rounded-lg p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <span className="flex-shrink-0 w-8 h-8 rounded-full bg-green-500/20 flex items-center justify-center text-green-400 text-sm font-bold">1</span>
            <div>
              <h3 className="text-white font-semibold">CWE-476：IPC 反序列化返回 NULL 未检查</h3>
              <p className="text-[#737373] text-xs">TypestateSpec — null → in_use 是 forbidden transition</p>
            </div>
          </div>

          <div className="mb-4">
            <h4 className="text-green-400 text-sm font-medium mb-2">规约来源：CVE-2023-24465（communication_wifi）</h4>
            <p className="text-[#a3a3a3] text-sm">WLAN 组件 <code className="text-blue-400">ReadCString</code> 返回 NULL 时，调用方未检查直接使用，触发空指针解引用。该模式被泛化为 <code className="text-blue-400">ipc_deserialization</code> + <code className="text-blue-400">discarded_error_return</code> source category。</p>
          </div>

          <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg overflow-hidden mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#262626]">
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">维度</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">CVE-2023-24465（已知）</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">OH-2026-DEVAUTH-001（新发现）</th>
                </tr>
              </thead>
              <tbody className="text-[#d4d4d4]">
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">Source</td>
                  <td className="px-4 py-2"><code className="text-blue-400">ReadCString()</code> 返回 nullptr</td>
                  <td className="px-4 py-2"><code className="text-blue-400">GetIpcRequestParamByType()</code> 返回错误码</td>
                </tr>
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">缺陷</td>
                  <td className="px-4 py-2">返回值直接赋给 std::string</td>
                  <td className="px-4 py-2">返回值被 (void) 丢弃</td>
                </tr>
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">修复</td>
                  <td className="px-4 py-2"><code className="text-blue-400">if (str != nullptr)</code></td>
                  <td className="px-4 py-2"><code className="text-blue-400">if (ret != HC_SUCCESS) return</code></td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-[#737373]">影响</td>
                  <td className="px-4 py-2">WLAN 服务崩溃</td>
                  <td className="px-4 py-2">12 个回调桩函数崩溃</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="flex gap-2">
            <Link href="/issues/OH-2026-DEVAUTH-001" className="text-xs text-blue-400 hover:text-blue-300 bg-blue-500/10 px-2 py-1 rounded">
              查看漏洞详情
            </Link>
          </div>
        </div>

        {/* Case 2 */}
        <div className="bg-[#141414] border border-red-500/30 rounded-lg p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <span className="flex-shrink-0 w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center text-red-400 text-sm font-bold">2</span>
            <div>
              <h3 className="text-white font-semibold">CWE-822：IPC 不可信指针直接调用</h3>
              <p className="text-[#737373] text-xs">TaintFlowSpec — must_not_reach（不可信数据不应到达函数调用点）</p>
            </div>
          </div>

          <div className="mb-4">
            <h4 className="text-red-400 text-sm font-medium mb-2">规约来源：CVE-2024-29074（telephony_cellular_call）</h4>
            <p className="text-[#a3a3a3] text-sm">Telephony 组件从 IPC 缓冲区 <code className="text-blue-400">ReadRawData</code> 读取原始数据，直接 <code className="text-blue-400">reinterpret_cast</code> 为结构体使用。<code className="text-blue-400">device_auth</code> 中是更极端的变体 — 直接将 IPC 值作为函数指针调用。</p>
          </div>

          <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg overflow-hidden mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#262626]">
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">维度</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">CVE-2024-29074（已知）</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">OH-2026-DEVAUTH-PTR-001（新发现）</th>
                </tr>
              </thead>
              <tbody className="text-[#d4d4d4]">
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">Source</td>
                  <td className="px-4 py-2"><code className="text-blue-400">ReadRawData()</code></td>
                  <td className="px-4 py-2"><code className="text-blue-400">ReadPointer()</code></td>
                </tr>
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">Sink</td>
                  <td className="px-4 py-2">reinterpret_cast 为结构体</td>
                  <td className="px-4 py-2">reinterpret_cast 为函数指针并调用</td>
                </tr>
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">Sanitizer</td>
                  <td className="px-4 py-2">无</td>
                  <td className="px-4 py-2">仅 cbHook == 0x0 非零检查</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-[#737373]">影响</td>
                  <td className="px-4 py-2">类型混淆 / 越界读</td>
                  <td className="px-4 py-2">任意代码执行（15 个桩函数 CFI 禁用）</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="flex gap-2">
            <Link href="/issues/OH-2026-DEVAUTH-PTR-001" className="text-xs text-blue-400 hover:text-blue-300 bg-blue-500/10 px-2 py-1 rounded">
              查看漏洞详情
            </Link>
          </div>
        </div>

        {/* Case 3 */}
        <div className="bg-[#141414] border border-amber-500/30 rounded-lg p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <span className="flex-shrink-0 w-8 h-8 rounded-full bg-amber-500/20 flex items-center justify-center text-amber-400 text-sm font-bold">3</span>
            <div>
              <h3 className="text-white font-semibold">CWE-862：RESTORE_CODE 路径跳过权限检查</h3>
              <p className="text-[#737373] text-xs">TaintFlowSpec — must_pass_through（请求到达 sink 前必须经过 CheckPermission）</p>
            </div>
          </div>

          <div className="mb-4">
            <h4 className="text-amber-400 text-sm font-medium mb-2">规约来源：CVE-2022-42488 + CVE-2022-38700</h4>
            <p className="text-[#a3a3a3] text-sm">
              <code className="text-blue-400">startup_init_lite</code> 参数服务和 <code className="text-blue-400">multimedia_camera_framework</code> 相机服务均存在 OnRemoteRequest 直达业务方法、缺少 CheckPermission 的模式。该模式被抽象为 AC-TAINT 规约。
            </p>
          </div>

          <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg overflow-hidden mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#262626]">
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">维度</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">CVE-2022-42488</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">CVE-2022-38700</th>
                  <th className="text-left text-[#737373] px-4 py-2 font-medium">OH-2026-DEVAUTH-RESTORE-001</th>
                </tr>
              </thead>
              <tbody className="text-[#d4d4d4]">
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">入口</td>
                  <td className="px-4 py-2">OnRemoteRequest</td>
                  <td className="px-4 py-2">OnRemoteRequest</td>
                  <td className="px-4 py-2">OnRemoteRequest</td>
                </tr>
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">Sink</td>
                  <td className="px-4 py-2">SetParameter</td>
                  <td className="px-4 py-2">OpenCamera</td>
                  <td className="px-4 py-2">ExecuteAccountAuthCmd</td>
                </tr>
                <tr className="border-b border-[#262626]">
                  <td className="px-4 py-2 text-[#737373]">缺失</td>
                  <td className="px-4 py-2">CheckParamPermission</td>
                  <td className="px-4 py-2">CheckPermission</td>
                  <td className="px-4 py-2">CheckPermission</td>
                </tr>
                <tr>
                  <td className="px-4 py-2 text-[#737373]">影响</td>
                  <td className="px-4 py-2">修改系统参数</td>
                  <td className="px-4 py-2">未授权访问摄像头</td>
                  <td className="px-4 py-2">重置账户认证数据</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="flex gap-2">
            <Link href="/issues/OH-2026-DEVAUTH-RESTORE-001" className="text-xs text-blue-400 hover:text-blue-300 bg-blue-500/10 px-2 py-1 rounded">
              查看漏洞详情
            </Link>
          </div>
        </div>
      </section>

      {/* Section 5: Candidate Discovery */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          5. 候选发现机制
        </h2>
        <p className="text-[#a3a3a3] mb-4">
          候选发现的核心是将规约中的 source/sink pattern 与程序中的函数调用进行匹配。匹配到 source + sink 且路径缺少 sanitizer 的函数被标记为候选。
        </p>
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">匹配方式</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">语法</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">示例</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["精确匹配", "functionName", "ReadPointer 匹配 data.ReadPointer()"],
                ["前缀匹配", "prefix*", "CheckPermission* 匹配 CheckPermissionForRole()"],
                ["后缀匹配", "*::suffix", "*Stub::OnRemoteRequest 匹配 ServiceDevAuth::OnRemoteRequest"],
                ["Glob 匹配", "fnmatch 语法", "Read*Object* 匹配 ReadRemoteObject"],
              ].map(([type, syntax, example], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3">{type}</td>
                  <td className="px-5 py-3"><code className="text-blue-400">{syntax}</code></td>
                  <td className="px-5 py-3 text-[#a3a3a3]">{example}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6">
          <h3 className="text-white font-semibold mb-3">候选评分</h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { factor: "graph_verdict=violation", score: "+5" },
              { factor: "IPC 可达", score: "+3" },
              { factor: "spec_kind=taint_flow", score: "+3" },
              { factor: "存在 taint path", score: "+2" },
              { factor: "IPC pattern 匹配", score: "+1" },
            ].map((item) => (
              <div key={item.factor} className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-3 text-center">
                <div className="text-green-400 text-lg font-bold">{item.score}</div>
                <div className="text-[#a3a3a3] text-xs mt-1">{item.factor}</div>
              </div>
            ))}
          </div>
          <p className="text-[#737373] text-xs mt-3">高于阈值（≥3）的候选进入深度分析阶段。三个 device_auth 案例的 risk score 均 ≥ 8。</p>
        </div>
      </section>

      {/* Section 6: Validation Loop */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          6. 知识库验证闭环
        </h2>

        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3]">
            <div>{"候选 ──→ [LLM 属性推理引擎]"}</div>
            <div>{"           │"}</div>
            <div>{"           ├─ 输入：函数源码 + 规约定义 + 历史证据 + 角色语义"}</div>
            <div>{"           │"}</div>
            <div>{"           ├─ 首轮：判定 safe / violation / uncertain"}</div>
            <div>{"           │"}</div>
            <div>{"           └─ 二轮（对抗性验证）：尝试推翻首轮结论"}</div>
            <div>{"                │"}</div>
            <div className="text-green-400">{"                └─ 两轮一致 → 最终确认 → PoC 验证"}</div>
          </div>
        </div>

        <div className="bg-[#141414] border border-green-500/30 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">源 CVE</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">提取的规约模式</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">新发现</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium hidden sm:table-cell">验证结论</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              <tr className="border-b border-[#262626]">
                <td className="px-5 py-3 text-[#a3a3a3]">CVE-2023-24465</td>
                <td className="px-5 py-3">IPC 反序列化返回 NULL + 未检查</td>
                <td className="px-5 py-3">
                  <Link href="/issues/OH-2026-DEVAUTH-001" className="text-blue-400 hover:text-blue-300">OH-2026-DEVAUTH-001</Link>
                </td>
                <td className="px-5 py-3 text-green-400 hidden sm:table-cell">同一模式在不同组件复现</td>
              </tr>
              <tr className="border-b border-[#262626]">
                <td className="px-5 py-3 text-[#a3a3a3]">CVE-2024-29074</td>
                <td className="px-5 py-3">IPC 原始数据 reinterpret_cast</td>
                <td className="px-5 py-3">
                  <Link href="/issues/OH-2026-DEVAUTH-PTR-001" className="text-blue-400 hover:text-blue-300">OH-2026-DEVAUTH-PTR-001</Link>
                </td>
                <td className="px-5 py-3 text-green-400 hidden sm:table-cell">泛化后覆盖更极端变体</td>
              </tr>
              <tr>
                <td className="px-5 py-3 text-[#a3a3a3]">CVE-2022-42488 / 38700</td>
                <td className="px-5 py-3">OnRemoteRequest 缺 CheckPermission</td>
                <td className="px-5 py-3">
                  <Link href="/issues/OH-2026-DEVAUTH-RESTORE-001" className="text-blue-400 hover:text-blue-300">OH-2026-DEVAUTH-RESTORE-001</Link>
                </td>
                <td className="px-5 py-3 text-green-400 hidden sm:table-cell">权限缺失是系统性问题</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Section 7: Conclusions */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          7. 结论
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#141414] border border-green-500/30 rounded-lg p-5">
            <h3 className="text-green-400 font-semibold mb-2">Pattern 可迁移</h3>
            <p className="text-[#a3a3a3] text-sm">从一个组件学到的漏洞模式可以发现另一个组件中的同类问题。wifi → device_auth，telephony → device_auth。</p>
          </div>
          <div className="bg-[#141414] border border-green-500/30 rounded-lg p-5">
            <h3 className="text-green-400 font-semibold mb-2">规约建模正确</h3>
            <p className="text-[#a3a3a3] text-sm">Source/sink/sanitizer 三元组准确刻画了漏洞的本质结构，三种规约类型覆盖了不同的漏洞类。</p>
          </div>
          <div className="bg-[#141414] border border-green-500/30 rounded-lg p-5">
            <h3 className="text-green-400 font-semibold mb-2">泛化有效</h3>
            <p className="text-[#a3a3a3] text-sm">从具体 CVE 提取的 pattern 经泛化后（ReadCString → ipc_deserialization）覆盖面更广，发现更多变体。</p>
          </div>
        </div>
      </section>
    </div>
  );
}
