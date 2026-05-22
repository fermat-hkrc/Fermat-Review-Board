import type { Metadata } from "next";
import Link from "next/link";
import { getVerifiedPocIssues } from "@/lib/content";

export const metadata: Metadata = {
  title: "PoC Verification - Fermat Review Board",
  description:
    "How Fermat verifies security vulnerabilities using Target-Compile methodology with ASan/UBSan on OpenHarmony",
};

export default function PocPage() {
  const verifiedIssues = getVerifiedPocIssues();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-white mb-2">
          PoC Verification
        </h1>
        <p className="text-[#a3a3a3] text-lg">
          Fermat Review Board 上的每个漏洞都经过 PoC（Proof of Concept）验证。
          本页介绍我们的验证方法、OpenHarmony 编译基础设施、以及如何阅读漏洞报告。
        </p>
      </div>

      {/* Section 1: Verification Framework */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          1. PoC 验证框架
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <div className="space-y-4 text-[#d4d4d4]">
            <p>
              <strong className="text-white">PoC（Proof of Concept）</strong>的本质不是"让程序崩溃"，而是<strong className="text-white">证明安全属性被违反</strong>。不同漏洞类型需要不同的验证 Oracle（判定准则）。
            </p>
            <p>
              Fermat 针对每种漏洞类型设计了对应的验证策略。静态分析引擎（Joern、Infer、IKOS）发现疑似漏洞后，根据漏洞类型选择对应的 Oracle 生成 PoC，通过运行时信号确认漏洞真实性。
            </p>
          </div>
        </div>

        {/* Verification Oracle Table */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">漏洞类型</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">验证 Oracle</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">判定信号</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">状态</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["内存空间安全\nCWE-125/787/120/416", "ASan (AddressSanitizer)", "SIGABRT + ASan report\n含完整调用栈和分配追踪", "done"],
                ["未初始化内存读取\nCWE-457/908", "MSan (MemorySanitizer)", "use-of-uninitialized-value\n精确到首次读取位置", "done"],
                ["未定义行为 / 整数溢出\nCWE-190/191", "UBSan (UndefinedBehaviorSanitizer)", "runtime error: signed integer overflow\n或 shift exponent too large", "done"],
                ["竞态条件 / TOCTOU\nCWE-362/367", "TSan + 并发竞争 Harness", "TSan: data race detected\n或竞争窗口内 symlink 替换成功", "planned"],
                ["权限 / 认证缺失\nCWE-862/306", "断言式 PoC (Assertion Oracle)", "受保护操作在无权限上下文中\n成功执行 → [VULN] marker", "planned"],
                ["路径遍历\nCWE-22", "文件系统沙箱 Oracle", "沙箱外文件被成功读写\n(../../ 逃逸检测)", "done"],
              ].map(([type, oracle, signal, status], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3 font-medium whitespace-pre-line">{type}</td>
                  <td className="px-5 py-3 text-blue-400 whitespace-pre-line">{oracle}</td>
                  <td className="px-5 py-3 text-[#a3a3a3] font-mono text-xs whitespace-pre-line">{signal}</td>
                  <td className="px-5 py-3">
                    {status === "done" ? (
                      <span className="text-green-400 text-xs font-medium">✓ 已实现</span>
                    ) : (
                      <span className="text-amber-400 text-xs font-medium">◐ 规划中</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Comparison cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#141414] border border-red-500/30 rounded-lg p-5">
            <h3 className="text-red-400 font-semibold mb-3">仅静态分析</h3>
            <div className="text-[#a3a3a3] text-sm space-y-1">
              <div>扫描源码 → 报告疑似漏洞</div>
              <div className="text-[#737373]">可能存在，也可能是误报</div>
              <div className="text-[#737373]">无法确认实际可利用性</div>
            </div>
          </div>
          <div className="bg-[#141414] border border-green-500/30 rounded-lg p-5">
            <h3 className="text-green-400 font-semibold mb-3">Oracle 驱动的 PoC 验证</h3>
            <div className="text-[#a3a3a3] text-sm space-y-1">
              <div>编译真实代码 → 构造触发输入 → Oracle 捕获违规</div>
              <div className="text-green-400/80">每种漏洞类型有对应的判定准则</div>
              <div className="text-green-400/80">运行时信号证明安全属性被违反</div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 1.5: Verification Strategies Detail */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          1.5 验证策略详解
        </h2>

        {/* A: Sanitizer Family */}
        <div className="bg-[#141414] border border-green-500/30 rounded-lg p-6 mb-4">
          <h3 className="text-green-400 font-semibold mb-3">A. Sanitizer 家族 — 内存与未定义行为（已实现）</h3>
          <div className="text-[#a3a3a3] text-sm space-y-3">
            <p>编译时插桩，运行时检测。Sanitizer 在内存分配周围插入 red zone，在释放后标记为 poisoned，在未初始化区域标记为 uninitialized。任何违规访问立即触发报告并终止。</p>
            <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs">
              <div className="text-[#737373]">{"# 编译命令"}</div>
              <div>{"clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O0 target.c poc.c -o poc"}</div>
              <div className="mt-2 text-[#737373]">{"# 判定: 程序以非零退出码终止 + stderr 包含 Sanitizer 报告"}</div>
              <div className="text-green-400">{"grep 'ERROR: AddressSanitizer\\|runtime error:' stderr → 漏洞确认"}</div>
            </div>
          </div>
        </div>

        {/* B: Race Condition */}
        <div className="bg-[#141414] border border-amber-500/30 rounded-lg p-6 mb-4">
          <h3 className="text-amber-400 font-semibold mb-3">B. 竞态条件 / TOCTOU 验证（规划中）</h3>
          <div className="text-[#a3a3a3] text-sm space-y-3">
            <p>TOCTOU 漏洞的 check 和 use 之间存在时间窗口。验证策略是在该窗口内并发修改目标资源，证明竞争可被利用。</p>
            <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs">
              <div className="text-[#737373]">{"// TOCTOU PoC 结构 (CWE-367)"}</div>
              <div>{"Thread A: while(1) { symlink(\"/tmp/target\", \"/etc/shadow\"); unlink(\"/tmp/target\"); }"}</div>
              <div>{"Thread B: target_function(\"/tmp/target\");  // access() + open()"}</div>
              <div className="mt-2 text-[#737373]">{"// Oracle: 检测 open() 实际打开的文件是否为 symlink 目标"}</div>
              <div className="text-amber-400">{"readlink(/proc/self/fd/N) != \"/tmp/target\" → 竞争成功 → 漏洞确认"}</div>
            </div>
            <p className="text-[#737373]">备选方案: TSan 编译 + 多线程 harness，检测 data race 报告。</p>
          </div>
        </div>

        {/* C: Logic/Auth */}
        <div className="bg-[#141414] border border-amber-500/30 rounded-lg p-6 mb-4">
          <h3 className="text-amber-400 font-semibold mb-3">C. 权限 / 认证缺失验证（规划中）</h3>
          <div className="text-[#a3a3a3] text-sm space-y-3">
            <p>逻辑漏洞不会触发 crash。验证策略是构造<strong className="text-white">不满足前置条件</strong>的调用上下文，证明受保护操作仍然成功执行。参考 POC-GYM (arXiv:2602.04165) 的 assertion-based oracle 方法。</p>
            <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs">
              <div className="text-[#737373]">{"// Assertion Oracle (CWE-862 权限缺失)"}</div>
              <div>{"setup_context(uid=UNPRIVILEGED_USER, no_capability=true);"}</div>
              <div>{"int ret = ProtectedOperation(params);  // 本应返回 PERMISSION_DENIED"}</div>
              <div className="mt-2 text-[#737373]">{"// Oracle: 操作成功 = 安全属性违反"}</div>
              <div className="text-amber-400">{"if (ret == SUCCESS) printf(\"[VULN] operation succeeded without authorization\");"}</div>
              <div className="mt-2 text-[#737373]">{"// 对照验证: 修复版本上同样调用应返回错误"}</div>
              <div>{"// patched: ret == PERMISSION_DENIED → 修复有效"}</div>
            </div>
          </div>
        </div>

        {/* D: Path Traversal */}
        <div className="bg-[#141414] border border-green-500/30 rounded-lg p-6">
          <h3 className="text-green-400 font-semibold mb-3">D. 路径遍历验证（已验证）</h3>
          <div className="text-[#a3a3a3] text-sm space-y-3">
            <p>构造包含 <code className="text-blue-400">../</code> 序列的路径输入，在受限沙箱环境中调用目标函数，检测是否成功逃逸到沙箱外。</p>
            <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs">
              <div className="text-[#737373]">{"// 文件系统沙箱 Oracle (CWE-22)"}</div>
              <div>{"mkdir(\"/tmp/sandbox/allowed/\");"}</div>
              <div>{"write_file(\"/tmp/sandbox/canary.txt\", \"SHOULD_NOT_READ\");"}</div>
              <div>{"char *result = target_read_file(\"../../canary.txt\");  // 相对于 allowed/"}</div>
              <div className="mt-2 text-[#737373]">{"// Oracle: 成功读取沙箱外文件 = 路径遍历确认"}</div>
              <div className="text-green-400">{"if (strcmp(result, \"SHOULD_NOT_READ\") == 0) printf(\"[VULN] path traversal\");"}</div>
            </div>
            <p className="text-green-400/80">已通过 OH-2026-FS-001（customization_config_policy <code className="text-blue-400">GetOneCfgFile</code>）验证。PoC 使用 <code className="text-blue-400">../../etc/passwd</code> 序列成功探测沙箱外文件存在性。</p>
          </div>
        </div>
      </section>

      {/* Section 2: Vulnerability Types */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          2. 漏洞类型速查
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">漏洞类型</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">CWE</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">技术描述</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium hidden md:table-cell">典型后果</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["堆越界读取", "CWE-125", "Out-of-bounds Read", "程序读取超出堆缓冲区分配范围的内存，可泄露相邻堆块中的敏感数据", "信息泄露、ASLR 绕过"],
                ["堆越界写入", "CWE-787", "Out-of-bounds Write", "程序写入超出堆缓冲区分配范围的内存，可覆盖堆元数据或相邻对象", "任意代码执行、堆布局劫持"],
                ["整数溢出", "CWE-190", "Integer Overflow or Wraparound", "算术运算结果超出数据类型表示范围，导致分配大小计算错误", "后续缓冲区溢出、逻辑绕过"],
                ["Null 终止符缺失", "CWE-170", "Improper Null Termination", "字符串缺少 \\0 结束标记，后续字符串操作越界读取直到遇到随机 \\0", "信息泄露、越界读取"],
                ["空指针解引用", "CWE-476", "NULL Pointer Dereference", "通过空指针访问内存，内核映射 NULL 页时可能被利用", "拒绝服务、特定内核配置下代码执行"],
                ["释放后使用", "CWE-416", "Use After Free", "访问已释放的堆内存，若该区域被重新分配给其他对象则可控制其内容", "任意代码执行、类型混淆"],
                ["未初始化内存使用", "CWE-908", "Use of Uninitialized Resource", "通过 malloc 分配但未初始化的内存被后续代码读取，堆上残留数据被泄露给调用方", "信息泄露、不可预测行为"],
                ["路径遍历", "CWE-22", "Path Traversal", "路径参数未过滤 ../ 序列，攻击者可拼接路径访问受限目录外的文件", "任意文件读取、信息泄露"],
                ["数组索引越界", "CWE-129", "Improper Validation of Array Index", "数组索引未校验范围，外部输入可控的索引值导致越界数组访问", "越界读写、代码执行"],
              ].map(([type, cwe, cweName, desc, impact], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3 font-medium">{type}</td>
                  <td className="px-5 py-3"><code className="text-blue-400 text-xs">{cwe}</code><br/><span className="text-[#737373] text-xs">{cweName}</span></td>
                  <td className="px-5 py-3 text-[#a3a3a3]">{desc}</td>
                  <td className="px-5 py-3 text-[#737373] hidden md:table-cell">{impact}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Section 3: Target-Compile */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          3. 什么是 Target-Compile（目标编译）？
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <p className="text-[#d4d4d4] mb-4">
            Target-Compile 是 Fermat 的核心验证方法。我们不提取代码片段或模拟头文件——而是将目标项目的<strong className="text-white">真实生产源码</strong>通过其自身的构建系统（GN + Ninja）编译为静态库（.a），然后链接测试驱动程序构造恶意输入，触发漏洞。
          </p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-sm text-[#a3a3a3]">
            <div className="text-blue-400 mb-1">{"# Target-Compile Pipeline"}</div>
            <div className="space-y-1">
              <div>{"目标源码（.c/.cpp）"}</div>
              <div className="text-[#737373]">{"    ↓ GN 构建系统"}</div>
              <div>{"静态库（.a）— 真实编译产物"}</div>
              <div className="text-[#737373]">{"    ↓ 链接测试驱动（PoC）"}</div>
              <div>{"可执行文件 + ASan/UBSan"}</div>
              <div className="text-[#737373]">{"    ↓ 运行"}</div>
              <div className="text-green-400">{"ASan 报告 → 漏洞确认"}</div>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#141414] border border-red-500/30 rounded-lg p-5">
            <h3 className="text-red-400 font-semibold mb-2">#include 模拟（我们不这样做）</h3>
            <ul className="text-[#a3a3a3] text-sm space-y-1">
              <li>- 提取漏洞函数到独立文件</li>
              <li>- 模拟或简化依赖关系</li>
              <li>- 编译环境与真实环境不同</li>
              <li>- 可能引入或消除真实 bug</li>
            </ul>
          </div>
          <div className="bg-[#141414] border border-green-500/30 rounded-lg p-5">
            <h3 className="text-green-400 font-semibold mb-2">Target-Compile（我们的方法）</h3>
            <ul className="text-[#a3a3a3] text-sm space-y-1">
              <li>- 编译目标项目的真实源码</li>
              <li>- 仅提供最小桩代码解决链接问题</li>
              <li>- 使用目标项目自身的构建系统</li>
              <li>- PoC 触发的是真正的代码路径</li>
            </ul>
          </div>
        </div>

        {/* PoC Automation: Path Resolver + Scenario + Modes */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-3">自动化 PoC 生成管线</h3>
          <p className="text-[#d4d4d4] mb-4">
            Fermat 的 L4 验证层将 PoC 生成从手动编写升级为<strong className="text-white">全自动管线</strong>：从漏洞函数自动追溯入口点、生成攻击场景计划、编写 PoC 代码、编译验证、生成补丁并验证补丁有效性。
          </p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-sm text-[#a3a3a3]">
            <div className="text-blue-400 mb-1">{"# L4 PoC 生成管线"}</div>
            <div className="space-y-1">
              <div>{"漏洞函数"}</div>
              <div className="text-[#737373]">{"    ↓ PoC Path Resolver — 自动入口追溯"}</div>
              <div>{"Public API 入口 + IPC 序列化格式 + CWE 触发值"}</div>
              <div className="text-[#737373]">{"    ↓ Scenario Planner — 攻击场景规划"}</div>
              <div>{"结构化攻击计划（SCENARIO / SETUP / TRIGGER / EXPECTED_SIGNAL）"}</div>
              <div className="text-[#737373]">{"    ↓ Code Generator — 按场景写代码"}</div>
              <div>{"PoC 测试驱动 + Build Agent 自动编译"}</div>
              <div className="text-[#737373]">{"    ↓ Oracle 验证 — ASan/MSan/Assertion"}</div>
              <div className="text-green-400">{"漏洞确认 → 补丁生成 → 补丁有效性验证"}</div>
            </div>
          </div>
        </div>

        {/* Two-level Entry Resolution */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-3">PoC Path Resolver：两级入口追溯</h3>
          <p className="text-[#a3a3a3] text-sm mb-4">
            PoC Path Resolver 从漏洞函数向上 BFS 追溯调用链，自动确定测试驱动应调用的入口函数、IPC 序列化格式（Read* 调用序列 + size-prefix 关系）、以及 CWE 特定的触发值。
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-[#0a0a0a] border border-green-500/30 rounded-lg p-4">
              <h4 className="text-green-400 text-sm font-semibold mb-2">Public API Entry（首选）</h4>
              <p className="text-[#a3a3a3] text-xs">模块公开头文件中声明的函数（如 <code className="text-blue-400">interfaces/kits/native/include/*.h</code>）。测试驱动直接调用此函数，真实编译代码处理完整的内部调用链。</p>
            </div>
            <div className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-4">
              <h4 className="text-[#d4d4d4] text-sm font-semibold mb-2">Transport Entry（Fallback）</h4>
              <p className="text-[#a3a3a3] text-xs">IPC 回调或 handler（如 <code className="text-blue-400">.func =</code> 注册的函数、<code className="text-blue-400">OnRemoteRequest</code>）。当无法追溯到 Public API 时，使用 transport entry 配合 IPC 序列化格式构造输入。</p>
            </div>
          </div>
        </div>

        {/* PoC Generation Modes */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">优先级</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">模式</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">说明</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium hidden sm:table-cell">可信度</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["1（最高）", "target_compile", "编译真实源码为 .a 静态库，链接测试驱动。OHOS 模块强制使用", "最高"],
                ["2", "chain_aware", "包含完整调用链源码的 PoC，通过入口点触发（非 OHOS）", "高"],
                ["3（最低）", "standalone", "自包含 PoC，仅用于非 OHOS 项目的 fallback", "中"],
              ].map(([priority, mode, desc, confidence], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3 text-[#737373]">{priority}</td>
                  <td className="px-5 py-3"><code className="text-blue-400">{mode}</code></td>
                  <td className="px-5 py-3 text-[#a3a3a3]">{desc}</td>
                  <td className="px-5 py-3 hidden sm:table-cell">{confidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          4. OpenHarmony 编译基础设施
        </h2>
        <p className="text-[#a3a3a3] mb-4">
          OpenHarmony（OHOS）是一个复杂的嵌入式操作系统，其模块依赖大量系统框架 API（IPC 通信、系统服务管理、日志等）。
          为了在标准 Linux x86_64 环境下编译和运行 OHOS 模块，我们构建了完整的编译工具链和桩代码（stub）体系。
        </p>

        {/* 4a: Toolchain Overview */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-4">工具链概览</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { name: "GN 构建系统", desc: "模拟 OHOS 构建环境，定义编译目标、依赖关系和编译标志", icon: "gn" },
              { name: "Ninja 编译器", desc: "执行增量编译，调度 clang/clang++ 编译任务", icon: "ninja" },
              { name: "ASan + UBSan", desc: "AddressSanitizer 检测内存越界，UndefinedBehaviorSanitizer 检测未定义行为", icon: "san" },
              { name: "setup_build.py", desc: "一键生成完整构建根目录的脚本，自动链接框架头文件和第三方库", icon: "py" },
            ].map((item) => (
              <div key={item.name} className="bg-[#0a0a0a] border border-[#262626] rounded-lg p-4">
                <div className="flex items-center gap-2 mb-1">
                  <code className="text-blue-400 text-xs bg-blue-500/10 px-1.5 py-0.5 rounded">{item.icon}</code>
                  <span className="text-white text-sm font-medium">{item.name}</span>
                </div>
                <p className="text-[#a3a3a3] text-xs">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* 4b: C Stubs */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-2">C 语言桩代码</h3>
          <p className="text-[#a3a3a3] text-sm mb-4">
            <code className="text-blue-400">ohos_stubs.c</code> 提供了 OHOS 系统框架的 C API 实现。桩代码的作用是在编译时替代缺失的系统服务，使目标模块能够编译和链接。
          </p>

          <h4 className="text-[#d4d4d4] text-sm font-medium mb-2">IPC 通信（进程间通信）</h4>
          <p className="text-[#a3a3a3] text-xs mb-3">
            OHOS 使用 IpcIo 进行进程间通信的数据序列化。我们实现了完整的 IpcIo 读写 API，测试驱动可以配置 IPC 调用的返回值。
          </p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs text-[#a3a3a3] mb-4 overflow-x-auto">
            <div className="text-[#737373]">{"// IpcIo 序列化/反序列化"}</div>
            <div>{"IpcIoInit(io, buffer, bufferSize, maxobjects)"}</div>
            <div>{"WriteInt32 / WriteInt64 / WriteString"}</div>
            <div>{"ReadInt32 / ReadString"}</div>
            <div className="mt-1 text-[#737373]">{"// IPC 客户端代理 — 测试驱动可配置返回值"}</div>
            <div>{"IClientProxy.Invoke → 写入 g_mock_result_code + g_mock_response_json"}</div>
            <div className="mt-1 text-[#737373]">{"// IPC 异步推送模拟 — 模拟服务端向客户端推送数据"}</div>
            <div>{"SAMGR_SimulatePush(IpcIo *data) → 调用 WriteRemoteObject 注册的回调"}</div>
          </div>

          <h4 className="text-[#d4d4d4] text-sm font-medium mb-2">系统服务管理（SamgrLite）</h4>
          <p className="text-[#a3a3a3] text-xs mb-3">
            SamgrLite 是 OHOS 的服务管理框架，包含 13 个函数指针。我们实现了完整的 vtable，包括服务注册、发现和功能 API 管理。
          </p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs text-[#a3a3a3] mb-4 overflow-x-auto">
            <div className="text-[#737373]">{"// SamgrLite — 13 个函数指针全部实现"}</div>
            <div>{"RegisterService / UnregisterService"}</div>
            <div>{"RegisterFeature / UnregisterFeature"}</div>
            <div>{"RegisterDefaultFeatureApi / GetDefaultFeatureApi"}</div>
            <div>{"RegisterFeatureApi / GetFeatureApi → 返回模拟 IPC 代理"}</div>
            <div>{"AddSystemCapability / HasSystemCapability"}</div>
          </div>

          <h4 className="text-[#d4d4d4] text-sm font-medium mb-2">日志系统</h4>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-3 font-mono text-xs text-[#a3a3a3]">
            <div>{"HiLogPrint(type, level, domain, tag, fmt, ...)"}</div>
            <div className="text-[#737373]">{"  → vfprintf(stderr, ...)  // 转发到标准错误输出"}</div>
          </div>
        </div>

        {/* 4c: C++ Stubs */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-2">C++ 框架桩代码</h3>
          <p className="text-[#a3a3a3] text-sm mb-4">
            <code className="text-blue-400">ohos_cpp_stubs.h</code> 提供了 OHOS C++ 框架核心类的实现，位于 <code className="text-blue-400">OHOS</code> 命名空间下。
          </p>
          <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#262626]">
                  <th className="text-left text-[#737373] px-5 py-3 font-medium">类</th>
                  <th className="text-left text-[#737373] px-5 py-3 font-medium">功能</th>
                  <th className="text-left text-[#737373] px-5 py-3 font-medium hidden sm:table-cell">对应 OHOS 类</th>
                </tr>
              </thead>
              <tbody className="text-[#d4d4d4]">
                {[
                  ["RefBase", "引用计数基类，提供 IncRef/DecRef 自动生命周期管理", "OHOS::RefBase"],
                  ["sptr<T>", "智能指针模板，类似 Android sp<>，自动管理引用计数", "OHOS::sptr"],
                  ["Parcel", "IPC 数据序列化缓冲区，支持基本类型和字符串的读写", "OHOS::Parcel"],
                  ["MessageParcel", "扩展 Parcel，支持 InterfaceToken 写入", "OHOS::MessageParcel"],
                  ["IRemoteObject", "IPC 远程对象接口，定义 SendRequest 虚方法", "OHOS::IRemoteObject"],
                  ["IPCSkeleton", "IPC 框架入口，提供 GetCallingPid/Uid 等静态方法", "OHOS::IPCSkeleton"],
                  ["HiLog", "日志工具，Info/Error 方法输出到 stderr", "OHOS::HiLog"],
                ].map(([cls, desc, ohos], i) => (
                  <tr key={i} className="border-b border-[#262626] last:border-0">
                    <td className="px-5 py-3"><code className="text-blue-400">{cls}</code></td>
                    <td className="px-5 py-3 text-[#a3a3a3]">{desc}</td>
                    <td className="px-5 py-3 text-[#737373] hidden sm:table-cell"><code className="text-xs">{ohos}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* 4d: HAL Stubs */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6">
          <h3 className="text-white font-semibold mb-2">HAL 桩代码</h3>
          <p className="text-[#a3a3a3] text-sm mb-4">
            <code className="text-blue-400">hal_stubs.c</code> 提供 Hardware Abstraction Layer 和平台 API 的模拟实现，用于服务端/守护进程模块的编译。
          </p>
          <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#262626]">
                  <th className="text-left text-[#737373] px-5 py-3 font-medium">函数</th>
                  <th className="text-left text-[#737373] px-5 py-3 font-medium">模拟行为</th>
                </tr>
              </thead>
              <tbody className="text-[#d4d4d4]">
                {[
                  ["HalMalloc(size)", "calloc(1, size+1) — 多分配 1 字节给 null 终止符"],
                  ["HalFree(ptr)", "标准 free(ptr)"],
                  ["HalGetPermissionPath()", "返回 /tmp/ohos_perm_test/ — 将文件操作重定向到测试目录"],
                  ["HalAccess(pathname)", "标准 access(pathname, F_OK)"],
                  ["HalIsValidPath(path)", "始终返回 true"],
                  ["HalGetMaxPermissionSize()", "返回 1,000,000"],
                  ["HalGetPermissionList(length)", "返回一个示例权限条目（ohos.permission.CAMERA）"],
                  ["HalMutexLock/Unlock()", "pthread_mutex_lock/unlock"],
                ].map(([fn, desc], i) => (
                  <tr key={i} className="border-b border-[#262626] last:border-0">
                    <td className="px-5 py-3"><code className="text-blue-400 text-xs">{fn}</code></td>
                    <td className="px-5 py-3 text-[#a3a3a3]">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Section 5: ASan/UBSan */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          5. ASan/UBSan/MSan 检测能力
        </h2>

        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <h3 className="text-white font-semibold mb-3">ASan 工作原理</h3>
          <p className="text-[#d4d4d4] mb-3">
            AddressSanitizer（ASan）是编译器内置的内存错误检测器。编译时，ASan 在每块内存分配周围插入<strong className="text-white">"哨兵"区域（red zone）</strong>。
            当程序访问这些哨兵区域时，ASan 立即报告错误并终止程序。这意味着越界读写不会"静默通过"——每次违规都会被捕获。
          </p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3] overflow-x-auto">
            <div className="text-[#737373]">{"// ASan 内存布局示意"}</div>
            <div className="mt-1">{"[red zone][  分配的缓冲区  ][red zone]"}</div>
            <div>{"  ↑ 禁止    ↑ 合法访问范围      ↑ 禁止"}</div>
            <div className="mt-1 text-green-400">{"正常读写 → 在合法范围内 → 程序正常运行"}</div>
            <div className="text-red-400">{"越界读写 → 进入 red zone → ASan 报错并终止"}</div>
          </div>
        </div>

        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">检测类型</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">含义</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">对应 CWE</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["heap-buffer-overflow", "堆缓冲区越界读写", "CWE-125, CWE-787"],
                ["SEGV (out-of-bounds)", "越界访问到未映射内存页", "CWE-129"],
                ["allocation-size-too-big", "整数溢出导致异常大分配", "CWE-190"],
                ["out-of-memory", "未校验的外部输入控制分配大小", "CWE-190"],
                ["heap-use-after-free", "释放后使用", "CWE-416"],
                ["stack-buffer-overflow", "栈缓冲区溢出", "CWE-121"],
                ["UBSan: signed-integer-overflow", "有符号整数溢出", "CWE-190"],
                ["MSan: use-of-uninitialized-value", "未初始化内存读取", "CWE-908"],
              ].map(([type, desc, cwe], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3"><code className="text-amber-400">{type}</code></td>
                  <td className="px-5 py-3">{desc}</td>
                  <td className="px-5 py-3"><code className="text-blue-400 text-xs">{cwe}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ASan Config Fix Callout */}
        <div className="bg-[#141414] border border-amber-500/40 rounded-lg p-6">
          <h3 className="text-amber-400 font-semibold mb-3">
            Critical: ASan 配置传播问题
          </h3>
          <p className="text-[#d4d4d4] mb-3">
            在构建 OHOS GN 项目时，<code className="text-blue-400">set_defaults()</code> 不会将 cflags 传播到各个编译目标。ASan 标志
            （<code className="text-blue-400">-fsanitize=address,undefined</code>）<strong className="text-white">必须</strong>在
            每个 target 的 <code className="text-blue-400">configs</code> 列表中显式声明。
          </p>
          <p className="text-[#a3a3a3] mb-4">
            如果不做这一步，代码编译时不会插入 ASan 探针，但链接阶段会链接 ASan 运行时——结果是程序正常运行，
            越界读写<strong className="text-red-400">静默通过</strong>，不报任何错误。这给人一种"一切正常"的假象。
          </p>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3] overflow-x-auto">
            <div className="text-green-400 mb-1">{"// Correct: every target needs explicit ASan config"}</div>
            <div>{"config(\"asan_config\") {"}</div>
            <div>{"  cflags = [ \"-fsanitize=address,undefined\", ... ]"}</div>
            <div>{"  cflags_cc = [ \"-std=c++17\", ... ]"}</div>
            <div>{"}"}</div>
            <div className="mt-2">{"executable(\"poc\") {"}</div>
            <div>{"  configs = [ \":asan_config\" ]  // MUST be explicit"}</div>
            <div>{"}"}</div>
          </div>
        </div>
      </section>

      {/* Section 6: Build Pipeline */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          6. PoC 构建与验证管线
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-sm text-[#a3a3a3]">
            <div className="space-y-1">
              <div className="text-white">{"漏洞报告（L3 输出）"}</div>
              <div className="text-[#737373]">{"    ↓ PoC Path Resolver — 入口追溯 + IPC 格式提取 + 触发值选择"}</div>
              <div>{"入口函数 + 序列化格式 + CWE 触发值"}</div>
              <div className="text-[#737373]">{"    ↓ Scenario Planner — 结构化攻击场景"}</div>
              <div>{"SCENARIO / SETUP / TRIGGER / EXPECTED_SIGNAL"}</div>
              <div className="text-[#737373]">{"    ↓ setup_build.py — 一键生成构建根目录"}</div>
              <div>{"GN 构建描述 (BUILD.gn) + 桩代码"}</div>
              <div className="text-[#737373]">{"    ↓ gn gen + ninja — clang/clang++ 编译 + ASan/MSan 插桩"}</div>
              <div className="text-white">{"静态库 (.a) — 真实编译产物"}</div>
              <div className="text-[#737373]">{"    ↓ Build Agent — 链接 PoC 测试驱动（自动修复编译错误）"}</div>
              <div>{"可执行文件（含 Sanitizer runtime）"}</div>
              <div className="text-[#737373]">{"    ↓ Oracle 验证 — 运行 + 捕获信号"}</div>
              <div className="text-green-400">{"漏洞确认 → 补丁生成 → 补丁有效性验证 → 反馈知识库"}</div>
            </div>
          </div>
        </div>
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">阶段</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">工具</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">输入</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">输出</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["入口解析", "PoC Path Resolver", "漏洞函数 + 源码", "Public API 入口 + IPC 格式"],
                ["场景规划", "Scenario Planner", "入口 + CWE + 触发条件", "结构化攻击计划"],
                ["源码准备", "setup_build.py", "OHOS 模块源码", "GN 构建根目录 + 桩代码"],
                ["构建生成", "gn gen", "BUILD.gn 文件", "ninja 构建文件"],
                ["编译", "ninja (clang/clang++)", ".c/.cpp 源文件", ".o 目标文件"],
                ["打包", "ar rcs", ".o 目标文件", ".a 静态库"],
                ["链接", "Build Agent", "PoC.o + .a + Sanitizer", "可执行文件"],
                ["验证", "Oracle (ASan/MSan/Assertion)", "构造的恶意输入", "漏洞确认报告"],
                ["补丁", "Patch Generator + Validator", "漏洞点 + PoC", "修复补丁 + 有效性验证"],
              ].map(([stage, tool, input, output], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3">{stage}</td>
                  <td className="px-5 py-3"><code className="text-blue-400">{tool}</code></td>
                  <td className="px-5 py-3 text-[#a3a3a3]">{input}</td>
                  <td className="px-5 py-3">{output}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Section 7: Verified PoC Cases */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          7. 已验证的 PoC 案例
        </h2>

        {/* Stats cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {[
            {
              label: "已验证 PoC",
              value: verifiedIssues.length.toString(),
              color: "text-white",
            },
            {
              label: "覆盖仓库",
              value: new Set(verifiedIssues.map((i) => i.repo)).size.toString(),
              color: "text-blue-400",
            },
            {
              label: "CWE 类型",
              value: new Set(verifiedIssues.map((i) => i.cwe)).size.toString(),
              color: "text-green-400",
            },
            {
              label: "验证方法",
              value: "Target-Compile",
              color: "text-amber-400",
            },
          ].map((stat) => (
            <div
              key={stat.label}
              className="bg-[#141414] border border-[#262626] rounded-lg p-4 text-center"
            >
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-[#737373] text-xs mt-1">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Issues table */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium">Issue</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium hidden sm:table-cell">仓库</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">漏洞类型</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium hidden md:table-cell">状态</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {verifiedIssues.map((issue) => (
                <tr key={issue.id} className="border-b border-[#262626] last:border-0 hover:bg-[#1a1a1a] transition-colors">
                  <td className="px-5 py-3">
                    <Link
                      href={`/issues/${issue.id}`}
                      className="text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      {issue.id}
                    </Link>
                  </td>
                  <td className="px-5 py-3 text-[#a3a3a3] hidden sm:table-cell">{issue.repo}</td>
                  <td className="px-5 py-3">
                    <code className="text-xs text-[#d4d4d4]">{issue.cwe}</code>
                    <span className="text-[#737373] text-xs ml-1">{issue.cwe_name}</span>
                  </td>
                  <td className="px-5 py-3 hidden md:table-cell">
                    <StatusBadge status={issue.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {verifiedIssues.length === 0 && (
          <p className="text-[#737373] text-sm mt-4">暂无已验证的 PoC 案例。</p>
        )}
      </section>

      {/* Section 8: Technical Challenges */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          8. OpenHarmony Target-Compile 技术挑战
        </h2>
        <p className="text-[#a3a3a3] mb-4">
          在 x86_64 Linux 上编译和运行 OHOS 模块面临一系列独特的技术挑战。以下是我们遇到并解决的关键问题：
        </p>
        <div className="space-y-3">
          {[
            {
              num: 1,
              title: "SamgrLite 结构体 ABI 精确匹配",
              desc: "SamgrLite 结构体有 13 个函数指针，必须与 samgr_lite.h 精确匹配。一个指针偏移错误就会导致调用跳转到错误地址。这意味着桩代码中的结构体布局必须和 OHOS 头文件逐字节对齐。",
            },
            {
              num: 2,
              title: "IpcIo bufferCur 重置时序",
              desc: "IpcIo mock 在写入数据后、notify 回调读取前，必须将 bufferCur 重置到 bufferBase，否则读取位置错误。这是一个微妙的时序问题——写入指针不重置，后续读取会从错误位置开始。",
            },
            {
              num: 3,
              title: "HalMalloc null 终止符空间",
              desc: "ReadString 不分配 null 终止符空间。HalMalloc 必须使用 calloc(1, size+1)——比请求的大小多分配 1 字节。如果不做这一步，字符串操作（strlen、printf）会越界读取。",
            },
            {
              num: 4,
              title: "ParsePermissions JSON flags 字段",
              desc: "服务端 ParsePermissions 要求 JSON 中必须有 'flags' 字段，ParseNewPermissionsItem 在没有 flags 时返回错误。这意味着测试数据必须包含完整的权限结构。",
            },
            {
              num: 5,
              title: "HiLogPrint 枚举类型签名",
              desc: "HiLogPrint 使用 LogType/LogLevel 枚举而非 int，桩代码签名必须使用正确的枚举类型。使用 int 会导致编译器在 strict 模式下报错。",
            },
            {
              num: 6,
              title: "GetCallingUid 返回类型",
              desc: "GetCallingUid 返回 pid_t 而非 uid_t。在 OHOS 中两者可能不同，混淆会导致类型不匹配的编译错误。",
            },
            {
              num: 7,
              title: "GN ASan cflags 不自动传播",
              desc: "GN 的 set_defaults() 不会将 cflags（包括 -fsanitize=address）传播到编译目标。必须在每个 target 的 configs 中显式声明。这是 RtpPacket PoC 最初无法触发 ASan 的根本原因——代码编译时没有 ASan 插桩，但链接了 ASan 运行时，造成越界访问静默通过。",
              highlight: true,
            },
            {
              num: 8,
              title: "模块特定编译依赖解析",
              desc: "不同 OHOS 模块使用不同的构建配置和第三方依赖。某些模块的 BUILD.gn 有 3-4 层嵌套引用，Build Agent 需要自动解析依赖树、查找缺失头文件并生成对应桩代码。setup_build.py 自动化了大部分流程，但极端情况仍需手动调整。",
            },
            {
              num: 9,
              title: "C++ NAPI 桩代码边界",
              desc: "涉及 NAPI（JS/Native 桥接层）的模块需要 napi.h 和 node_api.h 的桩实现，包括 napi_value、napi_env 等不透明类型。当前 Target-Compile 仅覆盖纯 C/C++ 模块，NAPI 类型需要独立的桩系统才能支持 JS 桥接模块的编译。",
            },
            {
              num: 10,
              title: "-Dstatic= 多重定义冲突",
              desc: "-Dstatic= 将 static 函数暴露为全局符号，当多个 .o 文件定义了同名 static 函数时会导致链接器报 multiple definition 错误。解决方案是对 OHOS target-compile 自动传递 -Wl,--allow-multiple-definition 链接器标志。",
            },
            {
              num: 11,
              title: "securec static inline 失效",
              desc: "-Dstatic= 同时影响 securec.h 中的 static inline 函数（memset_s、strcpy_s 等），使其变为 inline 但丢失外部定义（C99 语义）。需要独立的 securec_stubs.c 在不使用 -Dstatic= 的情况下编译，提供外部链接定义。",
            },
          ].map((item) => (
            <div
              key={item.num}
              className={`bg-[#141414] border rounded-lg p-5 ${
                item.highlight ? "border-amber-500/40" : "border-[#262626]"
              }`}
            >
              <div className="flex items-start gap-3">
                <span
                  className={`flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                    item.highlight
                      ? "bg-amber-500/20 text-amber-400"
                      : "bg-[#262626] text-[#a3a3a3]"
                  }`}
                >
                  {item.num}
                </span>
                <div>
                  <h3 className={`font-semibold mb-1 ${item.highlight ? "text-amber-400" : "text-white"}`}>
                    {item.title}
                  </h3>
                  <p className="text-[#a3a3a3] text-sm">{item.desc}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Section 9: How to Read PoC Reports */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          9. 如何阅读 PoC 报告
        </h2>
        <p className="text-[#a3a3a3] mb-4">
          Fermat Review Board 上的每个漏洞报告包含以下结构化信息：
        </p>
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden mb-6">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626]">
                <th className="text-left text-[#737373] px-5 py-3 font-medium w-12">#</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">章节</th>
                <th className="text-left text-[#737373] px-5 py-3 font-medium">内容说明</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["漏洞概述", "漏洞的简要描述、触发条件和影响范围"],
                ["问题代码", "精确的代码位置和有缺陷的代码片段（含行号）"],
                ["触发条件", "触发漏洞的步骤序列和攻击前提"],
                ["影响", "漏洞的影响范围和潜在危害"],
                ["PoC 验证", "验证方法、编译环境、编译产物列表"],
                ["ASan 输出", "ASan/UBSan 的完整报告，包含调用栈和分配追踪"],
                ["修复建议", "漏洞的修复代码（unified diff 格式）"],
                ["PoC 类型声明", "PoC 生成模式（target_compile / chain_aware / standalone）、验证 Oracle 类型、是否可在真实设备触发、攻击前提"],
              ].map(([title, desc], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3 text-[#737373]">{i + 1}</td>
                  <td className="px-5 py-3 font-medium">{title}</td>
                  <td className="px-5 py-3 text-[#a3a3a3]">{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ASan output example */}
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6">
          <h3 className="text-white font-semibold mb-3">ASan 输出示例与解读</h3>
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-xs text-[#a3a3a3] overflow-x-auto">
            <div className="text-red-400">{"ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000003c"}</div>
            <div className="text-amber-400">{"READ of size 1 at 0x50200000003c thread T0"}</div>
            <div>{"    #0 in OHOS::Sharing::RtcpHeader::GetPaddingSize() const rtcp.cpp:45"}</div>
            <div>{"    #1 in main rtp_poc.cpp:83"}</div>
            <div className="mt-2 text-blue-400">{"0x50200000003c is located 399 bytes after 4-byte region [0x502000000010,0x502000000014)"}</div>
            <div className="text-green-400">{"allocated by thread T0 here:"}</div>
            <div>{"    #0 in operator new[](unsigned long)"}</div>
            <div>{"    #1 in main rtp_poc.cpp:69"}</div>
          </div>
          <div className="mt-4 text-[#a3a3a3] text-sm space-y-1">
            <p><strong className="text-red-400">ERROR 行</strong>：检测到的错误类型（heap-buffer-overflow）和出错地址</p>
            <p><strong className="text-amber-400">READ/WRITE 行</strong>：操作类型（读/写）、操作大小、所在线程</p>
            <p><strong className="text-blue-400">定位行</strong>：出错地址与分配区域的关系。"399 bytes after 4-byte region" 表示程序在一个 4 字节缓冲区之后 399 字节的位置进行了读取</p>
            <p><strong className="text-green-400">分配追踪</strong>：显示缓冲区的分配来源和调用栈，证明 OOB 读取的缓冲区来自目标代码</p>
          </div>
        </div>
      </section>

      {/* Section 10: Capabilities & Limitations */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          10. 当前验证能力与局限
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#141414] border border-green-500/30 rounded-lg p-6">
            <h3 className="text-green-400 font-semibold mb-4">已验证能力</h3>
            <ul className="text-[#d4d4d4] text-sm space-y-2">
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>纯 C 模块（permission_lite, config_policy, sensors_sensor_lite）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>C++ 模块（castengine_wifi_display: DataBuffer, RtpPacket）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>路径遍历验证（CWE-22，文件系统沙箱 Oracle）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>未初始化内存检测（CWE-908，MSan Oracle）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>整数溢出→堆破坏链（CWE-190 → allocation-size-too-big）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>ASan/UBSan/MSan 多 Sanitizer 检测</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>自动入口追溯（PoC Path Resolver）+ 场景级 PoC 生成</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>补丁生成与有效性验证反馈闭环</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>客户端 + 服务端 + IPC 模块三向支持</span>
              </li>
            </ul>
          </div>
          <div className="bg-[#141414] border border-[#262626] rounded-lg p-6">
            <h3 className="text-[#a3a3a3] font-semibold mb-4">当前局限</h3>
            <ul className="text-[#a3a3a3] text-sm space-y-2">
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>仅 Linux x86_64（非 ARM 交叉编译）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>NAPI/JS 桥接层模块暂不支持</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>需要 OHOS 图形/音频/Ability 框架的模块暂不支持</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>TSan 竞态条件验证（CWE-362/367）仍为规划中</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>权限/认证 Assertion Oracle（CWE-862/306）仍为规划中</span>
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* Section 11: Compilation Environment */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          11. 编译环境
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <tbody className="text-[#d4d4d4]">
              {[
                ["操作系统", "Ubuntu 24.04 LTS, Linux 6.17, x86_64"],
                ["构建系统", "GN + Ninja (OHOS 构建工具链)"],
                ["C 编译器", "clang (LLVM) + ASan + UBSan"],
                ["C++ 编译器", "clang++ (LLVM) + ASan + UBSan"],
                ["C++ 标准", "C++17 (-std=c++17)"],
                ["RTTI", "禁用 (-fno-rtti)"],
                ["优化级别", "-O0 (无优化，确保 ASan 插桩完整)"],
                ["安全库", "bounds_checking_function (memcpy_s, strcpy_s 等)"],
              ].map(([key, val], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3 text-[#737373] w-32">{key}</td>
                  <td className="px-5 py-3">{val}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; color: string; bg: string }> = {
    CONFIRMED_REAL: { label: "Confirmed", color: "text-green-400", bg: "bg-green-500/10" },
    CONFIRMED_FIXED: { label: "Fixed", color: "text-green-400", bg: "bg-green-500/10" },
    SUBMITTED: { label: "Submitted", color: "text-blue-400", bg: "bg-blue-500/10" },
    PENDING: { label: "Pending", color: "text-amber-400", bg: "bg-amber-500/10" },
    FALSE_POSITIVE: { label: "FP", color: "text-[#737373]", bg: "bg-[#262626]" },
  };
  const c = config[status] || { label: status, color: "text-[#a3a3a3]", bg: "bg-[#262626]" };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${c.color} ${c.bg}`}>
      {c.label}
    </span>
  );
}
