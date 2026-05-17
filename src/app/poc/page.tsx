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

      {/* Section 1: What is PoC */}
      <section className="mb-10">
        <h2 className="text-xl font-semibold text-white border-b border-[#262626] pb-3 mb-6">
          1. 什么是 PoC（概念验证）？
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <div className="space-y-4 text-[#d4d4d4]">
            <p>
              <strong className="text-white">安全漏洞</strong>是程序中的缺陷，攻击者可以利用它执行不该执行的操作——读取不该读的数据、写入不该写的内存、绕过权限检查等。
            </p>
            <p>
              <strong className="text-white">PoC（Proof of Concept，概念验证）</strong>是一段代码，用来证明漏洞在真实环境中确实可以被触发。静态分析工具可以报告"这里可能有问题"，但可能是误报。PoC 用实际运行结果证明漏洞存在。
            </p>
            <p>
              在 Fermat 中，静态分析引擎（Joern、Infer、IKOS）发现疑似漏洞后，我们为每个发现构建 PoC，编译目标项目的真实源码，构造恶意输入，用 AddressSanitizer（ASan）捕获越界访问，从而确认漏洞的真实性。
            </p>
          </div>
        </div>
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
            <h3 className="text-green-400 font-semibold mb-3">PoC 验证（我们的方法）</h3>
            <div className="text-[#a3a3a3] text-sm space-y-1">
              <div>编译真实代码 → 构造恶意输入 → ASan 捕获错误</div>
              <div className="text-green-400/80">确认漏洞在真实代码路径上可触发</div>
              <div className="text-green-400/80">提供完整的崩溃调用栈和内存分配追踪</div>
            </div>
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
                <th className="text-left text-[#737373] px-5 py-3 font-medium hidden md:table-cell">类比</th>
              </tr>
            </thead>
            <tbody className="text-[#d4d4d4]">
              {[
                ["堆越界读取", "CWE-125", "程序读取超出堆缓冲区分配范围的内存", "一张 10 人名单，却去读第 15 个人"],
                ["堆越界写入", "CWE-787", "程序写入超出堆缓冲区分配范围的内存", "在白板上写答案，笔迹延伸到了别人的白板上"],
                ["整数溢出", "CWE-190", "算术运算结果超出数据类型能表示的范围", "汽车里程表从 999999 跳到 000000"],
                ["Null 终止符缺失", "CWE-170", "字符串缺少末尾的 \\0 结束标记", "一篇文章没有句号，读者不知道在哪停"],
                ["空指针解引用", "CWE-476", "通过空指针访问内存导致程序崩溃", "打开一个空盒子找东西"],
                ["释放后使用", "CWE-416", "访问已经释放（归还给系统）的内存", "退房后又回去找东西——房间可能已经被别人使用了"],
              ].map(([type, cwe, desc, analogy], i) => (
                <tr key={i} className="border-b border-[#262626] last:border-0">
                  <td className="px-5 py-3 font-medium">{type}</td>
                  <td className="px-5 py-3"><code className="text-blue-400 text-xs">{cwe}</code></td>
                  <td className="px-5 py-3 text-[#a3a3a3]">{desc}</td>
                  <td className="px-5 py-3 text-[#737373] hidden md:table-cell">{analogy}</td>
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
      </section>

      {/* Section 4: OpenHarmony Build Infrastructure */}
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
              { name: "Ninja 编译器", desc: "执行增量编译，调度 gcc/g++ 编译任务", icon: "ninja" },
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
          5. ASan/UBSan 检测能力
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
                ["allocation-size-too-big", "整数溢出导致异常大分配", "CWE-190"],
                ["heap-use-after-free", "释放后使用", "CWE-416"],
                ["stack-buffer-overflow", "栈缓冲区溢出", "CWE-121"],
                ["UBSan: signed-integer-overflow", "有符号整数溢出", "CWE-190"],
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
          6. GN+Ninja 构建管线
        </h2>
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-4">
          <div className="bg-[#0a0a0a] border border-[#262626] rounded p-4 font-mono text-sm text-[#a3a3a3]">
            <div className="space-y-1">
              <div className="text-white">{"OHOS 模块源码 (.c/.cpp)"}</div>
              <div className="text-[#737373]">{"    ↓ setup_build.py — 一键生成构建根目录"}</div>
              <div>{"GN 构建描述 (BUILD.gn)"}</div>
              <div className="text-[#737373]">{"    ↓ gn gen — 生成 ninja 构建规则"}</div>
              <div>{"Ninja 构建规则 (build.ninja)"}</div>
              <div className="text-[#737373]">{"    ↓ ninja — gcc/g++ 编译 + ASan 插桩"}</div>
              <div className="text-white">{"静态库 (.a) — 真实编译产物"}</div>
              <div className="text-[#737373]">{"    ↓ gcc/g++ 链接 PoC 测试驱动"}</div>
              <div>{"可执行文件（含 ASan runtime）"}</div>
              <div className="text-[#737373]">{"    ↓ 运行 — 构造恶意输入"}</div>
              <div className="text-green-400">{"ASan 报告 → 漏洞确认"}</div>
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
                ["源码准备", "setup_build.py", "OHOS 模块源码", "GN 构建根目录"],
                ["构建生成", "gn gen", "BUILD.gn 文件", "ninja 构建文件"],
                ["编译", "ninja (gcc/g++)", ".c/.cpp 源文件", ".o 目标文件"],
                ["打包", "ar rcs", ".o 目标文件", ".a 静态库"],
                ["链接", "gcc", "PoC.o + .a + ASan runtime", "可执行文件"],
                ["验证", "ASan + UBSan", "构造的恶意输入", "漏洞报告"],
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
              label: "C Target-Compile",
              value: verifiedIssues.filter((i) =>
                i.repo.includes("permission_lite") || i.repo.includes("config_policy")
              ).length.toString(),
              color: "text-blue-400",
            },
            {
              label: "C++ Target-Compile",
              value: verifiedIssues.filter((i) =>
                i.repo.includes("castengine")
              ).length.toString(),
              color: "text-green-400",
            },
            {
              label: "覆盖仓库",
              value: new Set(verifiedIssues.map((i) => i.repo)).size.toString(),
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
                ["PoC 类型声明", "PoC 是否可在真实设备触发、攻击前提等"],
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
                <span>纯 C 模块编译（permission_lite, config_policy）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>C++ 模块编译（castengine_wifi_display: DataBuffer, RtpPacket, RTCP）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>ASan heap-buffer-overflow 检测（READ + WRITE）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>ASan allocation-size-too-big 检测（整数溢出）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>UBSan 未定义行为检测</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>C++ 基础框架桩（RefBase, sptr, Parcel, IPC）</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">&#10003;</span>
                <span>客户端 + 服务端模块双向支持</span>
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
                <span>需要 OHOS 图形/音频框架的模块暂不支持</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>C++ 框架桩尚未在 IPC 模块中实际验证</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[#737373] mt-0.5">&#8722;</span>
                <span>setup_build.py 尚未自动检测 C++ 模块配置</span>
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
                ["C 编译器", "gcc 13.x + ASan + UBSan"],
                ["C++ 编译器", "g++ 13.x + ASan + UBSan"],
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
    NEEDS_REVIEW: { label: "Review", color: "text-purple-400", bg: "bg-purple-500/10" },
    FALSE_POSITIVE: { label: "FP", color: "text-[#737373]", bg: "bg-[#262626]" },
  };
  const c = config[status] || { label: status, color: "text-[#a3a3a3]", bg: "bg-[#262626]" };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${c.color} ${c.bg}`}>
      {c.label}
    </span>
  );
}
