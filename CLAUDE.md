# Fermat Review Board

安全漏洞审查看板。部署在 GitHub Pages: https://fermat-hkrc.github.io/Fermat-Review-Board/

## 项目结构

- `content/issues/` — 漏洞报告（Markdown + YAML frontmatter）
- `content/pocs/` — PoC 代码
- `src/` — Next.js 前端
- `scripts/` — 工具脚本

## 内容规范（必须遵守）

### 写作风格

- **冰冷理性，CVE 风格**。不要出现"你好"、"特此报告"、"我们发现"等措辞。直接陈述问题。
- **不要包含置信度/confidence**。无论是 frontmatter 还是正文，都不需要 confidence/置信度字段。提单即代表需要处理。
- **不要包含扫描元数据**。不要写"发现工具"、"扫描时间"、"LLM 调用次数"等。只写和漏洞本身相关的内容。
- **一个漏洞一个条目**。即使上游 issue 链接里包含多个漏洞（合并提单），在 Review Board 里必须拆分为独立条目。每个条目对应 `~/data/output` 中的一个独立发现。

### Status 规则

- `SUBMITTED` — 已提单，等待上游确认（默认状态）
- `CONFIRMED_REAL` — 上游开发人员已确认是真实漏洞
- `CONFIRMED_FIXED` — 已确认并已修复
- `PENDING` — 尚未提单
- `FALSE_POSITIVE` — 误报

**重要**：只有上游明确确认后才能标记为 CONFIRMED。提单不等于确认。

## 添加新 Issue

**重要**: 在添加 issue 前，必须阅读 `ISSUE-FORMAT-GUIDE.md` 了解格式规范。

**核心原则**: 漏洞描述和 PoC 验证必须分离。Issue 只描述漏洞技术细节，不包含 PoC 验证章节。

当用户要求添加新的漏洞 issue 时，按以下流程操作：

### 1. 确定 Issue ID

格式：`{项目}-{年份}-{类别}-{序号}`

- 项目前缀：`OH`（OpenHarmony）、`CANN`（CANN/Ascend）、`AI`（AI 项目）
- 类别：`CRYPTO`, `KERNEL`, `IPC`, `NET`, `FS`, `MEM`, `AUTH`, `TEL`, `UI`, `DRIVERS` 等
- 序号：查看 `content/issues/` 中同类别最大序号 +1

### 2. 创建 Issue 文件

在 `content/issues/{ID}.md` 创建文件，必须包含以下 frontmatter：

```yaml
---
id: OH-2026-XXX-001          # 必填
date: "2026-05-15"           # 必填，发现日期
repo: repository_name        # 必填，仓库名
repo_url: https://gitcode.com/openharmony/xxx  # 必填
title: 漏洞简述              # 必填，纯技术描述
severity: HIGH               # 必填：CRITICAL / HIGH / MEDIUM / LOW
cwe: CWE-476                 # 必填
cwe_name: NULL Pointer Dereference  # 必填，CWE 全称
status: SUBMITTED            # 必填：默认 SUBMITTED
issue_url: https://gitcode.com/xxx/issues/123  # 上游提单链接（如有）
affected_version: "版本信息"  # 可选
component: 组件名            # 可选
file_paths:                  # 可选，受影响文件列表
  - path/to/file.c
author: github-username      # 必填
---
```

### 3. 正文格式

**❌ 禁止包含以下章节**:
- "PoC 验证"
- "PoC 路径"
- "触发方式"（命令行示例）
- "实际结果"（PoC 输出）
- "源码验证"状态说明

**✅ 标准结构**:

```markdown
## 漏洞概述

直接描述问题。不要寒暄。

## 根本原因

**位置**: `file.rs:123`

代码块 + 问题说明。

## 影响

- 影响 1
- 影响 2

## 触发条件

1. 条件 A（攻击步骤，不是 PoC 运行步骤）
2. 条件 B

## 修复建议

diff 格式的修复代码。

## 参考

- RFC/标准
- CWE 链接
```

**参考**: 查看 `ISSUE-FORMAT-GUIDE.md` 获取详细说明和示例。

### 4. 验证

```bash
npm run build   # 必须成功
```

### 5. 提交

```bash
git add content/issues/{ID}.md
git commit -m "Add {ID}: 简述"
git push
```

## 严重程度标准

| Level | 标准 |
|-------|------|
| CRITICAL | 远程代码执行、权限提升、无需用户交互 |
| HIGH | 内存破坏可利用、密钥泄漏、授权缺失 |
| MEDIUM | 空指针崩溃（DoS）、特定条件下的资源泄漏 |
| LOW | 代码质量问题、需要特殊条件才能触发 |

## PoC 页面

`/poc` 路由向用户解释 PoC 验证方法论（Target-Compile、ASan 检测、OHOS 编译基础设施、已验证案例等）。
内容直接在 `src/app/poc/page.tsx` 中维护（不使用外部 markdown 文件）。

在以下情况更新此页面：
- 新的 PoC 类型支持（如 NAPI 模块、IPC harness）
- 新的技术挑战被发现（添加到第 8 节的技术挑战列表）
- 构建工具链发生重大变化（桩代码新增、工具链更新）
- ASan/UBSan 检测能力扩展
- 新的已验证 PoC 案例提交（Section 7 自动从 content/issues 读取 has_poc: true 的 issue）

## 开发

```bash
npm install
npm run dev     # 本地开发 http://localhost:3000
npm run build   # 静态导出到 ./out/
```

## 工具脚本

```bash
python scripts/add_issue.py   # 交互式添加新 issue
```
