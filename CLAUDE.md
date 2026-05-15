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
- `NEEDS_REVIEW` — 需要内部 review（尚未提单）
- `FALSE_POSITIVE` — 误报

**重要**：只有上游明确确认后才能标记为 CONFIRMED。提单不等于确认。

## 添加新 Issue

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

```markdown
## 漏洞概述

直接描述问题。不要寒暄。

## 问题代码

代码块 + 行号标注。

## 触发条件

1. 条件 A
2. 条件 B

## 影响

- 影响 1
- 影响 2

## 修复建议

diff 格式的修复代码。
```

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
