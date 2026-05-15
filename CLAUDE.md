# Fermat Review Board

安全漏洞审查看板。部署在 GitHub Pages: https://fermat-hkrc.github.io/Fermat-Review-Board/

## 项目结构

- `content/issues/` — 漏洞报告（Markdown + YAML frontmatter）
- `content/pocs/` — PoC 代码
- `src/` — Next.js 前端
- `scripts/` — 工具脚本

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
title: 漏洞简述              # 必填
severity: HIGH               # 必填：CRITICAL / HIGH / MEDIUM / LOW
cwe: CWE-476                 # 必填
cwe_name: NULL Pointer Dereference  # 必填
status: CONFIRMED_REAL       # 必填：CONFIRMED_REAL / CONFIRMED_FIXED / NEEDS_REVIEW
issue_url: https://gitcode.com/xxx/issues/123  # 上游提单链接（如有）
affected_version: "版本信息"  # 可选
component: 组件名            # 可选
file_paths:                  # 可选，受影响文件列表
  - path/to/file.c
finding_count: 1             # 可选，包含的漏洞发现数量
author: github-username      # 必填
---
```

Markdown body 包含：漏洞概述、问题代码、触发条件、影响分析、修复建议。

### 3. 验证

```bash
npm run build
```

必须成功才能提交。

### 4. 提交

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
