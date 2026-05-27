# Dashboard Issue 格式规范

**重要原则**: 漏洞描述和 PoC 验证必须分离

---

## ❌ 错误示例（不要这样写）

```markdown
## 影响

- 远程 DoS
- 内存损坏

## PoC 验证

**PoC 路径**: `content/pocs/XXX/`

**触发方式**:
\`\`\`bash
cd content/pocs/XXX
cargo run
\`\`\`

**实际结果**:
\`\`\`
panic at line 123
\`\`\`
```

---

## ✅ 正确示例（应该这样写）

```markdown
## 影响

- 远程 DoS
- 内存损坏

## 触发条件

1. 攻击者建立连接
2. 发送恶意数据
3. 触发漏洞
```

---

## 原因

1. **职责分离**:
   - Issue 描述：漏洞本身的技术细节（代码、原因、影响、触发条件）
   - PoC 页面：验证方法论（如何构建、如何运行、验证标准）

2. **避免冗余**:
   - PoC 的构建和运行方式在 `/poc` 页面统一说明
   - Issue 只需要 `has_poc: true` 标记即可

3. **保持一致性**:
   - 所有 issue 格式统一
   - 参考 RUST-2026-YLONG-HTTP-001 的格式

---

## Issue 标准结构

```markdown
---
id: XXX-2026-YYY-001
date: "2026-05-27"
repo: repository_name
repo_url: https://gitcode.com/xxx
title: 漏洞简述
severity: HIGH
cwe: CWE-XXX
cwe_name: CWE Name
status: PENDING
component: 组件名
language: Rust
file_paths:
  - path/to/file
author: author-name
has_poc: true  # 如果有 PoC
---

## 漏洞概述

直接描述问题。

## 根本原因

**位置**: `file.rs:123`

\`\`\`rust
// 问题代码
\`\`\`

**问题**:
1. 问题 1
2. 问题 2

## 影响

- 影响 1
- 影响 2

## 触发条件

1. 条件 1
2. 条件 2

## 修复建议

\`\`\`rust
// 修复代码
\`\`\`

## 参考

- RFC/标准
- CWE 链接
```

---

## 检查清单

在提交 issue 前检查：

- [ ] 没有 "PoC 验证" 章节
- [ ] 没有 "PoC 路径" 说明
- [ ] 没有 "触发方式" 的命令行示例
- [ ] 没有 "实际结果" 的输出
- [ ] 没有 "源码验证" 状态说明
- [ ] 只有 `has_poc: true` 标记（如果有 PoC）
- [ ] 格式与 RUST-2026-YLONG-HTTP-001 一致

---

## PoC 文件组织

PoC 相关内容放在：
- `content/pocs/{issue-id}/` - PoC 源码（扁平结构）
- `/poc` 页面 - 验证方法论统一说明

---

**记住**: Issue 描述漏洞，PoC 页面描述验证方法。两者分离！
