# Contributing to Fermat Review Board

## How to Report a Vulnerability

1. Fork this repository
2. Create a new branch: `git checkout -b issue/OH-2026-XXX`
3. Add your issue file in `content/issues/` following the template below
4. (Optional) Add PoC code in `content/pocs/{issue-id}/`
5. Submit a Pull Request

## Issue File Format

Create a markdown file at `content/issues/{ID}.md` with YAML frontmatter:

```markdown
---
id: OH-2026-XXX
date: "2026-05-15"
repo: repository_name
repo_url: https://gitcode.com/openharmony/repository_name
title: Brief description of the vulnerability
severity: HIGH          # CRITICAL / HIGH / MEDIUM / LOW
cwe: CWE-XXX
cwe_name: CWE Name
status: NEEDS_REVIEW    # NEEDS_REVIEW / CONFIRMED_REAL / CONFIRMED_FIXED / FALSE_POSITIVE
affected_version: "version info"
component: component_name
file_paths:
  - path/to/affected/file.c
author: your-github-username
---

## Vulnerability Summary

Describe the vulnerability...

## Root Cause

Show the problematic code...

## Impact

Explain the security impact...

## Fix Suggestion

Provide a suggested fix...
```

## Adding PoC Code

Place PoC files in `content/pocs/{issue-id}/`:

```
content/pocs/OH-2026-XXX/
├── poc.c           # PoC source code
├── build.sh        # Build instructions (optional)
└── output.txt      # Expected output / crash log (optional)
```

## Naming Convention

- Issue ID format: `{PROJECT}-{YEAR}-{CATEGORY}-{NUMBER}`
  - Example: `OH-2026-CRYPTO-001` (OpenHarmony, 2026, Crypto category, #001)
- Categories: CRYPTO, KERNEL, IPC, NET, FS, MEM, AUTH, etc.

## Local Development

```bash
npm install
npm run dev     # Start dev server at http://localhost:3000
npm run build   # Verify static export works
```

## Review Process

1. Maintainers review the PR for accuracy and completeness
2. If approved, the PR is merged and the site auto-deploys
3. Status may be updated later (NEEDS_REVIEW -> CONFIRMED_REAL -> CONFIRMED_FIXED)
