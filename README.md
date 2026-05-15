# Fermat Review Board

Security vulnerability review board powered by [Fermat Security Scanner](https://github.com/fermat-hkrc/fermat-checker-generator). Tracks confirmed vulnerabilities across OpenHarmony, CANN, and AI project repositories with full evidence chains and PoC verification.

**Live site:** https://fermat-hkrc.github.io/Fermat-Review-Board/

---

## Contributing — How to Submit a Vulnerability

Anyone can contribute by submitting a Pull Request. Here's the workflow:

### 1. Fork & Clone

```bash
git clone https://github.com/<your-username>/Fermat-Review-Board.git
cd Fermat-Review-Board
git checkout -b issue/OH-2026-XXX
```

### 2. Create an Issue File

Add a markdown file at `content/issues/{ID}.md` with YAML frontmatter:

```markdown
---
id: OH-2026-XXX
date: "2026-05-15"
repo: repository_name
repo_url: https://gitcode.com/openharmony/repository_name
title: Brief vulnerability description
severity: HIGH              # CRITICAL / HIGH / MEDIUM / LOW
cwe: CWE-XXX
cwe_name: CWE Full Name
status: NEEDS_REVIEW        # NEEDS_REVIEW / CONFIRMED_REAL / CONFIRMED_FIXED
affected_version: "version"
component: component_name
file_paths:
  - path/to/affected/file.c
author: your-github-username
---

## Vulnerability Summary

Describe the vulnerability...

## Root Cause

Show the problematic code with code blocks...

## Impact

Explain the security impact...

## Fix Suggestion

Provide a suggested fix (preferably as a diff)...
```

### 3. (Optional) Add PoC Code

Place proof-of-concept files in `content/pocs/{issue-id}/`:

```
content/pocs/OH-2026-XXX/
├── poc.c           # PoC source code
├── build.sh        # Build instructions
└── output.txt      # Expected crash output / ASan log
```

### 4. Verify Locally

```bash
npm install
npm run build       # Must succeed — generates static site
```

### 5. Submit PR

```bash
git add content/
git commit -m "Add OH-2026-XXX: brief description"
git push origin issue/OH-2026-XXX
```

Then open a Pull Request. Maintainers will review and merge.

---

## Issue ID Convention

Format: `{PROJECT}-{YEAR}-{CATEGORY}-{NUMBER}`

| Project | Prefix |
|---------|--------|
| OpenHarmony | OH |
| CANN/Ascend | CANN |
| AI Projects | AI |

Categories: `CRYPTO`, `KERNEL`, `IPC`, `NET`, `FS`, `MEM`, `AUTH`, `UI`, etc.

---

## Severity Levels

| Level | Criteria |
|-------|----------|
| CRITICAL | Remote code execution, privilege escalation, no user interaction |
| HIGH | Memory corruption exploitable for info leak or DoS, crypto key leakage |
| MEDIUM | Null pointer crash (DoS), resource leak under specific conditions |
| LOW | Code quality issue with minor security implications |

---

## Local Development

```bash
npm install
npm run dev         # http://localhost:3000
npm run build       # Static export to ./out/
```

## Tech Stack

- Next.js 15 (Static Export) + TypeScript
- Tailwind CSS (dark theme)
- react-markdown + highlight.js (code rendering)
- GitHub Pages + GitHub Actions (auto-deploy on merge)

---

## License

MIT
