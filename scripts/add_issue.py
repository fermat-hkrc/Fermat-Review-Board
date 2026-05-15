#!/usr/bin/env python3
"""Interactive CLI to add a new issue to Fermat Review Board."""

import os
import sys
import re
from datetime import date
from pathlib import Path

CONTENT_DIR = Path(__file__).parent.parent / "content" / "issues"

PROJECTS = {"OH": "OpenHarmony", "CANN": "CANN/Ascend", "AI": "AI Projects"}
CATEGORIES = [
    "CRYPTO", "KERNEL", "IPC", "NET", "FS", "MEM", "AUTH", "TEL",
    "UI", "DRIVERS", "CAST", "DEVAUTH", "DEVMGR", "DSOFTBUS",
    "ACCESSTOKEN", "SECCOMP", "GRAPHIC", "CFGPOLICY", "HUKS",
    "APPVERIFY", "ARK", "TELREG", "OPS", "PYTORCH",
]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
STATUSES = ["CONFIRMED_REAL", "CONFIRMED_FIXED", "NEEDS_REVIEW"]


def prompt(msg, default=None, choices=None):
    if choices:
        print(f"\n  Options: {', '.join(choices)}")
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"  {msg}{suffix}: ").strip()
        if not val and default:
            return default
        if choices and val.upper() not in [c.upper() for c in choices]:
            print(f"  Invalid. Choose from: {', '.join(choices)}")
            continue
        return val


def find_next_id(project, category):
    pattern = re.compile(rf"^{project}-\d{{4}}-{category}-(\d{{3}})\.md$")
    max_num = 0
    if CONTENT_DIR.exists():
        for f in CONTENT_DIR.iterdir():
            m = pattern.match(f.name)
            if m:
                max_num = max(max_num, int(m.group(1)))
    return f"{project}-2026-{category}-{max_num + 1:03d}"


def main():
    print("\n=== Fermat Review Board — Add New Issue ===\n")

    # Project
    print("  Projects: " + ", ".join(f"{k} ({v})" for k, v in PROJECTS.items()))
    project = prompt("Project prefix", "OH", list(PROJECTS.keys())).upper()

    # Category
    print(f"\n  Categories: {', '.join(CATEGORIES)}")
    category = prompt("Category", None).upper()

    # Auto-generate ID
    issue_id = find_next_id(project, category)
    print(f"\n  Generated ID: {issue_id}")
    confirm = prompt("Use this ID? (y/n)", "y")
    if confirm.lower() != "y":
        issue_id = prompt("Enter custom ID")

    # Basic info
    repo = prompt("Repository name (e.g. security_crypto_framework)")

    default_host = "gitcode.com/openharmony" if project == "OH" else "gitcode.com/Ascend"
    repo_url = prompt(f"Repository URL", f"https://{default_host}/{repo}")

    title = prompt("Issue title (brief description)")
    severity = prompt("Severity", "MEDIUM", SEVERITIES).upper()
    cwe = prompt("CWE ID (e.g. CWE-476)")
    cwe_name = prompt("CWE name (e.g. NULL Pointer Dereference)")
    status = prompt("Status", "CONFIRMED_REAL", STATUSES).upper()
    issue_url = prompt("Upstream issue URL (leave empty if none)", "")
    issue_date = prompt("Discovery date (YYYY-MM-DD)", date.today().isoformat())
    author = prompt("Author (GitHub username)", "Zirui")
    finding_count = prompt("Number of findings in this issue", "1")

    # Optional
    affected_version = prompt("Affected version (optional, press Enter to skip)", "")
    file_paths_raw = prompt("Affected file paths (comma-separated, optional)", "")
    file_paths = [p.strip() for p in file_paths_raw.split(",") if p.strip()] if file_paths_raw else []

    # Build frontmatter
    lines = ["---"]
    lines.append(f"id: {issue_id}")
    lines.append(f'date: "{issue_date}"')
    lines.append(f"repo: {repo}")
    lines.append(f"repo_url: {repo_url}")
    lines.append(f'title: "{title}"')
    lines.append(f"severity: {severity}")
    lines.append(f"cwe: {cwe}")
    lines.append(f"cwe_name: {cwe_name}")
    lines.append(f"status: {status}")
    if issue_url:
        lines.append(f"issue_url: {issue_url}")
    if affected_version:
        lines.append(f'affected_version: "{affected_version}"')
    if file_paths:
        lines.append("file_paths:")
        for fp in file_paths:
            lines.append(f"  - {fp}")
    lines.append(f"finding_count: {finding_count}")
    lines.append(f"author: {author}")
    lines.append("---")
    lines.append("")
    lines.append(f"## {title}")
    lines.append("")
    lines.append(f"**{cwe}**: {cwe_name}")
    lines.append("")
    lines.append("<!-- Add detailed vulnerability description below -->")
    lines.append("")
    lines.append("## 漏洞概述")
    lines.append("")
    lines.append("TODO: 描述漏洞...")
    lines.append("")
    lines.append("## 问题代码")
    lines.append("")
    lines.append("```cpp")
    lines.append("// TODO: 添加问题代码")
    lines.append("```")
    lines.append("")
    lines.append("## 影响分析")
    lines.append("")
    lines.append("TODO: 描述影响...")
    lines.append("")
    lines.append("## 修复建议")
    lines.append("")
    lines.append("```diff")
    lines.append("// TODO: 添加修复建议")
    lines.append("```")
    lines.append("")

    content = "\n".join(lines)

    # Write file
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)
    filepath = CONTENT_DIR / f"{issue_id}.md"

    if filepath.exists():
        overwrite = prompt(f"File {filepath.name} already exists. Overwrite? (y/n)", "n")
        if overwrite.lower() != "y":
            print("  Aborted.")
            sys.exit(1)

    filepath.write_text(content)
    print(f"\n  Created: {filepath}")
    print(f"\n  Next steps:")
    print(f"    1. Edit {filepath.name} to add detailed vulnerability description")
    print(f"    2. Run: npm run build  (verify it builds)")
    print(f"    3. Run: git add content/issues/{issue_id}.md")
    print(f"    4. Run: git commit -m 'Add {issue_id}: {title}'")
    print(f"    5. Run: git push")
    print()


if __name__ == "__main__":
    main()
