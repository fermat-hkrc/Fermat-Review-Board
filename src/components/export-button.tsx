"use client";

import type { IssueMeta } from "@/lib/content";

interface ExportButtonProps {
  meta: IssueMeta;
  content: string;
}

export default function ExportButton({ meta, content }: ExportButtonProps) {
  function handleExport() {
    const rows: string[] = [];

    rows.push(`| 字段 | 值 |`);
    rows.push(`|------|-----|`);
    if (meta.cwe) {
      const cweVal = meta.cwe_name ? `${meta.cwe} — ${meta.cwe_name}` : meta.cwe;
      rows.push(`| CWE | ${cweVal} |`);
    }
    if (meta.severity) {
      rows.push(`| 严重程度 | ${meta.severity} |`);
    }
    if (meta.component) {
      rows.push(`| 组件 | ${meta.component} |`);
    }
    if (meta.repo) {
      rows.push(`| 仓库 | ${meta.repo} |`);
    }
    if (meta.file_paths && meta.file_paths.length > 0) {
      rows.push(`| 影响文件 | ${meta.file_paths.map(f => `\`${f}\``).join(", ")} |`);
    }

    const md = `# ${meta.title}\n\n${rows.join("\n")}\n\n${content.trim()}\n`;

    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${meta.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <button
      onClick={handleExport}
      className="inline-flex items-center gap-2 px-3 py-1.5 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] border border-[var(--card-border)] hover:border-[var(--text-faint)] rounded-lg transition-colors"
    >
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
      导出提单
    </button>
  );
}
