"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import rehypeSlug from "rehype-slug";

export default function AnalysisViewer({
  report,
}: {
  report: string;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="mt-6 border-2 border-purple-500/30 rounded-xl overflow-hidden bg-[var(--card-bg)]">
      {/* Collapsible Header */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-6 py-4 flex items-center justify-between bg-purple-500/10 hover:bg-purple-500/15 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-purple-500/20 border border-purple-500/30">
            <svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </span>
          <div>
            <span className="text-base font-semibold text-purple-300">
              Analysis Trace
            </span>
            <span className="ml-3 text-xs text-purple-500/70">
              CVE pattern tracing + spec matching
            </span>
          </div>
        </div>
        <span className="text-purple-500/60 text-sm">{open ? "▼" : "▶"}</span>
      </button>

      {/* Collapsed hint */}
      {!open && (
        <div className="px-6 py-3 text-xs text-purple-500/50 border-t border-purple-500/10">
          Click to expand: how this vulnerability was discovered via property modeling
        </div>
      )}

      {/* Expanded Content */}
      {open && (
        <div className="border-t border-purple-500/20 p-6">
          <div className="prose max-w-none">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              rehypePlugins={[rehypeSlug, rehypeHighlight]}
            >
              {report}
            </ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
}
