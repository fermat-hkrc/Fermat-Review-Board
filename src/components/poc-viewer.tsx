"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeHighlight from "rehype-highlight";
import rehypeSlug from "rehype-slug";

interface PocFile {
  name: string;
  content: string;
  language: string;
}

export default function PocViewer({
  files,
  output,
  report,
  issueId,
}: {
  files: PocFile[];
  output?: string;
  report?: string;
  issueId: string;
}) {
  const [open, setOpen] = useState(false);
  const totalFiles = files.length + (output ? 1 : 0);

  return (
    <div className="mt-10 border-2 border-emerald-500/30 rounded-xl overflow-hidden bg-[#0d1117]">
      {/* Collapsible Header */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-6 py-4 flex items-center justify-between bg-emerald-500/10 hover:bg-emerald-500/15 transition-colors text-left"
      >
        <div className="flex items-center gap-3">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-500/30">
            <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
          </span>
          <div>
            <span className="text-base font-semibold text-emerald-300">
              Proof of Concept
            </span>
            <span className="ml-3 text-xs text-emerald-500/70">
              {totalFiles} file{totalFiles !== 1 ? "s" : ""}
              {report ? " + report" : ""}
            </span>
          </div>
        </div>
        <span className="text-emerald-500/60 text-sm">{open ? "▼" : "▶"}</span>
      </button>

      {/* Collapsed hint */}
      {!open && (
        <div className="px-6 py-3 text-xs text-emerald-500/50 border-t border-emerald-500/10">
          Click to expand PoC verification details
        </div>
      )}

      {/* Expanded Content */}
      {open && (
        <div className="border-t border-emerald-500/20 p-6 space-y-6">
          {/* PoC Report (markdown) */}
          {report && (
            <div className="prose max-w-none">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                rehypePlugins={[rehypeSlug, rehypeHighlight]}
              >
                {report}
              </ReactMarkdown>
            </div>
          )}

          {/* PoC Source Files */}
          {files.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-emerald-300 mb-3 flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full" />
                Source Files
              </h3>
              {files.map((file) => (
                <PocFileCard key={file.name} file={file} issueId={issueId} />
              ))}
            </div>
          )}

          {/* ASan / Run Output */}
          {output && (
            <CollapsibleBlock title="Run Output" defaultOpen={true}>
              <pre className="p-4 overflow-x-auto text-sm leading-relaxed text-green-400 font-mono whitespace-pre-wrap">
                {output}
              </pre>
            </CollapsibleBlock>
          )}
        </div>
      )}
    </div>
  );
}

function PocFileCard({ file, issueId }: { file: PocFile; issueId: string }) {
  const lines = file.content.split("\n").length;
  const bytes = new Blob([file.content]).size;
  const sizeLabel =
    bytes > 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
  const isLarge = lines > 80;
  const downloadHref = `https://github.com/fermat-hkrc/Fermat-Review-Board/raw/main/content/pocs/${issueId}/${file.name}`;

  return (
    <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden mb-4">
      <div className="px-4 py-3 border-b border-[#262626] flex items-center justify-between bg-[#1a1a1a]">
        <div className="flex items-center gap-3">
          <span className="text-sm font-mono text-[#e5e5e5]">{file.name}</span>
          <span className="text-xs text-[#525252]">
            {lines} lines &middot; {sizeLabel}
          </span>
        </div>
        <a
          href={downloadHref}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs text-[#737373] hover:text-blue-400 transition-colors px-2 py-1 rounded border border-[#262626] hover:border-blue-500/30"
        >
          <svg
            className="w-3 h-3"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
            />
          </svg>
          Download
        </a>
      </div>
      <CollapsibleBlock
        title={null}
        defaultOpen={!isLarge}
        collapsedLabel={`Click to expand (${lines} lines)`}
      >
        <pre className="p-4 overflow-x-auto text-[13px] leading-relaxed">
          <code className="text-[#d4d4d4] font-mono">{file.content}</code>
        </pre>
      </CollapsibleBlock>
    </div>
  );
}

function CollapsibleBlock({
  title,
  defaultOpen,
  collapsedLabel,
  children,
}: {
  title: string | null;
  defaultOpen: boolean;
  collapsedLabel?: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  if (title) {
    return (
      <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden mb-4">
        <button
          onClick={() => setOpen(!open)}
          className="w-full px-4 py-2 border-b border-[#262626] flex items-center justify-between bg-[#1a1a1a] hover:bg-[#222] transition-colors text-left"
        >
          <span className="text-sm font-mono text-[#a3a3a3]">{title}</span>
          <span className="text-xs text-[#525252]">{open ? "▼" : "▶"}</span>
        </button>
        {open && children}
      </div>
    );
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="w-full px-4 py-3 text-center text-xs text-[#525252] hover:text-[#a3a3a3] hover:bg-[#1a1a1a] transition-colors"
      >
        {collapsedLabel || "Click to expand"}
      </button>
    );
  }

  return <>{children}</>;
}
