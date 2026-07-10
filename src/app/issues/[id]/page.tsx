import { notFound } from "next/navigation";
import Link from "next/link";
import { getAllIssueIds, getIssue } from "@/lib/content";
import { getVendorLabel, getVendorColor } from "@/lib/vendors";
import IssueContent from "@/components/issue-content";
import PocViewer from "@/components/poc-viewer";
import AnalysisViewer from "@/components/analysis-viewer";
import ExportButton from "@/components/export-button";

export function generateStaticParams() {
  return getAllIssueIds().map((id) => ({ id }));
}

export const dynamicParams = false;

export default async function IssueDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const issue = getIssue(id);
  if (!issue) notFound();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-[var(--text-faint)] mb-6">
        <Link href="/" className="hover:text-[var(--text-primary)]">
          Dashboard
        </Link>
        <span>/</span>
        <Link href="/issues" className="hover:text-[var(--text-primary)]">
          Issues
        </Link>
        <span>/</span>
        <span className="text-[var(--text-muted)]">{issue.meta.id}</span>
      </div>

      {/* Header */}
      <div className="mb-8">
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <StatusBadge status={issue.meta.status} />
          {issue.meta.cwe && (
          <span className="text-xs font-mono text-blue-400 bg-[var(--pre-bg)] px-2 py-0.5 rounded border border-blue-500/20">
            {issue.meta.cwe}
            {issue.meta.cwe_name && ` — ${issue.meta.cwe_name}`}
          </span>
          )}
        </div>
        <h1 className="text-xl font-bold text-[var(--text-primary)] mb-4">
          {issue.meta.title}
        </h1>

        {/* Issue Reference */}
        <div className="flex flex-wrap items-center gap-3 mb-4">
          {issue.meta.issue_url && (
            <a
              href={issue.meta.issue_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2.5 bg-blue-600/20 border border-blue-500/40 rounded-lg text-blue-300 hover:bg-blue-600/30 hover:text-blue-200 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
              <span className="text-sm font-medium">View Upstream Issue</span>
              <span className="text-xs text-blue-400/70">{issue.meta.issue_url.replace(/https?:\/\//, '')}</span>
            </a>
          )}
          {!issue.meta.issue_url && issue.meta.internal_issue_id && (
            <span className="inline-flex items-center gap-2 px-4 py-2.5 bg-amber-600/20 border border-amber-500/40 rounded-lg text-amber-300">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <span className="text-sm font-medium">内网问题单</span>
              <span className="text-xs font-mono text-amber-400/80">{issue.meta.internal_issue_id}</span>
            </span>
          )}
          <ExportButton meta={issue.meta} content={issue.content} />
        </div>

        {/* Meta info */}
        <div className="bg-[var(--card-bg)] border border-[var(--card-border)] rounded-lg p-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
            {issue.meta.cwe && (
            <MetaRow label="CWE">
              <span className="text-[var(--text-secondary)] font-mono">
                {issue.meta.cwe}
                {issue.meta.cwe_name && ` — ${issue.meta.cwe_name}`}
              </span>
            </MetaRow>
            )}
            <MetaRow label="Repository">
              {issue.meta.repo_url ? (
                <a
                  href={issue.meta.repo_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300"
                >
                  {issue.meta.repo}
                </a>
              ) : (
                <span className="text-[var(--text-secondary)]">{issue.meta.repo}</span>
              )}
            </MetaRow>
            <MetaRow label="Date">
              <span className="text-[var(--text-secondary)]">{issue.meta.date}</span>
            </MetaRow>
            <MetaRow label="Vendor">
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${getVendorColor(issue.meta.vendor)}`}>
                {getVendorLabel(issue.meta.vendor)}
              </span>
            </MetaRow>
            {issue.meta.affected_version && (
              <MetaRow label="Affected Version">
                <span className="text-[var(--text-secondary)]">
                  {issue.meta.affected_version}
                </span>
              </MetaRow>
            )}
            {issue.meta.component && (
              <MetaRow label="Component">
                <span className="text-[var(--text-secondary)]">{issue.meta.component}</span>
              </MetaRow>
            )}
            {issue.meta.author && (
              <MetaRow label="Reporter">
                <span className="text-[var(--text-secondary)]">{issue.meta.author}</span>
              </MetaRow>
            )}
          </div>
          {issue.meta.file_paths && issue.meta.file_paths.length > 0 && (
            <div className="mt-3 pt-3 border-t border-[var(--card-border)]">
              <span className="text-xs text-[var(--text-faint)] uppercase tracking-wider">
                Affected Files
              </span>
              <div className="mt-1 flex flex-wrap gap-2">
                {issue.meta.file_paths.map((fp) => (
                  <code
                    key={fp}
                    className="text-xs bg-[var(--card-hover)] border border-[var(--card-border)] rounded px-2 py-0.5 text-[var(--text-muted)]"
                  >
                    {fp}
                  </code>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <IssueContent content={issue.content} />

      {/* PoC Section */}
      {issue.poc && issue.poc.files.length > 0 && (
        <>
        <div className="prose max-w-none"><hr /></div>
        <PocViewer
          files={issue.poc.files}
          output={issue.poc.output}
          report={issue.poc.report}
          issueId={issue.meta.id}
        />
        </>
      )}

      {/* Analysis Trace Section */}
      {issue.analysis && (
        <AnalysisViewer report={issue.analysis.report} />
      )}

      {/* Back link */}
      <div className="mt-8 pt-6 border-t border-[var(--card-border)]">
        <Link
          href="/issues"
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          &larr; Back to all issues
        </Link>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    CONFIRMED_REAL: "bg-green-500/20 text-green-400 border-green-500/30",
    CONFIRMED_FIXED: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    SUBMITTED: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    PENDING: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    FALSE_POSITIVE: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    CODE_QUALITY: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    CLOSED: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  const labels: Record<string, string> = {
    CONFIRMED_REAL: "Confirmed",
    CONFIRMED_FIXED: "Fixed",
    SUBMITTED: "Submitted",
    PENDING: "Pending",
    FALSE_POSITIVE: "False Positive",
    CODE_QUALITY: "Code Quality",
    CLOSED: "Closed",
  };
  return (
    <span
      className={`inline-flex items-center px-2.5 py-1 rounded text-xs font-semibold border ${colors[status] || "bg-gray-500/20 text-gray-400 border-gray-500/30"}`}
    >
      {labels[status] || status}
    </span>
  );
}

function MetaRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[var(--text-faint)] shrink-0">{label}:</span>
      {children}
    </div>
  );
}
