import Link from "next/link";
import { getConfirmedIssues } from "@/lib/content";

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    CONFIRMED_REAL: "bg-green-500/20 text-green-400 border-green-500/30",
    CONFIRMED_FIXED: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  const labels: Record<string, string> = {
    CONFIRMED_REAL: "Confirmed",
    CONFIRMED_FIXED: "Fixed",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors[status] || "bg-gray-500/20 text-gray-400 border-gray-500/30"}`}
    >
      {labels[status] || status}
    </span>
  );
}

export default function ConfirmedPage() {
  const issues = getConfirmedIssues();
  const confirmed = issues.filter((i) => i.status === "CONFIRMED_REAL");
  const fixed = issues.filter((i) => i.status === "CONFIRMED_FIXED");

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">
          Confirmed Vulnerabilities
        </h1>
        <p className="text-sm text-[#a3a3a3]">
          {issues.length} issues confirmed by upstream maintainers
          ({confirmed.length} confirmed, {fixed.length} fixed)
        </p>
      </div>

      {fixed.length > 0 && (
        <Section title="Fixed" issues={fixed} />
      )}
      {confirmed.length > 0 && (
        <Section title="Confirmed" issues={confirmed} />
      )}
      {issues.length === 0 && (
        <div className="bg-[#141414] border border-[#262626] rounded-lg px-6 py-12 text-center text-[#737373]">
          No confirmed or fixed issues yet.
        </div>
      )}
    </div>
  );
}

function Section({ title, issues }: { title: string; issues: ReturnType<typeof getConfirmedIssues> }) {
  return (
    <div className="mb-8">
      <h2 className="text-lg font-semibold text-white mb-3">{title}</h2>
      <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden divide-y divide-[#262626]">
        {issues.map((issue) => (
          <div
            key={issue.id}
            className="px-6 py-5 hover:bg-[#1a1a1a] transition-colors"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <StatusBadge status={issue.status} />
                  <Link
                    href={`/issues/${issue.id}`}
                    className="text-[15px] font-medium text-white hover:text-blue-300 transition-colors"
                  >
                    {issue.title}
                  </Link>
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-[#1a1a2e] text-blue-400 border border-blue-500/20">
                    {issue.cwe}
                    {issue.cwe_name && ` — ${issue.cwe_name}`}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-xs text-[#737373]">
                  <span className="font-mono">{issue.id}</span>
                  <span>{issue.repo}</span>
                  <span>{issue.date}</span>
                  {issue.author && (
                    <span>by {issue.author}</span>
                  )}
                </div>
              </div>
              <div className="shrink-0 flex items-center gap-2">
                {issue.has_poc && (
                  <Link
                    href={`/issues/${issue.id}#poc-验证`}
                    className="inline-flex items-center gap-1 text-xs font-medium px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/30 hover:bg-green-500/25 transition-colors"
                  >
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                    </svg>
                    PoC
                  </Link>
                )}
                {issue.issue_url && (
                  <a
                    href={issue.issue_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-xs font-medium px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 hover:bg-amber-500/25 transition-colors"
                  >
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                    Issue
                  </a>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
