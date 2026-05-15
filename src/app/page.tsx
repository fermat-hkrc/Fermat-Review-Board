import Link from "next/link";
import { getAllIssues, getStats } from "@/lib/content";

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    CONFIRMED_REAL: "bg-green-500/20 text-green-400 border-green-500/30",
    CONFIRMED_FIXED: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    SUBMITTED: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    PENDING: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    NEEDS_REVIEW: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    FALSE_POSITIVE: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    CODE_QUALITY: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  };
  const labels: Record<string, string> = {
    CONFIRMED_REAL: "Confirmed",
    CONFIRMED_FIXED: "Fixed",
    SUBMITTED: "Submitted",
    PENDING: "Pending",
    NEEDS_REVIEW: "Review",
    FALSE_POSITIVE: "FP",
    CODE_QUALITY: "Quality",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors[status] || "bg-gray-500/20 text-gray-400 border-gray-500/30"}`}
    >
      {labels[status] || status}
    </span>
  );
}

export default function DashboardPage() {
  const stats = getStats();
  const issues = getAllIssues();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white mb-2">
          Security Dashboard
        </h1>
        <p className="text-[#a3a3a3]">
          Fermat Security Scanner vulnerability findings across OpenHarmony,
          CANN, and AI project repositories.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard label="Total Issues" value={stats.total} />
        <StatCard
          label="Confirmed"
          value={stats.confirmed}
          accent="text-green-400"
        />
        <StatCard
          label="Repos"
          value={stats.repos}
          accent="text-purple-400"
        />
      </div>

      {/* Issues List */}
      <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-[#262626] flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Issues</h2>
          <Link
            href="/issues"
            className="text-sm text-blue-400 hover:text-blue-300"
          >
            View all &rarr;
          </Link>
        </div>
        <div className="divide-y divide-[#1e1e1e]">
          {issues.length === 0 ? (
            <div className="px-6 py-12 text-center text-[#737373]">
              No issues found.
            </div>
          ) : (
            issues.map((issue) => (
              <div
                key={issue.id}
                className="px-6 py-5 hover:bg-[#1a1a1a] transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    {/* Title row */}
                    <div className="flex items-center gap-2 mb-2">
                      <StatusBadge status={issue.status} />
                      <Link
                        href={`/issues/${issue.id}`}
                        className="text-[15px] font-medium text-white hover:text-blue-300 transition-colors"
                      >
                        {issue.title}
                      </Link>
                    </div>
                    {/* CWE + Repo info */}
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-[#1a1a2e] text-blue-400 border border-blue-500/20">
                        {issue.cwe}
                      </span>
                      {issue.cwe_name && (
                        <span className="text-xs text-[#a3a3a3]">
                          {issue.cwe_name}
                        </span>
                      )}
                    </div>
                    {/* Meta row */}
                    <div className="flex items-center gap-4 text-xs text-[#737373]">
                      <span className="font-mono">{issue.id}</span>
                      <span>{issue.repo}</span>
                      <span>{issue.date}</span>
                    </div>
                  </div>
                  {/* Right side: upstream link */}
                  <div className="shrink-0 flex items-center gap-2">
                    {issue.issue_url && (
                      <a
                        href={issue.issue_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-[#737373] hover:text-blue-400 transition-colors px-2 py-1 rounded border border-[#262626] hover:border-blue-500/30"
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
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <div className="bg-[#141414] border border-[#262626] rounded-lg p-5">
      <span className="text-sm text-[#a3a3a3]">{label}</span>
      <div className={`text-3xl font-bold mt-1 ${accent || "text-white"}`}>
        {value}
      </div>
    </div>
  );
}
