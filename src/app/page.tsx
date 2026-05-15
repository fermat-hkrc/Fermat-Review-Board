import Link from "next/link";
import { getAllIssues, getStats } from "@/lib/content";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    LOW: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors[severity] || "bg-gray-500/20 text-gray-400 border-gray-500/30"}`}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    CONFIRMED_REAL: "bg-green-500/20 text-green-400 border-green-500/30",
    CONFIRMED_FIXED: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    SUBMITTED: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    NEEDS_REVIEW: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    FALSE_POSITIVE: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    CODE_QUALITY: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  };
  const labels: Record<string, string> = {
    CONFIRMED_REAL: "Confirmed",
    CONFIRMED_FIXED: "Fixed",
    SUBMITTED: "Submitted",
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

      {Object.keys(stats.byCwe).length > 0 && (
        <div className="bg-[#141414] border border-[#262626] rounded-lg p-6 mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">
            By CWE Category
          </h2>
          <div className="flex flex-wrap gap-3">
            {Object.entries(stats.byCwe).map(([cwe, count]) => (
              <div
                key={cwe}
                className="flex items-center gap-2 bg-[#1a1a1a] border border-[#262626] rounded-md px-3 py-2"
              >
                <span className="text-sm font-mono text-blue-400">{cwe}</span>
                <span className="text-sm text-[#a3a3a3]">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-[#262626] flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Recent Issues</h2>
          <Link
            href="/issues"
            className="text-sm text-blue-400 hover:text-blue-300"
          >
            View all &rarr;
          </Link>
        </div>
        <div className="divide-y divide-[#262626]">
          {issues.length === 0 ? (
            <div className="px-6 py-12 text-center text-[#737373]">
              No issues found. Add issue markdown files to{" "}
              <code className="text-[#a3a3a3]">content/issues/</code>.
            </div>
          ) : (
            issues.slice(0, 10).map((issue) => (
              <Link
                key={issue.id}
                href={`/issues/${issue.id}`}
                className="block px-6 py-4 hover:bg-[#1a1a1a] transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono text-[#737373]">
                        {issue.id}
                      </span>
                      <SeverityBadge severity={issue.severity} />
                      <StatusBadge status={issue.status} />
                    </div>
                    <h3 className="text-sm font-medium text-white truncate">
                      {issue.title}
                    </h3>
                    <div className="flex items-center gap-3 mt-1 text-xs text-[#737373]">
                      <span>{issue.repo}</span>
                      <span>{issue.cwe}</span>
                      <span>{issue.date}</span>
                    </div>
                  </div>
                  {issue.has_poc && (
                    <span className="shrink-0 text-xs bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded">
                      PoC
                    </span>
                  )}
                </div>
              </Link>
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
