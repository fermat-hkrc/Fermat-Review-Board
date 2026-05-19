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
          <Link
            key={issue.id}
            href={`/issues/${issue.id}`}
            className="block px-5 py-4 hover:bg-[#1a1a1a] transition-colors"
          >
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-xs font-mono text-[#737373]">
                {issue.id}
              </span>
              <StatusBadge status={issue.status} />
              {issue.has_poc && (
                <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">
                  PoC
                </span>
              )}
              <span className="text-xs font-mono text-blue-400">
                {issue.cwe}{issue.cwe_name && ` — ${issue.cwe_name}`}
              </span>
            </div>
            <h3 className="text-sm font-medium text-white mb-1">
              {issue.title}
            </h3>
            <div className="flex items-center gap-4 text-xs text-[#737373]">
              <span>{issue.repo}</span>
              <span>{issue.date}</span>
              {issue.issue_url && (
                <span className="text-amber-400">has upstream issue</span>
              )}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
