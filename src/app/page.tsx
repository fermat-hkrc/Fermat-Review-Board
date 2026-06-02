import Link from "next/link";
import { getAllIssues, getStats } from "@/lib/content";
import { getVendorLabel } from "@/lib/vendors";

function LanguageIcon({ language }: { language: string }) {
  const icons: Record<string, React.ReactElement> = {
    Rust: (
      <svg className="w-4 h-4 text-orange-400" fill="currentColor" viewBox="0 0 24 24">
        <path d="M23.834 11.441l-1.05-.096a10.74 10.74 0 00-.41-1.44l.87-.546a.344.344 0 00.12-.47l-.5-.866a.344.344 0 00-.47-.12l-.87.546a10.74 10.74 0 00-1.05-1.05l.546-.87a.344.344 0 00-.12-.47l-.866-.5a.344.344 0 00-.47.12l-.546.87a10.74 10.74 0 00-1.44-.41l-.096-1.05A.344.344 0 0017.2 4h-1a.344.344 0 00-.344.334l-.096 1.05a10.74 10.74 0 00-1.44.41l-.546-.87a.344.344 0 00-.47-.12l-.866.5a.344.344 0 00-.12.47l.546.87a10.74 10.74 0 00-1.05 1.05l-.87-.546a.344.344 0 00-.47.12l-.5.866a.344.344 0 00.12.47l.87.546a10.74 10.74 0 00-.41 1.44l-1.05.096A.344.344 0 009 11.8v1a.344.344 0 00.334.344l1.05.096a10.74 10.74 0 00.41 1.44l-.87.546a.344.344 0 00-.12.47l.5.866a.344.344 0 00.47.12l.87-.546a10.74 10.74 0 001.05 1.05l-.546.87a.344.344 0 00.12.47l.866.5a.344.344 0 00.47-.12l.546-.87a10.74 10.74 0 001.44.41l.096 1.05a.344.344 0 00.344.334h1a.344.344 0 00.344-.334l.096-1.05a10.74 10.74 0 001.44-.41l.546.87a.344.344 0 00.47.12l.866-.5a.344.344 0 00.12-.47l-.546-.87a10.74 10.74 0 001.05-1.05l.87.546a.344.344 0 00.47-.12l.5-.866a.344.344 0 00-.12-.47l-.87-.546a10.74 10.74 0 00.41-1.44l1.05-.096A.344.344 0 0024 12.8v-1a.344.344 0 00-.166-.359zM16.7 16.2a3.5 3.5 0 110-7 3.5 3.5 0 010 7z"/>
      </svg>
    ),
    C: (
      <svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    ),
    "C++": (
      <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4M16 8v8M8 8v8" />
      </svg>
    ),
    Python: (
      <svg className="w-4 h-4 text-yellow-400" fill="currentColor" viewBox="0 0 24 24">
        <path d="M14.25.18l.9.2.73.26.59.3.45.32.34.34.25.34.16.33.1.3.04.26.02.2-.01.13V8.5l-.05.63-.13.55-.21.46-.26.38-.3.31-.33.25-.35.19-.35.14-.33.1-.3.07-.26.04-.21.02H8.77l-.69.05-.59.14-.5.22-.41.27-.33.32-.27.35-.2.36-.15.37-.1.35-.07.32-.04.27-.02.21v3.06H3.17l-.21-.03-.28-.07-.32-.12-.35-.18-.36-.26-.36-.36-.35-.46-.32-.59-.28-.73-.21-.88-.14-1.05-.05-1.23.06-1.22.16-1.04.24-.87.32-.71.36-.57.4-.44.42-.33.42-.24.4-.16.36-.1.32-.05.24-.01h.16l.06.01h8.16v-.83H6.18l-.01-2.75-.02-.37.05-.34.11-.31.17-.28.25-.26.31-.23.38-.2.44-.18.51-.15.58-.12.64-.1.71-.06.77-.04.84-.02 1.27.05zm-6.3 1.98l-.23.33-.08.41.08.41.23.34.33.22.41.09.41-.09.33-.22.23-.34.08-.41-.08-.41-.23-.33-.33-.22-.41-.09-.41.09zm13.09 3.95l.28.06.32.12.35.18.36.27.36.35.35.47.32.59.28.73.21.88.14 1.04.05 1.23-.06 1.23-.16 1.04-.24.86-.32.71-.36.57-.4.45-.42.33-.42.24-.4.16-.36.09-.32.05-.24.02-.16-.01h-8.22v.82h5.84l.01 2.76.02.36-.05.34-.11.31-.17.29-.25.25-.31.24-.38.2-.44.17-.51.15-.58.13-.64.09-.71.07-.77.04-.84.01-1.27-.04-1.07-.14-.9-.2-.73-.25-.59-.3-.45-.33-.34-.34-.25-.34-.16-.33-.1-.3-.04-.25-.02-.2.01-.13v-5.34l.05-.64.13-.54.21-.46.26-.38.3-.32.33-.24.35-.2.35-.14.33-.1.3-.06.26-.04.21-.02.13-.01h5.84l.69-.05.59-.14.5-.21.41-.28.33-.32.27-.35.2-.36.15-.36.1-.35.07-.32.04-.28.02-.21V6.07h2.09l.14.01zm-6.47 14.25l-.23.33-.08.41.08.41.23.33.33.23.41.08.41-.08.33-.23.23-.33.08-.41-.08-.41-.23-.33-.33-.23-.41-.08-.41.08z"/>
      </svg>
    ),
  };
  return icons[language] || (
    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  );
}

function VendorIcon({ vendor }: { vendor: string }) {
  const icons: Record<string, React.ReactElement> = {
    public: (
      <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    terminal: (
      <svg className="w-4 h-4 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    ),
  };
  return icons[vendor] || (
    <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5" />
    </svg>
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
    FALSE_POSITIVE: "FP",
    CODE_QUALITY: "Quality",
    CLOSED: "Closed",
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

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
        <StatCard label="Total Issues" value={stats.total} href="/issues" />
        <StatCard
          label="Confirmed"
          value={stats.confirmed}
          accent="text-green-400"
          href="/confirmed"
        />
        <StatCard
          label="Submitted"
          value={stats.byStatus["SUBMITTED"] || 0}
          accent="text-amber-400"
          href="/issues?status=SUBMITTED"
        />
        <StatCard
          label="Pending"
          value={stats.byStatus["PENDING"] || 0}
          accent="text-cyan-400"
          href="/issues?status=PENDING"
        />
        <StatCard
          label="Repos"
          value={stats.repos}
          accent="text-purple-400"
        />
      </div>

      {/* Vendor Statistics */}
      {Object.keys(stats.byVendor).length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">By Vendor</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {Object.entries(stats.byVendor)
              .sort(([, a], [, b]) => b - a)
              .map(([vendor, count]) => (
                <Link
                  key={vendor}
                  href={`/vendor/${encodeURIComponent(vendor)}`}
                  className="bg-[#141414] border border-[#262626] rounded-lg p-4 hover:border-blue-500/50 hover:bg-[#1a1a1a] transition-all group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white group-hover:text-blue-400 transition-colors">
                      {getVendorLabel(vendor)}
                    </span>
                    <VendorIcon vendor={vendor} />
                  </div>
                  <div className="text-2xl font-bold text-blue-400">
                    {count}
                  </div>
                </Link>
              ))}
          </div>
        </div>
      )}

      {/* Language Statistics */}
      {Object.keys(stats.byLanguage).length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">By Language</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {Object.entries(stats.byLanguage)
              .sort(([, a], [, b]) => b - a)
              .map(([lang, count]) => (
                <Link
                  key={lang}
                  href={`/issues?language=${encodeURIComponent(lang)}`}
                  className="bg-[#141414] border border-[#262626] rounded-lg p-4 hover:border-blue-500/50 hover:bg-[#1a1a1a] transition-all group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white group-hover:text-blue-400 transition-colors">
                      {lang}
                    </span>
                    <LanguageIcon language={lang} />
                  </div>
                  <div className="text-2xl font-bold text-blue-400">
                    {count}
                  </div>
                </Link>
              ))}
          </div>
        </div>
      )}

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
                    {/* CWE */}
                    {issue.cwe && (
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-mono px-1.5 py-0.5 rounded bg-[#1a1a2e] text-blue-400 border border-blue-500/20">
                        {issue.cwe}
                        {issue.cwe_name && ` — ${issue.cwe_name}`}
                      </span>
                    </div>
                    )}
                    {/* Meta row */}
                    <div className="flex items-center gap-4 text-xs text-[#737373]">
                      <span className="font-mono">{issue.id}</span>
                      <span>{issue.repo}</span>
                      <span>{issue.date}</span>
                      {issue.language && (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                          <LanguageIcon language={issue.language} />
                          {issue.language}
                        </span>
                      )}
                      {issue.author && (
                        <span>by {issue.author}</span>
                      )}
                    </div>
                  </div>
                  {/* Right side: PoC + Issue links */}
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
                    {!issue.issue_url && issue.internal_issue_id && (
                      <span className="inline-flex items-center gap-1 text-xs font-medium px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        {issue.internal_issue_id}
                      </span>
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
  href,
}: {
  label: string;
  value: number;
  accent?: string;
  href?: string;
}) {
  const content = (
    <div className={`bg-[#141414] border border-[#262626] rounded-lg p-5 ${href ? "hover:border-[#404040] transition-colors cursor-pointer" : ""}`}>
      <span className="text-sm text-[#a3a3a3]">{label}</span>
      <div className={`text-3xl font-bold mt-1 ${accent || "text-white"}`}>
        {value}
      </div>
    </div>
  );
  if (href) {
    return <Link href={href}>{content}</Link>;
  }
  return content;
}
