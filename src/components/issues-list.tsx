"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { IssueMeta } from "@/lib/content";

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

export default function IssuesListClient({
  issues,
}: {
  issues: IssueMeta[];
}) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const severities = [...new Set(issues.map((i) => i.severity))];
  const statuses = [...new Set(issues.map((i) => i.status))];

  const filtered = issues.filter((issue) => {
    if (search) {
      const q = search.toLowerCase();
      const match =
        issue.title.toLowerCase().includes(q) ||
        issue.id.toLowerCase().includes(q) ||
        issue.repo.toLowerCase().includes(q) ||
        issue.cwe.toLowerCase().includes(q);
      if (!match) return false;
    }
    if (severityFilter && issue.severity !== severityFilter) return false;
    if (statusFilter && issue.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">All Issues</h1>
        <p className="text-sm text-[#a3a3a3]">
          {issues.length} total issues across all scanned repositories
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-6">
        <input
          type="text"
          placeholder="Search issues..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-[#141414] border border-[#262626] rounded-md px-3 py-1.5 text-sm text-white placeholder-[#737373] focus:outline-none focus:border-blue-500 w-64"
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#141414] border border-[#262626] rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Severities</option>
          {severities.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-[#141414] border border-[#262626] rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Statuses</option>
          {statuses.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {(search || severityFilter || statusFilter) && (
          <button
            onClick={() => {
              setSearch("");
              setSeverityFilter("");
              setStatusFilter("");
            }}
            className="text-sm text-[#a3a3a3] hover:text-white px-2"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Issues Table */}
      <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#262626] text-left text-xs text-[#737373] uppercase tracking-wider">
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3 hidden md:table-cell">Repository</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3 hidden sm:table-cell">CWE</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3 hidden lg:table-cell">Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#262626]">
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={7}
                  className="px-4 py-12 text-center text-[#737373]"
                >
                  No issues match your filters.
                </td>
              </tr>
            ) : (
              filtered.map((issue) => (
                <tr
                  key={issue.id}
                  className="hover:bg-[#1a1a1a] transition-colors"
                >
                  <td className="px-4 py-3">
                    <Link
                      href={`/issues/${issue.id}`}
                      className="text-sm font-mono text-blue-400 hover:text-blue-300"
                    >
                      {issue.id}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      href={`/issues/${issue.id}`}
                      className="text-sm text-white hover:text-blue-300"
                    >
                      {issue.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell text-sm text-[#a3a3a3]">
                    {issue.repo}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={issue.severity} />
                  </td>
                  <td className="px-4 py-3 hidden sm:table-cell text-sm font-mono text-[#a3a3a3]">
                    {issue.cwe}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={issue.status} />
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell text-sm text-[#737373]">
                    {issue.date}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
