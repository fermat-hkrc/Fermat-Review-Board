"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { IssueMeta } from "@/lib/content";

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

export default function IssuesListClient({
  issues,
}: {
  issues: IssueMeta[];
}) {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const statuses = [...new Set(issues.map((i) => i.status))];

  const filtered = issues.filter((issue) => {
    if (search) {
      const q = search.toLowerCase();
      const match =
        issue.title.toLowerCase().includes(q) ||
        issue.id.toLowerCase().includes(q) ||
        issue.repo.toLowerCase().includes(q) ||
        issue.cwe.toLowerCase().includes(q) ||
        (issue.cwe_name || "").toLowerCase().includes(q);
      if (!match) return false;
    }
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
        {(search || statusFilter) && (
          <button
            onClick={() => {
              setSearch("");
              setStatusFilter("");
            }}
            className="text-sm text-[#a3a3a3] hover:text-white px-2"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Issues List */}
      <div className="bg-[#141414] border border-[#262626] rounded-lg overflow-hidden divide-y divide-[#262626]">
        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center text-[#737373]">
            No issues match your filters.
          </div>
        ) : (
          filtered.map((issue) => (
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
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}
