import fs from "fs";
import path from "path";
import matter from "gray-matter";
import { DEFAULT_VENDOR } from "./vendors";

const issuesDirectory = path.join(process.cwd(), "content/issues");
const pocsDirectory = path.join(process.cwd(), "content/pocs");
const analysisDirectory = path.join(process.cwd(), "content/analysis");

export interface IssueMeta {
  id: string;
  date: string;
  repo: string;
  repo_url: string;
  title: string;
  severity?: string;
  cwe: string;
  cwe_name?: string;
  status: string;
  vendor: string;
  language?: string;
  affected_version?: string;
  component?: string;
  issue_url?: string;
  internal_issue_id?: string;
  file_paths?: string[];
  author?: string;
  has_poc?: boolean;
}

export interface Issue {
  meta: IssueMeta;
  content: string;
  poc?: PocData;
  analysis?: AnalysisData;
}

export interface PocData {
  files: { name: string; content: string; language: string }[];
  output?: string;
  report?: string;
}

export interface AnalysisData {
  report: string;
}

export function getAllIssueIds(): string[] {
  if (!fs.existsSync(issuesDirectory)) return [];
  return fs
    .readdirSync(issuesDirectory)
    .filter((f) => f.endsWith(".md"))
    .map((f) => f.replace(/\.md$/, ""));
}

export function getAllIssues(): IssueMeta[] {
  const ids = getAllIssueIds();
  return ids
    .map((id) => getIssueMeta(id))
    .filter((m): m is IssueMeta => m !== null)
    .filter((m) => m.status !== "CLOSED")
    .sort((a, b) => b.date.localeCompare(a.date));
}

export function getIssueMeta(id: string): IssueMeta | null {
  const filePath = path.join(issuesDirectory, `${id}.md`);
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf-8");
  const { data } = matter(raw);
  const meta = data as IssueMeta;
  if (!meta.vendor) meta.vendor = DEFAULT_VENDOR;
  if (!meta.has_poc) {
    const pocDir = path.join(pocsDirectory, id);
    if (fs.existsSync(pocDir)) {
      const entries = fs.readdirSync(pocDir).filter((f) => !f.startsWith("."));
      if (entries.length > 0) meta.has_poc = true;
    }
  }
  return meta;
}

export function getIssue(id: string): Issue | null {
  const filePath = path.join(issuesDirectory, `${id}.md`);
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf-8");
  const { data, content } = matter(raw);
  const poc = getPocData(id);
  const analysis = getAnalysisData(id);
  return { meta: data as IssueMeta, content, poc: poc ?? undefined, analysis: analysis ?? undefined };
}

function getPocData(issueId: string): PocData | null {
  const pocDir = path.join(pocsDirectory, issueId);
  if (!fs.existsSync(pocDir)) return null;
  const entries = fs.readdirSync(pocDir);
  const files = entries
    .filter((f) => !f.startsWith("."))
    .map((f) => {
      const ext = path.extname(f).slice(1);
      const langMap: Record<string, string> = {
        c: "c",
        cpp: "cpp",
        h: "c",
        py: "python",
        sh: "bash",
        txt: "text",
        md: "markdown",
      };
      return {
        name: f,
        content: fs.readFileSync(path.join(pocDir, f), "utf-8"),
        language: langMap[ext] || "text",
      };
    });
  const outputFile = files.find((f) => f.name === "output.txt");
  const reportFile = files.find((f) => f.name === "poc-report.md");
  return {
    files: files.filter((f) => f.name !== "output.txt" && f.name !== "poc-report.md"),
    output: outputFile?.content,
    report: reportFile?.content,
  };
}

function getAnalysisData(issueId: string): AnalysisData | null {
  const analysisDir = path.join(analysisDirectory, issueId);
  if (!fs.existsSync(analysisDir)) return null;
  const reportPath = path.join(analysisDir, "analysis-report.md");
  if (!fs.existsSync(reportPath)) return null;
  return {
    report: fs.readFileSync(reportPath, "utf-8"),
  };
}

export function getVerifiedPocIssues(): IssueMeta[] {
  const issues = getAllIssues();
  return issues.filter((i) => i.has_poc === true);
}

export function getConfirmedIssues(): IssueMeta[] {
  const issues = getAllIssues();
  return issues.filter(
    (i) => i.status === "CONFIRMED_REAL" || i.status === "CONFIRMED_FIXED"
  );
}

export function getStats() {
  const issues = getAllIssues();
  const byCwe: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  const byRepo: Record<string, number> = {};
  const byLanguage: Record<string, number> = {};
  const byVendor: Record<string, number> = {};

  for (const issue of issues) {
    const cweLabel = issue.cwe_name
      ? `${issue.cwe} ${issue.cwe_name}`
      : issue.cwe;
    byCwe[cweLabel] = (byCwe[cweLabel] || 0) + 1;
    byStatus[issue.status] = (byStatus[issue.status] || 0) + 1;
    byRepo[issue.repo] = (byRepo[issue.repo] || 0) + 1;
    byVendor[issue.vendor] = (byVendor[issue.vendor] || 0) + 1;
    if (issue.language) {
      byLanguage[issue.language] = (byLanguage[issue.language] || 0) + 1;
    }
  }

  return {
    total: issues.length,
    confirmed: issues.filter(
      (i) => i.status === "CONFIRMED_REAL" || i.status === "CONFIRMED_FIXED"
    ).length,
    repos: Object.keys(byRepo).length,
    byCwe,
    byStatus,
    byRepo,
    byLanguage,
    byVendor,
  };
}
