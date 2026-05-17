import fs from "fs";
import path from "path";
import matter from "gray-matter";

const issuesDirectory = path.join(process.cwd(), "content/issues");
const pocsDirectory = path.join(process.cwd(), "content/pocs");

export interface IssueMeta {
  id: string;
  date: string;
  repo: string;
  repo_url: string;
  title: string;
  cwe: string;
  cwe_name?: string;
  status: string;
  affected_version?: string;
  component?: string;
  issue_url?: string;
  file_paths?: string[];
  author?: string;
  has_poc?: boolean;
}

export interface Issue {
  meta: IssueMeta;
  content: string;
  poc?: PocData;
}

export interface PocData {
  files: { name: string; content: string; language: string }[];
  output?: string;
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
    .sort((a, b) => b.date.localeCompare(a.date));
}

export function getIssueMeta(id: string): IssueMeta | null {
  const filePath = path.join(issuesDirectory, `${id}.md`);
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf-8");
  const { data } = matter(raw);
  return data as IssueMeta;
}

export function getIssue(id: string): Issue | null {
  const filePath = path.join(issuesDirectory, `${id}.md`);
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf-8");
  const { data, content } = matter(raw);
  const poc = getPocData(id);
  return { meta: data as IssueMeta, content, poc: poc ?? undefined };
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
  return {
    files: files.filter((f) => f.name !== "output.txt"),
    output: outputFile?.content,
  };
}

export function getVerifiedPocIssues(): IssueMeta[] {
  const issues = getAllIssues();
  return issues.filter((i) => i.has_poc === true);
}

export function getStats() {
  const issues = getAllIssues();
  const byCwe: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  const byRepo: Record<string, number> = {};

  for (const issue of issues) {
    const cweLabel = issue.cwe_name
      ? `${issue.cwe} ${issue.cwe_name}`
      : issue.cwe;
    byCwe[cweLabel] = (byCwe[cweLabel] || 0) + 1;
    byStatus[issue.status] = (byStatus[issue.status] || 0) + 1;
    byRepo[issue.repo] = (byRepo[issue.repo] || 0) + 1;
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
  };
}
