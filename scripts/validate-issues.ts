import fs from "fs";
import path from "path";
import matter from "gray-matter";

const REQUIRED_FIELDS = [
  "id",
  "date",
  "repo",
  "repo_url",
  "title",
  "severity",
  "cwe",
  "cwe_name",
  "status",
  "author",
] as const;

const VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const VALID_STATUSES = [
  "SUBMITTED",
  "CONFIRMED_REAL",
  "CONFIRMED_FIXED",
  "NEEDS_REVIEW",
  "PENDING",
  "FALSE_POSITIVE",
  "CODE_QUALITY",
];

interface ValidationError {
  file: string;
  errors: string[];
}

function validateIssue(filePath: string): string[] {
  const raw = fs.readFileSync(filePath, "utf-8");
  const { data } = matter(raw);
  const errors: string[] = [];

  for (const field of REQUIRED_FIELDS) {
    if (!data[field] && data[field] !== 0) {
      errors.push(`missing required field: ${field}`);
    }
  }

  if (data.severity && !VALID_SEVERITIES.includes(data.severity)) {
    errors.push(
      `invalid severity "${data.severity}" — must be one of: ${VALID_SEVERITIES.join(", ")}`
    );
  }

  if (data.cwe && !/^CWE-\d+$/.test(data.cwe)) {
    errors.push(`invalid cwe format "${data.cwe}" — must match CWE-\\d+`);
  }

  if (data.status && !VALID_STATUSES.includes(data.status)) {
    errors.push(
      `invalid status "${data.status}" — must be one of: ${VALID_STATUSES.join(", ")}`
    );
  }

  if (data.date && !/^\d{4}-\d{2}-\d{2}$/.test(data.date)) {
    errors.push(
      `invalid date format "${data.date}" — must be YYYY-MM-DD`
    );
  }

  return errors;
}

function main() {
  const issuesDir = path.join(process.cwd(), "content/issues");

  // If file paths passed as args, validate only those (incremental mode)
  // Otherwise validate all
  const args = process.argv.slice(2);
  let files: string[];

  if (args.length > 0) {
    files = args
      .filter((f) => f.startsWith("content/issues/") && f.endsWith(".md"))
      .map((f) => path.join(process.cwd(), f))
      .filter((f) => fs.existsSync(f));
  } else {
    if (!fs.existsSync(issuesDir)) {
      console.log("No content/issues/ directory found.");
      process.exit(0);
    }
    files = fs
      .readdirSync(issuesDir)
      .filter((f) => f.endsWith(".md"))
      .map((f) => path.join(issuesDir, f));
  }

  if (files.length === 0) {
    console.log("No issue files to validate.");
    process.exit(0);
  }

  const failures: ValidationError[] = [];

  for (const file of files) {
    const errors = validateIssue(file);
    if (errors.length > 0) {
      failures.push({ file: path.relative(process.cwd(), file), errors });
    }
  }

  if (failures.length === 0) {
    console.log(`✓ All ${files.length} issues pass validation`);
    process.exit(0);
  }

  console.error(`✗ ${failures.length}/${files.length} issues have errors:\n`);
  for (const f of failures) {
    console.error(`  ${f.file}`);
    for (const e of f.errors) {
      console.error(`    - ${e}`);
    }
    console.error();
  }
  process.exit(1);
}

main();
