import { getAllIssues } from "@/lib/content";
import IssuesListClient from "@/components/issues-list";

export default function IssuesPage() {
  const issues = getAllIssues();
  return <IssuesListClient issues={issues} />;
}
