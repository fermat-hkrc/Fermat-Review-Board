import { Suspense } from "react";
import { getAllIssues } from "@/lib/content";
import IssuesListClient from "@/components/issues-list";

export default function IssuesPage() {
  const issues = getAllIssues();
  return (
    <Suspense>
      <IssuesListClient issues={issues} />
    </Suspense>
  );
}
