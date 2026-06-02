import { Suspense } from "react";
import { getAllIssues } from "@/lib/content";
import { VENDORS, getVendorLabel } from "@/lib/vendors";
import IssuesListClient from "@/components/issues-list";

export function generateStaticParams() {
  return Object.keys(VENDORS).map((key) => ({ key }));
}

export const dynamicParams = false;

export default async function VendorPage({
  params,
}: {
  params: Promise<{ key: string }>;
}) {
  const { key } = await params;
  const allIssues = getAllIssues();
  const issues = allIssues.filter((i) => i.vendor === key);

  return (
    <Suspense>
      <IssuesListClient issues={issues} defaultVendor={key} />
    </Suspense>
  );
}
