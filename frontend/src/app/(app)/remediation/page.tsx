"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { scansApi } from "@/lib/api";
import { ScanSelector } from "@/components/scan-selector";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge, LoadingBlock, EmptyState } from "@/components/ui/misc";
import { ChevronRight } from "lucide-react";

export default function RemediationPage() {
  const [scanId, setScanId] = useState("");
  const findingsQuery = useQuery({ queryKey: ["findings", scanId], queryFn: () => scansApi.findings(scanId), enabled: !!scanId });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Remediation</h1>
        <p className="text-sm text-muted">
          AI drafts commands per finding; every plan is syntax-validated and requires explicit human approval before
          simulation — nothing is auto-applied to a real device.
        </p>
      </div>

      <ScanSelector scanId={scanId} onChange={setScanId} />

      {!scanId && <EmptyState title="Select a scan" description="Choose a scan to view and remediate its findings." />}
      {scanId && findingsQuery.isLoading && <LoadingBlock />}
      {scanId && findingsQuery.data?.length === 0 && <EmptyState title="No findings" description="This scan has no findings to remediate." />}

      <div className="grid gap-2">
        {findingsQuery.data?.map((f) => (
          <Link key={f.finding_id} href={`/findings/${f.finding_id}`}>
            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="flex items-center justify-between py-3">
                <div>
                  <p className="text-sm font-medium">{f.title}</p>
                  <p className="text-[11px] text-muted mt-1">{f.category}</p>
                </div>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <ChevronRight className="h-4 w-4 text-muted" />
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
