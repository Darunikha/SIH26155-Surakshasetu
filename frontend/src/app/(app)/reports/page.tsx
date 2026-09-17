"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { reportsApi, ApiError } from "@/lib/api";
import { ScanSelector } from "@/components/scan-selector";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ErrorBlock } from "@/components/ui/misc";
import { formatDate, downloadBlob } from "@/lib/utils";

export default function ReportsPage() {
  const [scanId, setScanId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const generateMutation = useMutation({
    mutationFn: () => reportsApi.generate(scanId),
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to generate report"),
    onSuccess: () => setError(null),
  });

  const downloadMutation = useMutation({
    mutationFn: async (reportId: string) => {
      const res = await reportsApi.download(reportId);
      downloadBlob(res.data as Blob, `${reportId}.pdf`);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to download report"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Reports</h1>
        <p className="text-sm text-muted">
          Generates a PDF combining device identification, compliance results, risk analysis, attack paths, ACO
          sequencing, AI recommendations (when available), and blockchain provenance — every section pulled live from
          this scan&apos;s evidence.
        </p>
      </div>

      <ScanSelector scanId={scanId} onChange={setScanId} />

      <Button size="sm" onClick={() => generateMutation.mutate()} disabled={!scanId || generateMutation.isPending}>
        {generateMutation.isPending ? "Generating PDF..." : "Generate Report"}
      </Button>

      {error && <ErrorBlock message={error} />}

      {generateMutation.data && (
        <Card>
          <CardHeader>
            <CardTitle>{generateMutation.data.report_id}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted mono">Report hash: {generateMutation.data.report_hash}</p>
            <p className="text-xs text-muted">
              Generated {formatDate(generateMutation.data.generated_at)} · {(generateMutation.data.size_bytes / 1024).toFixed(1)} KB
            </p>
            <Button
              size="sm"
              onClick={() => downloadMutation.mutate(generateMutation.data!.report_id)}
              disabled={downloadMutation.isPending}
            >
              {downloadMutation.isPending ? "Downloading..." : "Download PDF"}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
