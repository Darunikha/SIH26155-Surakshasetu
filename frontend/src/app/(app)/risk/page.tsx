"use client";

import { useState } from "react";
import Link from "next/link";
import { useMutation, useQuery } from "@tanstack/react-query";
import { scansApi, ApiError, isAiUnavailableError } from "@/lib/api";
import { ScanSelector } from "@/components/scan-selector";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SeverityBadge, LoadingBlock, EmptyState, AiActionError, AiSummaryPanel } from "@/components/ui/misc";
import { severityColor, truncateHash } from "@/lib/utils";
import { ChevronRight, Sparkles } from "lucide-react";

const RISK_LEVEL_COLOR = severityColor;

/** Same 0-30/31-60/61-80/81-100 tiers the risk engine itself uses
 * (app/risk/engine.py) -- each factor bar is colored by its own tier, not a
 * single flat color, so it's obvious at a glance which factors are driving
 * the score. */
function tierForScore(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score <= 30) return "LOW";
  if (score <= 60) return "MEDIUM";
  if (score <= 80) return "HIGH";
  return "CRITICAL";
}

const BAR_COLOR: Record<string, string> = {
  LOW: "bg-low",
  MEDIUM: "bg-medium",
  HIGH: "bg-high",
  CRITICAL: "bg-critical",
};

export default function RiskPage() {
  const [scanId, setScanId] = useState("");
  const riskQuery = useQuery({ queryKey: ["risk", scanId], queryFn: () => scansApi.risk(scanId), enabled: !!scanId });
  const findingsQuery = useQuery({ queryKey: ["findings", scanId], queryFn: () => scansApi.findings(scanId), enabled: !!scanId });

  const [aiError, setAiError] = useState<string | null>(null);
  const [aiUnavailable, setAiUnavailable] = useState(false);
  const aiSummary = useMutation({
    mutationFn: () => scansApi.riskAiSummary(scanId),
    onSuccess: () => setAiError(null),
    onError: (err) => {
      setAiUnavailable(isAiUnavailableError(err));
      setAiError(err instanceof ApiError ? err.message : "Failed to generate AI summary");
    },
  });

  const severityRank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sortedFindings = [...(findingsQuery.data || [])].sort(
    (a, b) => (severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4)
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Risk Analysis</h1>
        <p className="text-sm text-muted">Multi-factor risk scoring: exposure, asset criticality, vulnerability, control failure.</p>
      </div>

      <ScanSelector scanId={scanId} onChange={setScanId} />

      {!scanId && <EmptyState title="Select a scan" description="Choose a completed scan above to see its risk breakdown." />}
      {scanId && riskQuery.isLoading && <LoadingBlock />}

      {riskQuery.data && (
        <>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Overall Risk Score</CardTitle>
              <Badge className={`text-sm px-3 py-1 ${RISK_LEVEL_COLOR[riskQuery.data.risk_level] || ""}`}>
                {riskQuery.data.risk_score} / 100 — {riskQuery.data.risk_level}
              </Badge>
            </CardHeader>
            <CardContent className="space-y-3">
              {Object.entries(riskQuery.data.risk_factors).map(([factor, val]) => {
                const tier = tierForScore(val.score);
                return (
                  <div key={factor} className="flex items-center gap-3">
                    <span className="text-xs text-muted w-40 shrink-0 capitalize">{factor.replace(/_/g, " ")}</span>
                    <div className="flex-1 h-2 rounded-full bg-surface-raised overflow-hidden">
                      <div className={`h-full ${BAR_COLOR[tier]}`} style={{ width: `${val.score}%` }} />
                    </div>
                    <Badge className={`w-32 justify-center ${RISK_LEVEL_COLOR[tier]}`}>
                      {val.score} (weight {val.weight})
                    </Badge>
                  </div>
                );
              })}
              <p className="text-[11px] text-muted mono pt-2">
                Calculation version {riskQuery.data.calculation_version} — hash {truncateHash(riskQuery.data.risk_hash, 20)}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-primary" /> AI Risk Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {!aiSummary.data && (
                <>
                  <Button size="sm" onClick={() => aiSummary.mutate()} disabled={aiSummary.isPending}>
                    {aiSummary.isPending ? "Asking local LLM..." : "Explain this risk & suggest fixes"}
                  </Button>
                  {aiError && <AiActionError message={aiError} isAiUnavailable={aiUnavailable} />}
                </>
              )}
              {aiSummary.data && (
                <>
                  <AiSummaryPanel text={aiSummary.data.summary} model={aiSummary.data.model} />
                  <Button size="sm" variant="secondary" onClick={() => aiSummary.mutate()} disabled={aiSummary.isPending}>
                    {aiSummary.isPending ? "Regenerating..." : "Regenerate"}
                  </Button>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Contributing Findings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {findingsQuery.isLoading && <LoadingBlock />}
              {findingsQuery.data?.length === 0 && (
                <p className="text-sm text-muted">No findings recorded for this scan.</p>
              )}
              {sortedFindings.map((f) => (
                <Link key={f.finding_id} href={`/findings/${f.finding_id}`}>
                  <div className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 hover:border-primary/50 transition-colors">
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{f.title}</p>
                      <p className="text-[11px] text-muted truncate">{f.description}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <SeverityBadge severity={f.severity} />
                      <ChevronRight className="h-4 w-4 text-muted" />
                    </div>
                  </div>
                </Link>
              ))}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
