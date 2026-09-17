"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { optimizerApi, scansApi, ApiError, isAiUnavailableError } from "@/lib/api";
import { ScanSelector } from "@/components/scan-selector";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LoadingBlock, EmptyState, AiActionError, AiSummaryPanel } from "@/components/ui/misc";
import { Sparkles } from "lucide-react";

export default function OptimizerPage() {
  const [scanId, setScanId] = useState("");
  const scanQuery = useQuery({ queryKey: ["scan", scanId], queryFn: () => scansApi.get(scanId), enabled: !!scanId });
  const optimizerQuery = useQuery({
    queryKey: ["optimizer", scanQuery.data?.optimizer_run_id],
    queryFn: () => optimizerApi.get(scanQuery.data!.optimizer_run_id as string),
    enabled: !!scanQuery.data?.optimizer_run_id,
  });
  const runMutation = useMutation({ mutationFn: () => optimizerApi.run(scanId) });

  const result = runMutation.data || optimizerQuery.data;

  const [aiError, setAiError] = useState<string | null>(null);
  const [aiUnavailable, setAiUnavailable] = useState(false);
  const aiSummary = useMutation({
    mutationFn: () => optimizerApi.aiSummary(result!.optimizer_run_id),
    onSuccess: () => setAiError(null),
    onError: (err) => {
      setAiUnavailable(isAiUnavailableError(err));
      setAiError(err instanceof ApiError ? err.message : "Failed to generate AI summary");
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Remediation Optimizer (ACO)</h1>
        <p className="text-sm text-muted">
          Compares severity-only ordering, greedy risk-per-cost, and Ant Colony Optimization on real measured metrics —
          residual risk, cost, and runtime are all computed, never asserted.
        </p>
      </div>

      <ScanSelector scanId={scanId} onChange={setScanId} />

      {!scanId && <EmptyState title="Select a scan" description="Choose a completed scan above to compare remediation strategies." />}

      {scanId && (
        <Button size="sm" onClick={() => runMutation.mutate()} disabled={runMutation.isPending}>
          {runMutation.isPending ? "Running ACO..." : "Run Optimizer"}
        </Button>
      )}

      {optimizerQuery.isLoading && <LoadingBlock />}

      {result && (
        <>
          <div className="grid md:grid-cols-3 gap-3">
            {Object.entries(result.strategies).map(([strategy, m]) => (
              <Card key={strategy} className={strategy === "aco" ? "border-primary/50" : ""}>
                <CardHeader>
                  <CardTitle className="capitalize">{strategy.replace("_", " ")}</CardTitle>
                </CardHeader>
                <CardContent className="text-xs space-y-1">
                  <p>Residual risk: {m.residual_risk}</p>
                  <p>
                    Risk reduced: {m.risk_reduced} ({m.risk_reduction_percent}%)
                  </p>
                  <p>Operational cost: {m.operational_cost}</p>
                  <p>
                    Attack paths removed: {m.attack_paths_removed} / {m.total_potential_paths}
                  </p>
                  <p>Runtime: {m.runtime_ms}ms</p>
                  <p>Objective score: {m.objective_score} (lower is better)</p>
                  <p className="text-muted pt-1">Order: {m.sequence.join(" → ") || "-"}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-primary" /> AI Problem &amp; Suggestion
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {!aiSummary.data && (
                <>
                  <Button size="sm" onClick={() => aiSummary.mutate()} disabled={aiSummary.isPending}>
                    {aiSummary.isPending ? "Asking local LLM..." : "Explain the problem & recommended fix"}
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
        </>
      )}
    </div>
  );
}
