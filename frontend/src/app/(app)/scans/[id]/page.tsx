"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import dynamic from "next/dynamic";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { blockchainApi, optimizerApi, reportsApi, scansApi, ApiError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge, StatusBadge, LoadingBlock, ErrorBlock } from "@/components/ui/misc";
import { StatCard } from "@/components/ui/stat-card";
import { formatDate, truncateHash, downloadBlob } from "@/lib/utils";

const AttackGraphView = dynamic(() => import("./attack-graph-view").then((m) => m.AttackGraphView), { ssr: false });

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();

  const scanQuery = useQuery({ queryKey: ["scan", id], queryFn: () => scansApi.get(id), refetchInterval: (q) => (q.state.data?.status === "COMPLETED" || q.state.data?.status === "FAILED" ? false : 2000) });
  const scan = scanQuery.data;
  const completed = scan?.status === "COMPLETED";

  const complianceQuery = useQuery({ queryKey: ["compliance", id], queryFn: () => scansApi.compliance(id), enabled: completed });
  const findingsQuery = useQuery({ queryKey: ["findings", id], queryFn: () => scansApi.findings(id), enabled: completed });
  const riskQuery = useQuery({ queryKey: ["risk", id], queryFn: () => scansApi.risk(id), enabled: completed });
  const attackQuery = useQuery({ queryKey: ["attack-paths", id], queryFn: () => scansApi.attackPaths(id), enabled: completed });
  const optimizerQuery = useQuery({
    queryKey: ["optimizer", scan?.optimizer_run_id],
    queryFn: () => optimizerApi.get(scan!.optimizer_run_id as string),
    enabled: !!scan?.optimizer_run_id,
  });

  const [verifyResult, setVerifyResult] = useState<Record<string, unknown> | null>(null);
  const verifyMutation = useMutation({
    mutationFn: () => blockchainApi.verify(id),
    onSuccess: (res) => setVerifyResult(res as unknown as Record<string, unknown>),
  });

  const [reportError, setReportError] = useState<string | null>(null);
  const generateReport = useMutation({
    mutationFn: () => reportsApi.generate(id),
    onError: (err) => setReportError(err instanceof ApiError ? err.message : "Failed to generate report"),
  });

  const downloadReport = useMutation({
    mutationFn: async (reportId: string) => {
      const res = await reportsApi.download(reportId);
      downloadBlob(res.data as Blob, `${reportId}.pdf`);
    },
    onError: (err) => setReportError(err instanceof ApiError ? err.message : "Failed to download report"),
  });

  const runOptimizer = useMutation({
    mutationFn: (budget?: number) => optimizerApi.run(id, budget),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scan", id] }),
  });

  if (scanQuery.isLoading) return <LoadingBlock />;
  if (!scan) return <ErrorBlock message="Scan not found" />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold">Scan {scan.scan_id}</h1>
          <p className="text-sm text-muted">Status: {scan.status}{scan.error_message ? ` — ${scan.error_message}` : ""}</p>
        </div>
        {completed && (
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => generateReport.mutate()} disabled={generateReport.isPending}>
              {generateReport.isPending ? "Generating..." : "Generate PDF Report"}
            </Button>
            <Button size="sm" variant="outline" onClick={() => verifyMutation.mutate()} disabled={verifyMutation.isPending}>
              Verify Blockchain
            </Button>
          </div>
        )}
      </div>

      {!completed && (
        <Card>
          <CardContent className="py-6 text-center text-sm text-muted">
            Pipeline in progress ({scan.status})... this page auto-refreshes.
          </CardContent>
        </Card>
      )}

      {reportError && <ErrorBlock message={reportError} />}
      {generateReport.isSuccess && generateReport.data && (
        <Card>
          <CardContent className="py-3 flex items-center justify-between">
            <p className="text-sm">Report generated: {generateReport.data.report_id}</p>
            <Button
              size="sm"
              onClick={() => downloadReport.mutate(generateReport.data!.report_id)}
              disabled={downloadReport.isPending}
            >
              {downloadReport.isPending ? "Downloading..." : "Download PDF"}
            </Button>
          </CardContent>
        </Card>
      )}

      {verifyResult && (
        <Card>
          <CardContent className="py-3">
            <p className={`text-sm font-medium ${verifyResult.verified ? "text-success" : "text-danger"}`}>
              {verifyResult.verified ? "✓ BLOCKCHAIN VERIFIED" : `✗ ${verifyResult.status || "NOT VERIFIED"}`}
            </p>
            {!!verifyResult.mismatched_fields && (
              <p className="text-xs text-danger mt-1">Mismatched: {(verifyResult.mismatched_fields as string[]).join(", ")}</p>
            )}
          </CardContent>
        </Card>
      )}

      {completed && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Compliance Score" value={complianceQuery.data ? `${complianceQuery.data.compliance_score}%` : "..."} />
            <StatCard label="Risk Score" value={riskQuery.data ? `${riskQuery.data.risk_score} (${riskQuery.data.risk_level})` : "..."} />
            <StatCard label="Findings" value={findingsQuery.data?.length ?? "..."} />
            <StatCard label="Potential Attack Paths" value={attackQuery.data?.potential_attack_paths.length ?? "..."} />
          </div>

          <Tabs defaultValue="compliance">
            <TabsList>
              <TabsTrigger value="compliance">Compliance</TabsTrigger>
              <TabsTrigger value="findings">Findings</TabsTrigger>
              <TabsTrigger value="risk">Risk</TabsTrigger>
              <TabsTrigger value="attack-graph">Attack Graph</TabsTrigger>
              <TabsTrigger value="optimizer">Optimizer</TabsTrigger>
              <TabsTrigger value="blockchain">Blockchain</TabsTrigger>
            </TabsList>

            <TabsContent value="compliance">
              {complianceQuery.data && (
                <div className="space-y-4">
                  <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {Object.entries(complianceQuery.data.framework_coverage).map(([key, fw]) => (
                      <Card key={key}>
                        <CardContent className="py-3">
                          <p className="text-xs font-medium">{fw.framework}</p>
                          <p className="text-lg font-semibold mt-1">
                            {fw.implemented_controls} / {fw.total_controls ?? "N/A"}
                          </p>
                          <p className="text-[11px] text-muted mt-1">
                            {fw.coverage_percent !== null ? `${fw.coverage_percent}% coverage` : "Not enumerable"}
                          </p>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                  <Card>
                    <CardContent className="p-0">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-border text-left text-muted text-xs">
                            <th className="p-3">Control</th>
                            <th className="p-3">Status</th>
                            <th className="p-3">Severity</th>
                          </tr>
                        </thead>
                        <tbody>
                          {complianceQuery.data.controls.map((c) => (
                            <tr key={c.control_id} className="border-b border-border last:border-0">
                              <td className="p-3">
                                <p className="font-medium">{c.title}</p>
                                <p className="text-[11px] text-muted">{c.description}</p>
                              </td>
                              <td className="p-3">
                                <StatusBadge status={c.status} />
                              </td>
                              <td className="p-3">
                                <SeverityBadge severity={c.severity} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>
                </div>
              )}
            </TabsContent>

            <TabsContent value="findings">
              <div className="grid gap-2">
                {findingsQuery.data?.length === 0 && <p className="text-sm text-muted">No findings — all applicable controls passed.</p>}
                {findingsQuery.data?.map((f) => (
                  <Link key={f.finding_id} href={`/findings/${f.finding_id}`}>
                    <Card className="hover:border-primary/50 transition-colors">
                      <CardContent className="flex items-center justify-between py-3">
                        <div>
                          <p className="text-sm font-medium">{f.title}</p>
                          <p className="text-[11px] text-muted mt-1">{f.category}</p>
                        </div>
                        <SeverityBadge severity={f.severity} />
                      </CardContent>
                    </Card>
                  </Link>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="risk">
              {riskQuery.data && (
                <Card>
                  <CardHeader>
                    <CardTitle>
                      Risk Score: {riskQuery.data.risk_score} / 100 — {riskQuery.data.risk_level}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {Object.entries(riskQuery.data.risk_factors).map(([factor, val]) => (
                      <div key={factor} className="flex items-center gap-3">
                        <span className="text-xs text-muted w-40 shrink-0 capitalize">{factor.replace(/_/g, " ")}</span>
                        <div className="flex-1 h-2 rounded-full bg-surface-raised overflow-hidden">
                          <div className="h-full bg-primary" style={{ width: `${val.score}%` }} />
                        </div>
                        <span className="text-xs w-24 text-right">
                          {val.score} (w={val.weight})
                        </span>
                      </div>
                    ))}
                    <p className="text-[11px] text-muted mono pt-2">Risk hash: {truncateHash(riskQuery.data.risk_hash, 20)}</p>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="attack-graph">
              {attackQuery.data && (
                <div className="space-y-4">
                  <AttackGraphView graph={attackQuery.data.graph as { nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] }} />
                  <div className="space-y-2">
                    {attackQuery.data.potential_attack_paths.length === 0 && (
                      <p className="text-sm text-muted">No potential attack path could be derived from this configuration.</p>
                    )}
                    {attackQuery.data.potential_attack_paths.map((p, i) => (
                      <Card key={i}>
                        <CardContent className="py-3">
                          <Badge className="mb-2">{p.label}</Badge>
                          <p className="text-sm">{p.steps.join(" → ")}</p>
                          {p.exposed_services.length > 0 && (
                            <p className="text-[11px] text-warning mt-1">Exposed services: {p.exposed_services.join(", ")}</p>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>

            <TabsContent value="optimizer">
              <div className="space-y-4">
                <Button size="sm" onClick={() => runOptimizer.mutate(undefined)} disabled={runOptimizer.isPending}>
                  {runOptimizer.isPending ? "Running ACO..." : "Re-run Optimizer"}
                </Button>
                {optimizerQuery.data && (
                  <div className="grid md:grid-cols-3 gap-3">
                    {Object.entries(optimizerQuery.data.strategies).map(([strategy, m]) => (
                      <Card key={strategy} className={strategy === "aco" ? "border-primary/50" : ""}>
                        <CardHeader>
                          <CardTitle className="capitalize">{strategy.replace("_", " ")}</CardTitle>
                        </CardHeader>
                        <CardContent className="text-xs space-y-1">
                          <p>Residual risk: {m.residual_risk}</p>
                          <p>Risk reduced: {m.risk_reduced} ({m.risk_reduction_percent}%)</p>
                          <p>Operational cost: {m.operational_cost}</p>
                          <p>Attack paths removed: {m.attack_paths_removed} / {m.total_potential_paths}</p>
                          <p>Runtime: {m.runtime_ms}ms</p>
                          <p>Objective score: {m.objective_score} (lower is better)</p>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="blockchain">
              <Card>
                <CardContent className="py-4 space-y-2 text-sm">
                  <p>Configuration SHA-256: <span className="mono text-xs">{scan.configuration_hash}</span></p>
                  <p>Blockchain status: <Badge>{scan.blockchain_status || "PENDING"}</Badge></p>
                  <p className="text-xs text-muted">Created {formatDate(scan.created_at)}, updated {formatDate(scan.updated_at)}</p>
                  <Link href={`/blockchain/audit/${scan.scan_id}`} className="text-primary text-xs hover:underline">
                    View full provenance history →
                  </Link>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}
