"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { findingsApi, remediationApi, ApiError, isAiUnavailableError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge, StatusBadge, LoadingBlock, ErrorBlock, AiActionError } from "@/components/ui/misc";
import { Badge } from "@/components/ui/badge";

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const findingQuery = useQuery({ queryKey: ["finding", id], queryFn: () => findingsApi.get(id) });

  const [aiError, setAiError] = useState<string | null>(null);
  const [aiUnavailable, setAiUnavailable] = useState(false);
  const generateRemediation = useMutation({
    mutationFn: () => remediationApi.generate(id),
    onSuccess: () => {
      setAiError(null);
      qc.invalidateQueries({ queryKey: ["finding", id] });
    },
    onError: (err) => {
      setAiUnavailable(isAiUnavailableError(err));
      setAiError(err instanceof ApiError ? err.message : "Failed to generate remediation");
    },
  });

  const approveMutation = useMutation({
    mutationFn: (remediationId: string) => remediationApi.approve(remediationId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });

  const validateMutation = useMutation({
    mutationFn: (remediationId: string) => remediationApi.validate(remediationId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });

  if (findingQuery.isLoading) return <LoadingBlock />;
  if (!findingQuery.data) return <ErrorBlock message="Finding not found" />;

  const f = findingQuery.data;
  const remediation = f.remediation;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="text-lg font-semibold">{f.title}</h1>
        <SeverityBadge severity={f.severity} />
        <StatusBadge status={f.status} />
      </div>
      <p className="text-sm text-muted">{f.description}</p>

      <Card>
        <CardHeader>
          <CardTitle>Evidence</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="text-xs mono bg-surface-raised rounded-md p-3 overflow-x-auto">{JSON.stringify(f.evidence, null, 2)}</pre>
          {f.notes && <p className="text-xs text-muted mt-2">{f.notes}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Framework Mappings</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {f.framework_mappings.map((m, i) => (
            <Badge key={i}>
              {m.framework}: {m.control_id}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>AI Remediation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {!remediation && (
            <>
              <Button size="sm" onClick={() => generateRemediation.mutate()} disabled={generateRemediation.isPending}>
                {generateRemediation.isPending ? "Asking local LLM..." : "Generate Remediation Plan"}
              </Button>
              {aiError && <AiActionError message={aiError} isAiUnavailable={aiUnavailable} />}
            </>
          )}
          {remediation && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Badge>{remediation.status}</Badge>
                <span className="text-xs text-muted">
                  {remediation.vendor} / {remediation.platform}
                </span>
              </div>
              <p className="text-sm">{remediation.explanation}</p>
              <div className="space-y-1">
                {remediation.suggested_commands.map((cmd, i) => {
                  const validation = remediation.validation_results[i];
                  return (
                    <div key={i} className="flex items-center gap-2">
                      <code className="mono text-xs bg-surface-raised px-2 py-1 rounded flex-1">{cmd}</code>
                      {validation && (
                        <Badge className={validation.valid ? "text-success border-success/40" : "text-danger border-danger/40"}>
                          {validation.valid ? "valid syntax" : validation.reason}
                        </Badge>
                      )}
                    </div>
                  );
                })}
              </div>
              <div className="flex gap-2">
                {remediation.status === "AWAITING_APPROVAL" && (
                  <Button size="sm" onClick={() => approveMutation.mutate(remediation.remediation_id)} disabled={approveMutation.isPending}>
                    Approve (human sign-off required)
                  </Button>
                )}
                {remediation.status === "APPROVED" && (
                  <Button size="sm" variant="secondary" onClick={() => validateMutation.mutate(remediation.remediation_id)} disabled={validateMutation.isPending}>
                    Simulate
                  </Button>
                )}
                {remediation.status === "SIMULATED" && (
                  <p className="text-xs text-success">
                    Simulated — no real device was changed. Apply manually, then start a new scan to re-audit.
                  </p>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
