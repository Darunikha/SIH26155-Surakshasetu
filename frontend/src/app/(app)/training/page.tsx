"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { trainingApi, ApiError, isAiUnavailableError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { LoadingBlock, EmptyState, AiActionError } from "@/components/ui/misc";

export default function TrainingPage() {
  const qc = useQueryClient();
  const unknownQuery = useQuery({ queryKey: ["unknown-patterns"], queryFn: () => trainingApi.unknown() });
  const [aiErrors, setAiErrors] = useState<Record<string, string>>({});
  const [aiUnavailable, setAiUnavailable] = useState<Record<string, boolean>>({});
  const [drafts, setDrafts] = useState<Record<string, { category: string; ir_field_path: string; meaning: string }>>({});

  const suggestMutation = useMutation({
    mutationFn: ({ vendor, rawLine }: { vendor: string; rawLine: string }) => trainingApi.suggest(vendor, rawLine),
    onSuccess: (res, vars) => {
      setDrafts((d) => ({ ...d, [vars.rawLine]: { category: res.category, ir_field_path: "", meaning: res.meaning } }));
      setAiErrors((e) => ({ ...e, [vars.rawLine]: "" }));
    },
    onError: (err, vars) => {
      setAiUnavailable((u) => ({ ...u, [vars.rawLine]: isAiUnavailableError(err) }));
      setAiErrors((e) => ({ ...e, [vars.rawLine]: err instanceof ApiError ? err.message : "Failed to get AI suggestion" }));
    },
  });

  const confirmMutation = useMutation({
    mutationFn: (body: { vendor: string; raw_line: string; category: string; ir_field_path: string; meaning: string; decision: string }) =>
      trainingApi.confirmMapping(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["unknown-patterns"] }),
  });

  if (unknownQuery.isLoading) return <LoadingBlock />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Adaptive Learning</h1>
        <p className="text-sm text-muted">
          Configuration lines the parser could not map to the Security IR. AI may suggest a category, but only a human
          CONFIRM makes it authoritative — the system never learns from itself alone.
        </p>
      </div>

      {unknownQuery.data?.length === 0 && (
        <EmptyState title="No unknown patterns" description="Every parsed configuration line has been mapped." />
      )}

      <div className="space-y-4">
        {unknownQuery.data?.map((p) => {
          const draft = drafts[p.raw_line];
          return (
            <Card key={`${p.vendor}-${p.raw_line}`}>
              <CardHeader>
                <CardTitle className="mono text-xs font-normal">{p.raw_line}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex gap-2 flex-wrap">
                  <Badge>{p.vendor}</Badge>
                  <Badge>seen {p.occurrence_count}x</Badge>
                  <Badge>{p.status}</Badge>
                </div>

                {!draft && (
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => suggestMutation.mutate({ vendor: p.vendor, rawLine: p.raw_line })}
                    disabled={suggestMutation.isPending}
                  >
                    Ask AI for a suggestion
                  </Button>
                )}
                {aiErrors[p.raw_line] && (
                  <AiActionError message={aiErrors[p.raw_line]} isAiUnavailable={!!aiUnavailable[p.raw_line]} />
                )}

                {draft && (
                  <div className="grid sm:grid-cols-3 gap-2">
                    <div>
                      <Label>Category</Label>
                      <Input
                        value={draft.category}
                        onChange={(e) => setDrafts((d) => ({ ...d, [p.raw_line]: { ...draft, category: e.target.value } }))}
                      />
                    </div>
                    <div>
                      <Label>IR field path</Label>
                      <Input
                        placeholder="e.g. management.session_timeout_seconds"
                        value={draft.ir_field_path}
                        onChange={(e) => setDrafts((d) => ({ ...d, [p.raw_line]: { ...draft, ir_field_path: e.target.value } }))}
                      />
                    </div>
                    <div>
                      <Label>Meaning</Label>
                      <Input
                        value={draft.meaning}
                        onChange={(e) => setDrafts((d) => ({ ...d, [p.raw_line]: { ...draft, meaning: e.target.value } }))}
                      />
                    </div>
                  </div>
                )}

                {draft && (
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      onClick={() =>
                        confirmMutation.mutate({
                          vendor: p.vendor,
                          raw_line: p.raw_line,
                          category: draft.category,
                          ir_field_path: draft.ir_field_path,
                          meaning: draft.meaning,
                          decision: "confirm",
                        })
                      }
                    >
                      Confirm mapping
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        confirmMutation.mutate({
                          vendor: p.vendor,
                          raw_line: p.raw_line,
                          category: "",
                          ir_field_path: "",
                          meaning: "",
                          decision: "reject",
                        })
                      }
                    >
                      Reject
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
