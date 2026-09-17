"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { scansApi, devicesApi, projectsApi } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, Label } from "@/components/ui/input";
import { LoadingBlock, EmptyState } from "@/components/ui/misc";
import { formatDate } from "@/lib/utils";

const STATUS_COLOR: Record<string, string> = {
  COMPLETED: "text-success border-success/40 bg-success/10",
  FAILED: "text-danger border-danger/40 bg-danger/10",
  PENDING: "text-muted",
};

export default function ScansPage() {
  const [projectId, setProjectId] = useState<string>("");
  const projectsQuery = useQuery({ queryKey: ["projects"], queryFn: projectsApi.list });
  const mostRecentProjectId = projectsQuery.data?.length
    ? [...projectsQuery.data].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0].project_id
    : "";
  const activeProjectId = projectId || mostRecentProjectId;

  const TERMINAL_STATUSES = new Set(["COMPLETED", "FAILED"]);
  const scansQuery = useQuery({
    queryKey: ["scans", activeProjectId],
    queryFn: () => scansApi.list({ projectId: activeProjectId }),
    enabled: !!activeProjectId,
    // Only keep polling while at least one scan is still in flight -- a
    // flat 3s interval kept refetching (and re-rendering the whole list)
    // forever, even once every scan had already finished.
    refetchInterval: (query) => {
      const scans = query.state.data;
      const hasActiveScan = scans?.some((s) => !TERMINAL_STATUSES.has(s.status));
      return hasActiveScan ? 3000 : false;
    },
  });
  const devicesQuery = useQuery({
    queryKey: ["devices", activeProjectId],
    queryFn: () => devicesApi.list(activeProjectId),
    enabled: !!activeProjectId,
  });
  const deviceById = new Map((devicesQuery.data || []).map((d) => [d.device_id, d]));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Scans</h1>
        <p className="text-sm text-muted">Compliance → risk → attack-graph → ACO pipeline runs, auto-refreshing while in progress.</p>
      </div>

      <div className="max-w-sm">
        <Label>Project</Label>
        <Select value={activeProjectId} onChange={(e) => setProjectId(e.target.value)}>
          {projectsQuery.data?.map((p) => (
            <option key={p.project_id} value={p.project_id}>
              {p.name}
            </option>
          ))}
        </Select>
      </div>

      {scansQuery.isLoading && <LoadingBlock />}
      {!scansQuery.isLoading && scansQuery.data?.length === 0 && (
        <EmptyState title="No scans in this project yet" description="Start a scan from the Configurations page." />
      )}

      <div className="grid gap-3">
        {scansQuery.data?.map((s) => (
          <Link key={s.scan_id} href={`/scans/${s.scan_id}`}>
            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="flex items-center justify-between gap-4 py-3">
                <div>
                  <p className="text-sm font-medium">{deviceById.get(s.device_id)?.name || s.device_id}</p>
                  <p className="text-[11px] text-muted mt-1">{formatDate(s.created_at)}</p>
                </div>
                <div className="flex items-center gap-3">
                  {s.compliance_score != null && <Badge>{s.compliance_score}% compliant</Badge>}
                  {s.risk_score != null && <Badge>risk {s.risk_score}</Badge>}
                  <Badge className={STATUS_COLOR[s.status] || ""}>{s.status}</Badge>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
