"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { configurationsApi, devicesApi, projectsApi, scansApi, ApiError } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, Label } from "@/components/ui/input";
import { LoadingBlock, EmptyState } from "@/components/ui/misc";
import { formatDate, truncateHash } from "@/lib/utils";

function ConfigurationsInner() {
  const searchParams = useSearchParams();
  const deviceFilter = searchParams.get("device") || undefined;
  const qc = useQueryClient();
  const [scanningDevice, setScanningDevice] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [projectId, setProjectId] = useState<string>("");

  const projectsQuery = useQuery({ queryKey: ["projects"], queryFn: projectsApi.list });
  // Default to the most recently created project so a user (or a fresh
  // test run) isn't shown a page cluttered with every project's history.
  const mostRecentProjectId = projectsQuery.data?.length
    ? [...projectsQuery.data].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0].project_id
    : "";
  const activeProjectId = projectId || mostRecentProjectId;

  const configsQuery = useQuery({
    queryKey: ["configurations", activeProjectId],
    queryFn: () => configurationsApi.list(activeProjectId),
    enabled: !!activeProjectId,
  });
  const devicesQuery = useQuery({
    queryKey: ["devices", activeProjectId],
    queryFn: () => devicesApi.list(activeProjectId),
    enabled: !!activeProjectId,
  });

  const startScan = useMutation({
    mutationFn: (deviceId: string) => scansApi.start(deviceId),
    onMutate: (deviceId) => setScanningDevice(deviceId),
    onSuccess: () => {
      setScanError(null);
      qc.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err) => setScanError(err instanceof ApiError ? err.message : "Failed to start scan"),
    onSettled: () => setScanningDevice(null),
  });

  const deviceById = new Map((devicesQuery.data || []).map((d) => [d.device_id, d]));
  const configs = (configsQuery.data || []).filter((c) => !deviceFilter || c.device_id === deviceFilter);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Configurations</h1>
        <p className="text-sm text-muted">Every uploaded configuration and its version history, scoped to one project at a time.</p>
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

      {scanError && <p className="text-xs text-danger">{scanError}</p>}

      {configsQuery.isLoading && <LoadingBlock />}
      {!configsQuery.isLoading && configs.length === 0 && (
        <EmptyState title="No configurations in this project" description="Upload a configuration to get started." />
      )}

      <div className="grid gap-4">
        {configs.map((c) => {
          const device = deviceById.get(c.device_id);
          return (
            <Card key={c.configuration_id}>
              <CardContent className="flex items-center justify-between gap-4 py-4">
                <div className="min-w-0">
                  <Link href={`/configurations/${c.configuration_id}`} className="text-sm font-medium hover:text-primary">
                    {device?.name || c.device_id}
                  </Link>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    <Badge>{device?.vendor || "Unknown vendor"}</Badge>
                    <Badge>v{c.latest_version}</Badge>
                    {c.latest && <Badge>{c.latest.status}</Badge>}
                  </div>
                  {c.latest?.configuration_hash && (
                    <p className="text-[11px] text-muted mono mt-1">SHA-256: {truncateHash(c.latest.configuration_hash, 16)}</p>
                  )}
                  <p className="text-[11px] text-muted mt-1">Created {formatDate(c.created_at)}</p>
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={scanningDevice === c.device_id || c.latest?.status !== "COMPLETED"}
                  onClick={() => startScan.mutate(c.device_id)}
                >
                  {scanningDevice === c.device_id ? "Starting..." : "Start Scan"}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

export default function ConfigurationsPage() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <ConfigurationsInner />
    </Suspense>
  );
}
