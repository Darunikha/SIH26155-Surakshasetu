"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { useQuery } from "@tanstack/react-query";
import { scansApi } from "@/lib/api";
import { ScanSelector } from "@/components/scan-selector";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingBlock, EmptyState } from "@/components/ui/misc";

const AttackGraphView = dynamic(() => import("../scans/[id]/attack-graph-view").then((m) => m.AttackGraphView), { ssr: false });

export default function AttackPathsPage() {
  const [scanId, setScanId] = useState("");
  const attackQuery = useQuery({ queryKey: ["attack-paths", scanId], queryFn: () => scansApi.attackPaths(scanId), enabled: !!scanId });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Attack Path Analysis</h1>
        <p className="text-sm text-muted">Graph reachability derived from parsed topology, ACLs, and exposed services — never a canned template.</p>
      </div>

      <ScanSelector scanId={scanId} onChange={setScanId} />

      {!scanId && <EmptyState title="Select a scan" description="Choose a completed scan above to view its attack graph." />}
      {scanId && attackQuery.isLoading && <LoadingBlock />}

      {attackQuery.data && (
        <div className="space-y-4">
          <AttackGraphView graph={attackQuery.data.graph as { nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] }} />
          {attackQuery.data.potential_attack_paths.length === 0 && (
            <p className="text-sm text-muted">No potential attack path could be derived from this configuration and asset context.</p>
          )}
          {attackQuery.data.potential_attack_paths.map((p, i) => (
            <Card key={i}>
              <CardContent className="py-3">
                <Badge className="mb-2">{p.label}</Badge>
                <p className="text-sm">{p.steps.join(" → ")}</p>
                {p.exposed_services.length > 0 && (
                  <p className="text-[11px] text-warning mt-1">Exposed services: {p.exposed_services.join(", ")}</p>
                )}
                <p className="text-[11px] text-muted mt-1">Risk contribution: {p.risk_contribution}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
