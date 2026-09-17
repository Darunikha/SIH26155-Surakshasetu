"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { blockchainApi } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingBlock, EmptyState } from "@/components/ui/misc";
import { formatDate, truncateHash } from "@/lib/utils";

export default function AuditHistoryPage() {
  const { id } = useParams<{ id: string }>();
  const historyQuery = useQuery({ queryKey: ["audit-history", id], queryFn: () => blockchainApi.auditHistory(id) });

  if (historyQuery.isLoading) return <LoadingBlock />;
  const events = historyQuery.data || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Provenance History — {id}</h1>
        <p className="text-sm text-muted">Every blockchain event recorded for this audit, in order.</p>
      </div>

      {events.length === 0 && <EmptyState title="No blockchain events yet" />}

      <div className="relative pl-6 space-y-4 before:absolute before:left-[7px] before:top-2 before:bottom-2 before:w-px before:bg-border">
        {events.map((e) => (
          <div key={e.event_id} className="relative">
            <div className="absolute -left-6 top-1.5 h-3 w-3 rounded-full bg-primary" />
            <Card>
              <CardContent className="py-3">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <p className="text-sm font-medium">{e.event_type}</p>
                  <Badge className={e.status === "CONFIRMED" ? "text-success border-success/40" : "text-warning border-warning/40"}>
                    {e.status}
                  </Badge>
                </div>
                <p className="text-[11px] text-muted mt-1">{formatDate(e.created_at)} · actor {e.actor_id}</p>
                {e.transaction_id && <p className="text-[11px] mono text-muted mt-1">tx: {truncateHash(e.transaction_id, 20)}</p>}
                {e.configuration_hash && <p className="text-[11px] mono text-muted">config hash: {truncateHash(e.configuration_hash, 20)}</p>}
                {e.compliance_hash && <p className="text-[11px] mono text-muted">compliance hash: {truncateHash(e.compliance_hash, 20)}</p>}
                {e.risk_hash && <p className="text-[11px] mono text-muted">risk hash: {truncateHash(e.risk_hash, 20)}</p>}
                {e.reason && <p className="text-[11px] text-danger mt-1">{e.reason}</p>}
              </CardContent>
            </Card>
          </div>
        ))}
      </div>
    </div>
  );
}
