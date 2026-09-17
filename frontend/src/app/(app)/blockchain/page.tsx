"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { blockchainApi, scansApi } from "@/lib/api";
import { ScanSelector } from "@/components/scan-selector";
import { StatCard } from "@/components/ui/stat-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { LoadingBlock } from "@/components/ui/misc";
import { truncateHash } from "@/lib/utils";

export default function BlockchainPage() {
  const statusQuery = useQuery({ queryKey: ["blockchain-status"], queryFn: blockchainApi.status, refetchInterval: 10000 });
  const [scanId, setScanId] = useState("");
  const verifyMutation = useMutation({ mutationFn: () => blockchainApi.verify(scanId) });

  if (statusQuery.isLoading) return <LoadingBlock />;
  const s = statusQuery.data!;
  const result = verifyMutation.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Blockchain Integrity</h1>
        <p className="text-sm text-muted">
          Hyperledger Fabric provenance ledger — every hash below is recomputed live from MongoDB and compared against
          the real ledger, never a static claim.
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Fabric Network" value={s.fabric_reachable ? "Connected" : "Unreachable"} accent={s.fabric_reachable ? "success" : "danger"} />
        <StatCard label="Total Audits" value={s.total_audits} />
        <StatCard label="Confirmed Transactions" value={s.confirmed_transactions} accent="success" />
        <StatCard label="Pending Transactions" value={s.pending_transactions} accent={s.pending_transactions > 0 ? "warning" : "success"} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Verify an audit</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <ScanSelector scanId={scanId} onChange={setScanId} />
          <Button size="sm" onClick={() => verifyMutation.mutate()} disabled={!scanId || verifyMutation.isPending}>
            {verifyMutation.isPending ? "Verifying..." : "Verify"}
          </Button>

          {result && (
            <div className="space-y-2">
              <p className={`text-sm font-medium ${result.verified ? "text-success" : "text-danger"}`}>
                {result.verified ? "✓ VERIFIED — evidence matches the Fabric ledger" : `✗ ${result.status || "NOT VERIFIED"}`}
              </p>
              {result.mismatched_fields && result.mismatched_fields.length > 0 && (
                <p className="text-xs text-danger">Mismatched fields: {result.mismatched_fields.join(", ")}</p>
              )}
              <div className="grid sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <p className="font-medium mb-1">Database (recomputed now)</p>
                  {result.database_hashes &&
                    Object.entries(result.database_hashes).map(([k, v]) => (
                      <p key={k} className="mono text-muted">
                        {k}: {truncateHash(v, 14)}
                      </p>
                    ))}
                </div>
                <div>
                  <p className="font-medium mb-1">Blockchain (ledger)</p>
                  {result.blockchain_hashes &&
                    Object.entries(result.blockchain_hashes).map(([k, v]) => (
                      <p key={k} className="mono text-muted">
                        {k}: {truncateHash(v, 14)}
                      </p>
                    ))}
                </div>
              </div>
              <Link href={`/blockchain/audit/${scanId}`}>
                <Button size="sm" variant="outline">
                  View full provenance history
                </Button>
              </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
