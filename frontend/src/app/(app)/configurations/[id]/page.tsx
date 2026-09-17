"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { configurationsApi } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingBlock } from "@/components/ui/misc";
import { formatDate, truncateHash } from "@/lib/utils";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false });

export default function ConfigurationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const versionsQuery = useQuery({ queryKey: ["configuration-versions", id], queryFn: () => configurationsApi.versions(id) });
  const versions = versionsQuery.data || [];
  const latestVersionNumber = versions.length ? versions[versions.length - 1].version : undefined;

  const latestDetailQuery = useQuery({
    queryKey: ["configuration-version-detail", id, latestVersionNumber],
    queryFn: () => configurationsApi.getVersion(id, latestVersionNumber as number),
    enabled: latestVersionNumber !== undefined,
  });

  if (versionsQuery.isLoading) return <LoadingBlock />;

  const latest = latestDetailQuery.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Configuration {id}</h1>
        <p className="text-sm text-muted">{versions.length} version(s) — historical versions are never overwritten.</p>
      </div>

      <div className="grid gap-3">
        {[...versions].reverse().map((v) => (
          <Card key={v.version}>
            <CardContent className="py-3">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <p className="text-sm font-medium">
                    v{v.version} — {v.original_filename}
                  </p>
                  <div className="flex gap-2 mt-1 flex-wrap">
                    <Badge>{v.vendor || "Unknown"}</Badge>
                    <Badge>{v.platform || "-"}</Badge>
                    <Badge>{v.status}</Badge>
                  </div>
                </div>
                <p className="text-[11px] text-muted">{formatDate(v.uploaded_at)}</p>
              </div>
              <p className="text-[11px] text-muted mono mt-2">SHA-256: {truncateHash(v.configuration_hash, 20)}</p>
              {v.ir_hash && <p className="text-[11px] text-muted mono">IR hash: {truncateHash(v.ir_hash, 20)}</p>}
              {v.secret_findings.length > 0 && (
                <p className="text-[11px] text-warning mt-1">
                  Secret categories redacted before AI processing: {v.secret_findings.join(", ")}
                </p>
              )}
              {v.error_message && <p className="text-[11px] text-danger mt-1">{v.error_message}</p>}
            </CardContent>
          </Card>
        ))}
      </div>

      {latest?.security_ir && (
        <Card>
          <CardHeader>
            <CardTitle>Vendor-Neutral Security IR (latest version)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="rounded-md overflow-hidden border border-border">
              <MonacoEditor
                height="420px"
                language="json"
                theme="vs-dark"
                value={JSON.stringify(latest.security_ir, null, 2)}
                options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
              />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
