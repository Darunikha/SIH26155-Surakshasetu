"use client";

import { useCallback, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { configurationsApi, projectsApi, ApiError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, Label } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/misc";
import { truncateHash, cn } from "@/lib/utils";
import { UploadCloud, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";

interface UploadItem {
  id: string;
  filename: string;
  status: "uploading" | "done" | "error" | "needs_confirmation";
  vendor?: string | null;
  platform?: string | null;
  confidence?: number | null;
  hash?: string | null;
  irHash?: string | null;
  error?: string;
  compliancePreview?: string;
}

export default function UploadPage() {
  const projectsQuery = useQuery({ queryKey: ["projects"], queryFn: projectsApi.list });
  const [projectId, setProjectId] = useState<string>("");
  const [items, setItems] = useState<UploadItem[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Default to the most recently created project, not whatever order the
  // API happens to return -- a user who just created a project expects it
  // selected here, not an older one.
  const mostRecentProjectId = projectsQuery.data?.length
    ? [...projectsQuery.data].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0].project_id
    : "";
  const activeProjectId = projectId || mostRecentProjectId;

  const handleFiles = useCallback(
    async (files: FileList | File[]) => {
      if (!activeProjectId) {
        setSelectionError("Create or select a project first.");
        return;
      }
      setSelectionError(null);
      const fileArr = Array.from(files);
      const newItems: UploadItem[] = fileArr.map((f, i) => ({
        id: `${Date.now()}-${i}`,
        filename: f.name,
        status: "uploading",
      }));
      setItems((prev) => [...newItems, ...prev]);

      for (let i = 0; i < fileArr.length; i++) {
        const file = fileArr[i];
        const itemId = newItems[i].id;
        try {
          const deviceName = file.name.replace(/\.[^.]+$/, "");
          const result = await configurationsApi.upload({ projectId: activeProjectId, deviceName, file });
          setItems((prev) =>
            prev.map((it) =>
              it.id === itemId
                ? {
                    ...it,
                    status: result.status === "NEEDS_VENDOR_CONFIRMATION" ? "needs_confirmation" : result.status === "COMPLETED" ? "done" : "error",
                    vendor: result.vendor,
                    platform: result.platform,
                    confidence: result.vendor_confidence,
                    hash: result.configuration_hash,
                    irHash: result.ir_hash,
                    error: result.error_message || undefined,
                  }
                : it
            )
          );
        } catch (err) {
          setItems((prev) =>
            prev.map((it) => (it.id === itemId ? { ...it, status: "error", error: err instanceof ApiError ? err.message : "Upload failed" } : it))
          );
        }
      }
    },
    [activeProjectId]
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Upload Configurations</h1>
        <p className="text-sm text-muted">
          Configurations enter the system only through uploaded files (.cfg, .conf, .txt, .xml, .json, .yaml, .yml).
        </p>
      </div>

      <Card>
        <CardContent className="pt-4">
          <Label>Project</Label>
          <Select value={activeProjectId} onChange={(e) => setProjectId(e.target.value)} className="max-w-sm">
            {projectsQuery.data?.map((p) => (
              <option key={p.project_id} value={p.project_id}>
                {p.name}
              </option>
            ))}
          </Select>
          {selectionError && <p className="text-xs text-danger mt-2">{selectionError}</p>}
        </CardContent>
      </Card>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        className={cn(
          "rounded-lg border-2 border-dashed p-12 text-center cursor-pointer transition-colors",
          dragOver ? "border-primary bg-primary/5" : "border-border hover:border-muted"
        )}
      >
        <UploadCloud className="mx-auto h-8 w-8 text-muted mb-3" />
        <p className="text-sm font-medium">Drag and drop configuration files here, or click to browse</p>
        <p className="text-xs text-muted mt-1">Bulk upload supported — each file becomes its own device record</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          accept=".cfg,.conf,.txt,.xml,.json,.yaml,.yml"
          onChange={(e) => e.target.files && handleFiles(e.target.files)}
        />
      </div>

      {items.length === 0 ? (
        <EmptyState title="No uploads yet" description="Uploaded files will appear here with live processing status." />
      ) : (
        <div className="space-y-2">
          {items.map((item) => (
            <Card key={item.id}>
              <CardContent className="flex items-center justify-between gap-4 py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">{item.filename}</p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {item.vendor && <Badge>{item.vendor}</Badge>}
                    {item.platform && <Badge>{item.platform}</Badge>}
                    {item.confidence != null && <Badge>confidence {(item.confidence * 100).toFixed(0)}%</Badge>}
                  </div>
                  {item.hash && <p className="text-[11px] text-muted mono mt-1">SHA-256: {truncateHash(item.hash, 16)}</p>}
                  {item.error && <p className="text-[11px] text-danger mt-1">{item.error}</p>}
                </div>
                <div className="shrink-0">
                  {item.status === "uploading" && <Badge>Uploading...</Badge>}
                  {item.status === "done" && (
                    <span className="flex items-center gap-1 text-success text-xs">
                      <CheckCircle2 className="h-4 w-4" /> Analyzed
                    </span>
                  )}
                  {item.status === "needs_confirmation" && (
                    <span className="flex items-center gap-1 text-warning text-xs">
                      <AlertTriangle className="h-4 w-4" /> Confirm vendor
                    </span>
                  )}
                  {item.status === "error" && (
                    <span className="flex items-center gap-1 text-danger text-xs">
                      <XCircle className="h-4 w-4" /> Failed
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>What happens after upload</CardTitle>
          <CardDescription>Hash → vendor detection → normalization all run immediately and synchronously</CardDescription>
        </CardHeader>
        <CardContent className="text-xs text-muted space-y-1">
          <p>1. File is validated (extension, size, encoding, path-safety) and never trusted by original filename.</p>
          <p>2. SHA-256 of the canonicalized configuration is computed and stored.</p>
          <p>3. Vendor is detected via signature matching; low-confidence results require your confirmation.</p>
          <p>4. The configuration is parsed into the vendor-neutral Security IR.</p>
          <p>5. Go to Configurations → select the device → Start Scan to run compliance/risk/attack-graph/ACO analysis.</p>
        </CardContent>
      </Card>
    </div>
  );
}
