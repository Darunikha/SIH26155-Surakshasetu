"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { devicesApi, projectsApi, ApiError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { LoadingBlock, EmptyState } from "@/components/ui/misc";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const projectsQuery = useQuery({ queryKey: ["projects"], queryFn: projectsApi.list });
  const devicesQuery = useQuery({ queryKey: ["devices", id], queryFn: () => devicesApi.list(id) });

  const [name, setName] = useState("");
  const [criticality, setCriticality] = useState("medium");
  const [error, setError] = useState<string | null>(null);

  const createDevice = useMutation({
    mutationFn: () =>
      devicesApi.create({ project_id: id, name, asset_context: { criticality: criticality as "low" | "medium" | "high" | "critical" } }),
    onSuccess: () => {
      setName("");
      qc.invalidateQueries({ queryKey: ["devices", id] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to create device"),
  });

  const project = projectsQuery.data?.find((p) => p.project_id === id);

  if (devicesQuery.isLoading) return <LoadingBlock />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">{project?.name || id}</h1>
        <p className="text-sm text-muted">{project?.description}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Add device</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="grid sm:grid-cols-[2fr_1fr_auto] gap-3 items-end"
            onSubmit={(e) => {
              e.preventDefault();
              createDevice.mutate();
            }}
          >
            <div>
              <Label>Device name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div>
              <Label>Criticality</Label>
              <Select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </Select>
            </div>
            <Button type="submit" disabled={createDevice.isPending}>
              Add
            </Button>
          </form>
          {error && <p className="text-xs text-danger mt-2">{error}</p>}
        </CardContent>
      </Card>

      {devicesQuery.data?.length === 0 && (
        <EmptyState title="No devices yet" description="Add a device, then upload a configuration for it." />
      )}

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {devicesQuery.data?.map((d) => (
          <Link key={d.device_id} href={`/configurations?device=${d.device_id}`}>
            <Card className="hover:border-primary/50 transition-colors h-full">
              <CardHeader>
                <CardTitle>{d.name}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex gap-2">
                  <Badge>{d.vendor || "Vendor unknown"}</Badge>
                  <Badge>{d.asset_context.criticality}</Badge>
                </div>
                <p className="text-xs text-muted">{d.platform || "No configuration uploaded yet"}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
