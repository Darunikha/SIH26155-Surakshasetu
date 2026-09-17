"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { projectsApi, ApiError } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { LoadingBlock, ErrorBlock, EmptyState } from "@/components/ui/misc";
import { formatDate } from "@/lib/utils";

export default function ProjectsPage() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({ queryKey: ["projects"], queryFn: projectsApi.list });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const createMutation = useMutation({
    mutationFn: () => projectsApi.create({ name, description }),
    onSuccess: () => {
      setName("");
      setDescription("");
      setFormError(null);
      qc.invalidateQueries({ queryKey: ["projects"] });
    },
    onError: (err) => setFormError(err instanceof ApiError ? err.message : "Failed to create project"),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Projects</h1>
        <p className="text-sm text-muted">Group devices and audits by engagement or environment.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>New project</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="grid sm:grid-cols-[2fr_3fr_auto] gap-3 items-end"
            onSubmit={(e) => {
              e.preventDefault();
              createMutation.mutate();
            }}
          >
            <div>
              <Label>Name</Label>
              <Input name="projectName" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div>
              <Label>Description</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <Button type="submit" disabled={createMutation.isPending}>
              {createMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </form>
          {formError && <p className="text-xs text-danger mt-2">{formError}</p>}
        </CardContent>
      </Card>

      {isLoading && <LoadingBlock />}
      {isError && <ErrorBlock message={(error as Error).message} />}
      {data && data.length === 0 && <EmptyState title="No projects yet" description="Create your first project above." />}

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {data?.map((p) => (
          <Link key={p.project_id} href={`/projects/${p.project_id}`}>
            <Card className="hover:border-primary/50 transition-colors h-full">
              <CardHeader>
                <CardTitle>{p.name}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-xs text-muted">{p.description || "No description"}</p>
                <p className="text-[11px] text-muted mt-3">Created {formatDate(p.created_at)}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
