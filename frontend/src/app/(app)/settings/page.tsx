"use client";

import { useAuthStore } from "@/lib/auth-store";
import { API_BASE_URL } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function SettingsPage() {
  const { user } = useAuthStore();

  return (
    <div className="space-y-6 max-w-xl">
      <div>
        <h1 className="text-lg font-semibold">Settings</h1>
        <p className="text-sm text-muted">Account and environment details.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>{user?.full_name}</p>
          <p className="text-muted">{user?.email}</p>
          <Badge>{user?.role}</Badge>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Environment</CardTitle>
        </CardHeader>
        <CardContent className="space-y-1 text-xs text-muted">
          <p>API endpoint: {API_BASE_URL}</p>
          <p>Blockchain: Hyperledger Fabric (local network)</p>
          <p>AI: Ollama (local LLM) — status shown per-feature when unavailable</p>
        </CardContent>
      </Card>
    </div>
  );
}
