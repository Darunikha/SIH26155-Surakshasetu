"use client";

import { useQuery } from "@tanstack/react-query";
import { devicesApi, scansApi } from "@/lib/api";
import { Select, Label } from "@/components/ui/input";

export function useScanSelector() {
  const scansQuery = useQuery({ queryKey: ["scans"], queryFn: () => scansApi.list() });
  const devicesQuery = useQuery({ queryKey: ["devices-all"], queryFn: () => devicesApi.list() });
  const completedScans = (scansQuery.data || []).filter((s) => s.status === "COMPLETED");
  return { completedScans, devicesQuery, isLoading: scansQuery.isLoading };
}

export function ScanSelector({
  scanId,
  onChange,
}: {
  scanId: string;
  onChange: (scanId: string) => void;
}) {
  const { completedScans, devicesQuery } = useScanSelector();
  const deviceById = new Map((devicesQuery.data || []).map((d) => [d.device_id, d]));

  return (
    <div className="max-w-md">
      <Label>Select a completed scan</Label>
      <Select value={scanId} onChange={(e) => onChange(e.target.value)}>
        <option value="">Choose a scan...</option>
        {completedScans.map((s) => (
          <option key={s.scan_id} value={s.scan_id}>
            {deviceById.get(s.device_id)?.name || s.device_id} — {s.scan_id} ({new Date(s.created_at).toLocaleDateString()})
          </option>
        ))}
      </Select>
    </div>
  );
}
