import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Triggers a client-side save of an already-fetched blob (e.g. a PDF response
 * read via the authenticated API client) -- used instead of a plain `<a href>`
 * to a protected download endpoint, since a normal link navigation can't
 * attach the Authorization header the backend requires. */
export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function formatDate(iso: string | undefined | null): string {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function truncateHash(hash: string | undefined | null, len = 10): string {
  if (!hash) return "-";
  if (hash.length <= len * 2) return hash;
  return `${hash.slice(0, len)}...${hash.slice(-6)}`;
}

export const severityColor: Record<string, string> = {
  CRITICAL: "text-critical border-critical/40 bg-critical/10",
  HIGH: "text-high border-high/40 bg-high/10",
  MEDIUM: "text-medium border-medium/40 bg-medium/10",
  LOW: "text-low border-low/40 bg-low/10",
};

export const statusColor: Record<string, string> = {
  PASS: "text-success border-success/40 bg-success/10",
  FAIL: "text-danger border-danger/40 bg-danger/10",
  NOT_APPLICABLE: "text-muted border-border bg-surface-raised",
  UNKNOWN: "text-warning border-warning/40 bg-warning/10",
  INSUFFICIENT_EVIDENCE: "text-warning border-warning/40 bg-warning/10",
};
