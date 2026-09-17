import { cn } from "@/lib/utils";
import { Card } from "./card";

export function StatCard({
  label,
  value,
  hint,
  accent,
  className,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  accent?: "success" | "warning" | "danger" | "primary";
  className?: string;
}) {
  const accentClass = accent
    ? {
        success: "text-success",
        warning: "text-warning",
        danger: "text-danger",
        primary: "text-primary",
      }[accent]
    : "text-foreground";

  return (
    <Card className={cn("p-4", className)}>
      <p className="text-xs text-muted">{label}</p>
      <p className={cn("text-2xl font-semibold mt-1", accentClass)}>{value}</p>
      {hint && <p className="text-[11px] text-muted mt-1">{hint}</p>}
    </Card>
  );
}
