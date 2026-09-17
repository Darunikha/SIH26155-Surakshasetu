"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/lib/auth-store";
import {
  LayoutDashboard,
  FolderKanban,
  Upload,
  FileText,
  ScanSearch,
  ShieldAlert,
  Gauge,
  Network,
  Wrench,
  Sparkles,
  GraduationCap,
  Link2,
  FileOutput,
  MessageSquare,
  Settings,
  LogOut,
} from "lucide-react";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/projects", label: "Projects", icon: FolderKanban },
  { href: "/upload", label: "Upload", icon: Upload },
  { href: "/configurations", label: "Configurations", icon: FileText },
  { href: "/scans", label: "Scans", icon: ScanSearch },
  { href: "/risk", label: "Risk", icon: Gauge },
  { href: "/attack-paths", label: "Attack Paths", icon: Network },
  { href: "/optimizer", label: "Optimizer (ACO)", icon: Sparkles },
  { href: "/remediation", label: "Remediation", icon: Wrench },
  { href: "/training", label: "Adaptive Learning", icon: GraduationCap },
  { href: "/blockchain", label: "Blockchain Integrity", icon: Link2 },
  { href: "/reports", label: "Reports", icon: FileOutput },
  { href: "/assistant", label: "AI Assistant", icon: MessageSquare },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuthStore();

  return (
    <aside className="fixed inset-y-0 left-0 w-60 border-r border-border bg-surface flex flex-col">
      <div className="h-14 flex items-center gap-2 px-4 border-b border-border">
        <Image src="/brand/icon.png" alt="" width={22} height={28} priority />
        <span className="font-semibold text-sm">SurakshaSetu</span>
      </div>
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
        {NAV.map((item) => {
          const active = pathname === item.href || pathname.startsWith(item.href + "/");
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                active ? "bg-primary/15 text-primary" : "text-muted hover:bg-surface-raised hover:text-foreground"
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border p-3">
        <div className="flex items-center justify-between">
          <div className="min-w-0">
            <p className="text-xs font-medium truncate">{user?.full_name}</p>
            <p className="text-[11px] text-muted truncate">{user?.role}</p>
          </div>
          <button onClick={logout} className="text-muted hover:text-danger" title="Log out">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
