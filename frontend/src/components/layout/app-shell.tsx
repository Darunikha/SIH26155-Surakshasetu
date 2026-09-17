"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore, useHasHydrated } from "@/lib/auth-store";
import { Sidebar } from "./sidebar";
import { LoadingBlock } from "@/components/ui/misc";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { token } = useAuthStore();
  const hasHydrated = useHasHydrated();
  const router = useRouter();

  useEffect(() => {
    if (hasHydrated && !token) router.replace("/login");
  }, [hasHydrated, token, router]);

  if (!hasHydrated || !token) return <LoadingBlock />;

  return (
    <div className="min-h-screen">
      <Sidebar />
      <main className="pl-60">
        <div className="max-w-7xl mx-auto px-6 py-6">{children}</div>
      </main>
    </div>
  );
}
