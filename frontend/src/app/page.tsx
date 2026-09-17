"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore, useHasHydrated } from "@/lib/auth-store";

export default function RootPage() {
  const router = useRouter();
  const { token } = useAuthStore();
  const hasHydrated = useHasHydrated();

  useEffect(() => {
    if (hasHydrated) router.replace(token ? "/dashboard" : "/login");
  }, [hasHydrated, token, router]);

  return null;
}
