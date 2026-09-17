"use client";

import { useEffect, useState } from "react";
import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface AuthUser {
  user_id: string;
  email: string;
  full_name: string;
  role: string;
}

interface AuthState {
  token: string | null;
  user: AuthUser | null;
  setAuth: (token: string, user: AuthUser) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      setAuth: (token, user) => set({ token, user }),
      logout: () => set({ token: null, user: null }),
    }),
    { name: "sih26155-auth" }
  )
);

/**
 * Zustand's persist middleware rehydrates from localStorage asynchronously
 * and only in the browser. Reading `useAuthStore.persist` at module scope
 * crashes during SSR (it's undefined there), and even client-side, `token`
 * is briefly null before rehydration finishes -- so every hard
 * navigation/reload would otherwise bounce a logged-in user to /login.
 * Deferring all `.persist` access into useEffect sidesteps both problems.
 */
export function useHasHydrated(): boolean {
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    if (useAuthStore.persist.hasHydrated()) {
      setHydrated(true);
      return;
    }
    const unsubscribe = useAuthStore.persist.onFinishHydration(() => setHydrated(true));
    return unsubscribe;
  }, []);

  return hydrated;
}
