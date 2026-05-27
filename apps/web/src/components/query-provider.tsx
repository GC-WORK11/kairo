"use client";

// V1 uses mock data — no React Query needed yet.
// Add a real data fetching library here when connecting to live APIs.
export function QueryProvider({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
