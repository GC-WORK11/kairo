import type { Metadata } from "next";
import "./globals.css";
import { QueryProvider } from "@/components/query-provider";

export const metadata: Metadata = {
  title: "Kairo — Live intelligence for AI coding agents",
  description: "Real-time risk decisions for package installs, terminal commands, CI/CD changes, and more.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="antialiased">
      <body className="min-h-screen bg-white font-sans text-stone-950">
        <QueryProvider>
          <div className="flex min-h-screen flex-col">
            <header className="border-b border-stone-200 bg-white">
              <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-stone-950 text-white text-sm font-bold">
                    K
                  </div>
                  <span className="text-sm font-semibold tracking-tight">Kairo</span>
                </div>
                <nav className="flex items-center gap-6 text-sm text-stone-500">
                  <a href="/checks" className="hover:text-stone-950 transition-colors">Checks</a>
                  <a href="/policies" className="hover:text-stone-950 transition-colors">Policies</a>
                  <a href="/packages" className="hover:text-stone-950 transition-colors">Packages</a>
                  <a href="/audit" className="hover:text-stone-950 transition-colors">Audit Log</a>
                </nav>
                <div className="flex items-center gap-3">
                  <button className="rounded-lg bg-stone-950 px-3 py-1.5 text-sm font-medium text-white hover:bg-stone-800 transition-colors">
                    Connect
                  </button>
                </div>
              </div>
            </header>
            <main className="flex-1">
              {children}
            </main>
          </div>
        </QueryProvider>
      </body>
    </html>
  );
}
