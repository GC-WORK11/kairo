"use client";

import { useEffect, useState, useCallback } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, RefreshCw } from "lucide-react";

interface AuditEntry {
  id: string;
  verdict: "ALLOW" | "WARN" | "BLOCK";
  command: string;
  ecosystem: string;
  risk_score: number;
  reason: string;
  timestamp: string;
}

export default function ChecksPage() {
  const [checks, setChecks] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAudit = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("http://127.0.0.1:8080/v1/audit");
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setChecks(data.entries ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch audit");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAudit();
  }, [loadAudit]);

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-stone-950">Checks</h1>
        <p className="mt-1 text-sm text-stone-500">
          Full audit trail of all Kairo decisions across your organization.
        </p>
      </div>

      {/* Filter bar */}
      <div className="mb-6 flex items-center gap-3">
        <input
          type="text"
          placeholder="Search commands, packages..."
          className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-950 focus:ring-offset-1"
        />
        <select className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 focus:outline-none focus:ring-2 focus:ring-stone-950">
          <option>All verdicts</option>
          <option>ALLOW</option>
          <option>WARN</option>
          <option>BLOCK</option>
        </select>
        <select className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 focus:outline-none focus:ring-2 focus:ring-stone-950">
          <option>All ecosystems</option>
          <option>npm</option>
          <option>pnpm</option>
          <option>docker</option>
          <option>cargo</option>
        </select>
        <select className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 focus:outline-none focus:ring-2 focus:ring-stone-950">
          <option>Last 7 days</option>
          <option>Last 30 days</option>
          <option>All time</option>
        </select>
        <button
          onClick={loadAudit}
          disabled={loading}
          className="ml-auto h-9 flex items-center gap-2 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 hover:bg-stone-50 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {loading && checks.length === 0 ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-stone-200 border-t-stone-950" />
            <p className="mt-2 text-sm text-stone-500">Loading audit trail...</p>
          </div>
        </div>
      ) : error && checks.length === 0 ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-center text-red-500">
            <p className="font-medium">Failed to load audit</p>
            <p className="text-sm mt-1">{error}</p>
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-stone-200 bg-white overflow-hidden">
          <div className="divide-y divide-stone-100">
            {checks.map((check) => (
              <div key={check.id} className="flex items-center gap-4 px-6 py-4 hover:bg-stone-50 transition-colors">
                <div className="flex-shrink-0">
                  {check.verdict === "BLOCK" ? (
                    <ShieldX className="h-5 w-5 text-red-500" />
                  ) : check.verdict === "WARN" ? (
                    <ShieldAlert className="h-5 w-5 text-amber-500" />
                  ) : (
                    <ShieldCheck className="h-5 w-5 text-emerald-500" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <code className="text-sm font-mono text-stone-700">{check.command}</code>
                  <p className="text-xs text-stone-500 mt-0.5">{check.reason}</p>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <span className="rounded bg-stone-100 px-1.5 py-0.5 text-xs text-stone-500">{check.ecosystem}</span>
                  <span className={`text-sm font-semibold ${
                    check.verdict === "BLOCK" ? "text-red-600" :
                    check.verdict === "WARN" ? "text-amber-600" : "text-emerald-600"
                  }`}>{check.risk_score}</span>
                  <span className="text-xs text-stone-400 w-16 text-right">{formatRelativeTime(check.timestamp)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function formatRelativeTime(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins} min ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours} hr ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
}
