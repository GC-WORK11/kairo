"use client";

import { useEffect, useState } from "react";
import { VerdictDistribution } from "@/components/verdict-distribution";
import { RecentChecks } from "@/components/recent-checks";
import { RiskTrend } from "@/components/risk-trend";
import { ShieldCheck, ShieldAlert, ShieldX, Activity } from "lucide-react";

interface CheckResult {
  id: string;
  verdict: "Allow" | "Warn" | "Block";
  command: string;
  ecosystem: string;
  risk_score: number;
  summary: string;
  timestamp: string;
}

interface Stats {
  total: number;
  blocked: number;
  warnings: number;
  allowed: number;
}

export default function DashboardPage() {
  const [checks, setChecks] = useState<CheckResult[]>([]);
  const [stats, setStats] = useState<Stats>({ total: 0, blocked: 0, warnings: 0, allowed: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setError(null);

      try {
        const [auditRes, statsRes] = await Promise.all([
          fetch("http://127.0.0.1:8080/v1/audit"),
          fetch("http://127.0.0.1:8080/v1/stats"),
        ]);

        if (!auditRes.ok || !statsRes.ok) {
          throw new Error("Failed to fetch from API");
        }

        const auditData = await auditRes.json();
        const statsData = await statsRes.json();

        const entries = auditData.entries ?? [];
        setChecks(entries.slice(0, 5).map((e: Record<string, unknown>) => ({
          id: String(e.id),
          verdict: (e.verdict as string).charAt(0).toUpperCase() + (e.verdict as string).slice(1).toLowerCase() as "Allow" | "Warn" | "Block",
          command: String(e.command),
          ecosystem: String(e.ecosystem),
          risk_score: Number(e.risk_score),
          summary: String(e.reason ?? ""),
          timestamp: String(e.timestamp),
        })));

        setStats({
          total: statsData.total ?? 0,
          blocked: statsData.blocked ?? 0,
          warnings: statsData.warnings ?? 0,
          allowed: statsData.allowed ?? 0,
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to fetch data");
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, []);

  const verdictCounts = {
    allow: stats.allowed,
    warn: stats.warnings,
    block: stats.blocked,
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-stone-950">Overview</h1>
        <p className="mt-1 text-sm text-stone-500">
          Real-time intelligence for your AI coding agents.
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-stone-200 border-t-stone-950" />
            <p className="mt-2 text-sm text-stone-500">Analyzing packages...</p>
          </div>
        </div>
      ) : error ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-center text-red-500">
            <p className="font-medium">Failed to load data</p>
            <p className="text-sm mt-1">{error}</p>
          </div>
        </div>
      ) : (
        <>
          {/* Stats row */}
          <div className="grid grid-cols-4 gap-4 mb-8">
            <StatCard
              label="Total Checks"
              value={stats.total.toString()}
              icon={<Activity className="h-4 w-4 text-stone-400" />}
              sublabel="Last 7 days"
            />
            <StatCard
              label="Blocked"
              value={stats.blocked.toString()}
              icon={<ShieldX className="h-4 w-4 text-red-500" />}
              sublabel="High-risk actions stopped"
              valueColor="text-red-600"
            />
            <StatCard
              label="Warnings"
              value={stats.warnings.toString()}
              icon={<ShieldAlert className="h-4 w-4 text-amber-500" />}
              sublabel="Required human review"
              valueColor="text-amber-600"
            />
            <StatCard
              label="Allowed"
              value={stats.allowed.toString()}
              icon={<ShieldCheck className="h-4 w-4 text-emerald-500" />}
              sublabel="Actions approved"
              valueColor="text-emerald-600"
            />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-3 gap-4 mb-8">
            <div className="col-span-2 rounded-xl border border-stone-200 bg-white p-6">
              <h2 className="mb-4 text-sm font-medium text-stone-950">Risk Trend</h2>
              <RiskTrend checks={checks} />
            </div>
            <div className="rounded-xl border border-stone-200 bg-white p-6">
              <h2 className="mb-4 text-sm font-medium text-stone-950">Verdict Distribution</h2>
              <VerdictDistribution counts={verdictCounts} />
            </div>
          </div>

          {/* Recent checks */}
          <div className="rounded-xl border border-stone-200 bg-white">
            <div className="flex items-center justify-between border-b border-stone-200 px-6 py-4">
              <h2 className="text-sm font-medium text-stone-950">Recent Checks</h2>
              <a href="/checks" className="text-sm text-stone-500 hover:text-stone-950 transition-colors">
                View all
              </a>
            </div>
            <RecentChecks checks={checks} />
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  sublabel,
  valueColor = "text-stone-950",
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
  sublabel: string;
  valueColor?: string;
}) {
  return (
    <div className="rounded-xl border border-stone-200 bg-white p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-stone-500 uppercase tracking-wide">{label}</span>
        {icon}
      </div>
      <div className={`text-2xl font-semibold ${valueColor}`}>{value}</div>
      <div className="mt-1 text-xs text-stone-400">{sublabel}</div>
    </div>
  );
}
