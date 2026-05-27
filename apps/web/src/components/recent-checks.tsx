"use client";

import { ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

interface Check {
  id: string;
  verdict: "Allow" | "Warn" | "Block";
  command: string;
  ecosystem: string;
  risk_score: number;
  summary: string;
  timestamp: string;
}

interface RecentChecksProps {
  checks: Check[];
}

export function RecentChecks({ checks }: RecentChecksProps) {
  if (checks.length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-stone-400 text-sm">
        No checks yet
      </div>
    );
  }

  return (
    <div className="divide-y divide-stone-100">
      {checks.map((check) => (
        <div key={check.id} className="flex items-center gap-4 px-6 py-4 hover:bg-stone-50 transition-colors">
          <div className="flex-shrink-0">
            {check.verdict === "Block" ? (
              <ShieldX className="h-5 w-5 text-red-500" />
            ) : check.verdict === "Warn" ? (
              <ShieldAlert className="h-5 w-5 text-amber-500" />
            ) : (
              <ShieldCheck className="h-5 w-5 text-emerald-500" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <code className="text-sm font-mono text-stone-700 truncate">{check.command}</code>
              <span className="flex-shrink-0 rounded bg-stone-100 px-1.5 py-0.5 text-xs text-stone-500">
                {check.ecosystem}
              </span>
            </div>
            <p className="text-xs text-stone-500 mt-0.5 truncate">{check.summary}</p>
          </div>
          <div className="flex-shrink-0 text-right">
            <div className={`text-sm font-semibold ${
              check.verdict === "Block" ? "text-red-600" :
              check.verdict === "Warn" ? "text-amber-600" : "text-emerald-600"
            }`}>
              {check.risk_score}
            </div>
            <div className="text-xs text-stone-400">{check.timestamp}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
