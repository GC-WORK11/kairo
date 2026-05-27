"use client";

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface Check {
  id: string;
  verdict: "Allow" | "Warn" | "Block";
  risk_score: number;
  timestamp: string;
}

interface RiskTrendProps {
  checks: Check[];
}

export function RiskTrend({ checks }: RiskTrendProps) {
  // Transform checks into daily aggregated data
  const dataMap = new Map<string, { blocked: number; warnings: number; allowed: number }>();

  // Initialize last 7 days
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const key = date.toLocaleDateString("en-US", { weekday: "short" });
    dataMap.set(key, { blocked: 0, warnings: 0, allowed: 0 });
  }

  // Aggregate checks into days (simplified - just spread checks across last 7 days)
  const sortedChecks = [...checks].reverse();
  const dayKeys = Array.from(dataMap.keys());

  sortedChecks.forEach((check, index) => {
    if (index < dayKeys.length) {
      const day = dataMap.get(dayKeys[index])!;
      if (check.verdict === "Block") day.blocked++;
      else if (check.verdict === "Warn") day.warnings++;
      else day.allowed++;
    }
  });

  const data = dayKeys.map((day) => ({
    date: day,
    ...dataMap.get(day)!,
  }));

  const hasData = data.some((d) => d.blocked > 0 || d.warnings > 0 || d.allowed > 0);

  if (!hasData) {
    return (
      <div className="h-48 flex items-center justify-center text-stone-400 text-sm">
        No data yet
      </div>
    );
  }

  return (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
          <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="#a1a1aa" />
          <YAxis tick={{ fontSize: 11 }} stroke="#a1a1aa" />
          <Tooltip
            contentStyle={{
              borderRadius: "8px",
              border: "1px solid #e5e7eb",
              fontSize: "12px",
            }}
          />
          <Area
            type="monotone"
            dataKey="blocked"
            stackId="1"
            stroke="#ef4444"
            fill="#fee2e2"
            strokeWidth={1}
          />
          <Area
            type="monotone"
            dataKey="warnings"
            stackId="1"
            stroke="#f59e0b"
            fill="#fef3c7"
            strokeWidth={1}
          />
          <Area
            type="monotone"
            dataKey="allowed"
            stackId="1"
            stroke="#10b981"
            fill="#d1fae5"
            strokeWidth={1}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
