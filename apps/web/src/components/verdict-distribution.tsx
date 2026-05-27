"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

interface VerdictCounts {
  allow: number;
  warn: number;
  block: number;
}

interface VerdictDistributionProps {
  counts: VerdictCounts;
}

export function VerdictDistribution({ counts }: VerdictDistributionProps) {
  const data = [
    { name: "Allow", value: counts.allow, color: "#10b981" },
    { name: "Warn", value: counts.warn, color: "#f59e0b" },
    { name: "Block", value: counts.block, color: "#ef4444" },
  ];

  const hasData = data.some((d) => d.value > 0);

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
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              borderRadius: "8px",
              border: "1px solid #e5e7eb",
              fontSize: "12px",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="flex justify-center gap-4 mt-2">
        {data.map((d) => (
          <div key={d.name} className="flex items-center gap-1.5">
            <div className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
            <span className="text-xs text-stone-500">{d.name} {d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
