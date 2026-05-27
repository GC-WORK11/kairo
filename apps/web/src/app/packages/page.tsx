const MOCK_PACKAGES = [
  { name: "lodash", ecosystem: "npm", risk_score: 5, last_checked: "2 hr ago", advisories: 0, trend: "stable" },
  { name: "express", ecosystem: "npm", risk_score: 18, last_checked: "4 hr ago", advisories: 1, trend: "stable" },
  { name: "axios", ecosystem: "npm", risk_score: 42, last_checked: "6 hr ago", advisories: 2, trend: "up" },
  { name: "ws", ecosystem: "npm", risk_score: 65, last_checked: "1 hr ago", advisories: 3, trend: "up" },
  { name: "event-stream", ecosystem: "npm", risk_score: 96, last_checked: "2 min ago", advisories: 5, trend: "critical" },
];

export default function PackagesPage() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-stone-950">Packages</h1>
        <p className="mt-1 text-sm text-stone-500">
          Monitor risk scores and advisory status for packages in your dependency graph.
        </p>
      </div>

      <div className="mb-6 flex items-center gap-3">
        <input
          type="text"
          placeholder="Search packages..."
          className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-950 focus:ring-offset-1"
        />
        <select className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 focus:outline-none focus:ring-2 focus:ring-stone-950">
          <option>All ecosystems</option>
          <option>npm</option>
          <option>cargo</option>
          <option>pip</option>
        </select>
      </div>

      <div className="rounded-xl border border-stone-200 bg-white overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-stone-100 bg-stone-50">
              <th className="px-6 py-3 text-left text-xs font-medium text-stone-500 uppercase tracking-wide">Package</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-stone-500 uppercase tracking-wide">Ecosystem</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-stone-500 uppercase tracking-wide">Risk Score</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-stone-500 uppercase tracking-wide">Advisories</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-stone-500 uppercase tracking-wide">Last Checked</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-stone-500 uppercase tracking-wide">Trend</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-stone-100">
            {MOCK_PACKAGES.map((pkg) => (
              <tr key={pkg.name} className="hover:bg-stone-50 transition-colors">
                <td className="px-6 py-4">
                  <code className="text-sm font-mono text-stone-700">{pkg.name}</code>
                </td>
                <td className="px-6 py-4">
                  <span className="rounded bg-stone-100 px-1.5 py-0.5 text-xs text-stone-600">{pkg.ecosystem}</span>
                </td>
                <td className="px-6 py-4">
                  <span className={`text-sm font-semibold ${
                    pkg.risk_score >= 70 ? "text-red-600" :
                    pkg.risk_score >= 40 ? "text-amber-600" : "text-emerald-600"
                  }`}>{pkg.risk_score}</span>
                </td>
                <td className="px-6 py-4 text-sm text-stone-600">{pkg.advisories}</td>
                <td className="px-6 py-4 text-sm text-stone-500">{pkg.last_checked}</td>
                <td className="px-6 py-4">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${
                    pkg.trend === "critical" ? "bg-red-50 text-red-600" :
                    pkg.trend === "up" ? "bg-amber-50 text-amber-600" :
                    "bg-emerald-50 text-emerald-600"
                  }`}>
                    {pkg.trend}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
