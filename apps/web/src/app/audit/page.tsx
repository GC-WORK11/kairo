import { FileText, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

export default function AuditPage() {
  const events = [
    { id: "1", action: "check_verdict", user: "agent-001", target: "pnpm add event-stream@3.3.6", verdict: "BLOCK", timestamp: "2024-01-15 14:32:01" },
    { id: "2", action: "policy_updated", user: "alice@acme.io", target: "Production Safety v2", verdict: null, timestamp: "2024-01-15 14:28:45" },
    { id: "3", action: "check_verdict", user: "agent-002", target: "npm install axios@1.6.0", verdict: "WARN", timestamp: "2024-01-15 14:25:12" },
    { id: "4", action: "team_member_added", user: "bob@acme.io", target: "carol@acme.io", verdict: null, timestamp: "2024-01-15 14:20:00" },
    { id: "5", action: "check_verdict", user: "agent-001", target: "pnpm add lodash@4.17.21", verdict: "ALLOW", timestamp: "2024-01-15 14:18:33" },
  ];

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-stone-950">Audit Log</h1>
        <p className="mt-1 text-sm text-stone-500">
          Complete history of all Kairo actions and configuration changes.
        </p>
      </div>

      <div className="mb-6 flex items-center gap-3">
        <input
          type="text"
          placeholder="Search events..."
          className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm placeholder:text-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-950 focus:ring-offset-1"
        />
        <select className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 focus:outline-none focus:ring-2 focus:ring-stone-950">
          <option>All actions</option>
          <option>check_verdict</option>
          <option>policy_updated</option>
          <option>team_member_added</option>
        </select>
        <select className="h-9 rounded-lg border border-stone-200 bg-white px-3 text-sm text-stone-600 focus:outline-none focus:ring-2 focus:ring-stone-950">
          <option>Last 7 days</option>
          <option>Last 30 days</option>
          <option>All time</option>
        </select>
      </div>

      <div className="rounded-xl border border-stone-200 bg-white overflow-hidden">
        <div className="divide-y divide-stone-100">
          {events.map((event) => (
            <div key={event.id} className="flex items-start gap-4 px-6 py-4 hover:bg-stone-50 transition-colors">
              <div className="flex-shrink-0 mt-0.5">
                <FileText className="h-4 w-4 text-stone-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-mono text-stone-700">{event.action}</span>
                  {event.verdict && (
                    event.verdict === "BLOCK" ? (
                      <ShieldX className="h-4 w-4 text-red-500" />
                    ) : event.verdict === "WARN" ? (
                      <ShieldAlert className="h-4 w-4 text-amber-500" />
                    ) : (
                      <ShieldCheck className="h-4 w-4 text-emerald-500" />
                    )
                  )}
                </div>
                <p className="text-xs text-stone-500 mt-0.5">
                  {event.user} → {event.target}
                </p>
              </div>
              <div className="flex-shrink-0 text-xs text-stone-400 font-mono">
                {event.timestamp}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
