export default function PoliciesPage() {
  const policies = [
    {
      id: "1",
      name: "Malicious Package Blocking",
      description: "Block known malicious packages from being installed",
      rules: [
        "Block event-stream-flat",
        "Block flatmap-stream",
        "Block event-stream-promise",
      ],
      repos: null,
      severity: "critical" as const,
    },
    {
      id: "2",
      name: "Package Age Risk",
      description: "Evaluate packages based on their publish age",
      rules: [
        "Block packages < 5 minutes old (risk score 85)",
        "Warn on packages < 30 minutes old (risk score 55)",
      ],
      repos: null,
      severity: "strict" as const,
    },
    {
      id: "3",
      name: "Lifecycle Script Prevention",
      description: "Block or warn on potentially dangerous lifecycle scripts",
      rules: [
        "Warn on postinstall scripts",
        "Warn on install scripts",
        "Warn on prepare scripts",
      ],
      repos: null,
      severity: "moderate" as const,
    },
    {
      id: "4",
      name: "OSV Advisory Severity",
      description: "Take action based on OSV vulnerability severity levels",
      rules: [
        "Block CRITICAL severity OSV advisories",
        "Block HIGH severity OSV advisories",
        "Warn on MEDIUM severity OSV advisories",
        "Warn on LOW severity OSV advisories",
        "Warn on UNKNOWN severity OSV advisories",
      ],
      repos: null,
      severity: "strict" as const,
    },
    {
      id: "5",
      name: "Critical Package Provenance",
      description: "Require npm provenance for critical packages",
      rules: [
        "Warn on express without npm provenance",
        "Warn on lodash without npm provenance",
        "Warn on axios without npm provenance",
        "Warn on ws without npm provenance",
        "Warn on minimist without npm provenance",
      ],
      repos: null,
      severity: "moderate" as const,
    },
  ];

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-stone-950">Policies</h1>
          <p className="mt-1 text-sm text-stone-500">
            Define rules for how Kairo evaluates actions across your organization.
          </p>
        </div>
        <button className="rounded-lg bg-stone-950 px-4 py-2 text-sm font-medium text-white hover:bg-stone-800 transition-colors">
          New Policy
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {policies.map((policy) => (
          <div key={policy.id} className="rounded-xl border border-stone-200 bg-white p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-stone-950">{policy.name}</h3>
                <p className="mt-0.5 text-xs text-stone-500">{policy.description}</p>
              </div>
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${
                policy.severity === "critical" ? "bg-red-100 text-red-700" :
                policy.severity === "strict" ? "bg-red-50 text-red-600" :
                "bg-amber-50 text-amber-600"
              }`}>
                {policy.severity}
              </span>
            </div>
            <ul className="space-y-1.5 mb-4">
              {policy.rules.map((rule, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-stone-600">
                  <span className="mt-0.5 h-1.5 w-1.5 rounded-full bg-stone-300 flex-shrink-0" />
                  {rule}
                </li>
              ))}
            </ul>
            <div className="pt-3 border-t border-stone-100 flex items-center justify-between">
              <span className="text-xs text-stone-400">{policy.repos != null ? `${policy.repos} repositories` : "All repositories"}</span>
              <button className="text-xs text-stone-600 hover:text-stone-950 transition-colors">Edit →</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
