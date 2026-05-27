const API_BASE = "http://127.0.0.1:8080";

export interface DecideRequest {
  action_type: "PackageInstall";
  ecosystem: "npm" | "pnpm" | "yarn" | "bun" | "pip" | "cargo" | "go" | "docker";
  command: string;
  package: string;
  version: string;
  repo_context: {
    framework: string | null;
    has_database: boolean;
    has_ci: boolean;
  };
}

export interface Verdict {
  verdict: "Allow" | "Warn" | "Block";
  risk_score: number;
  title: string;
  summary: string;
  recommended_action: string | null;
  safe_command: string | null;
  evidence: unknown[];
}

export async function fetchVerdict(request: DecideRequest): Promise<Verdict> {
  const response = await fetch(`${API_BASE}/v1/decide`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return response.json();
}

// Sample packages to demonstrate real API calls
export const SAMPLE_PACKAGES: DecideRequest[] = [
  {
    action_type: "PackageInstall",
    ecosystem: "npm",
    command: "npm install lodash@4.17.21",
    package: "lodash",
    version: "4.17.21",
    repo_context: { framework: null, has_database: false, has_ci: false },
  },
  {
    action_type: "PackageInstall",
    ecosystem: "npm",
    command: "npm install express@4.18.2",
    package: "express",
    version: "4.18.2",
    repo_context: { framework: null, has_database: false, has_ci: false },
  },
  {
    action_type: "PackageInstall",
    ecosystem: "npm",
    command: "npm install axios@1.6.0",
    package: "axios",
    version: "1.6.0",
    repo_context: { framework: null, has_database: false, has_ci: false },
  },
  {
    action_type: "PackageInstall",
    ecosystem: "npm",
    command: "npm install react@18.2.0",
    package: "react",
    version: "18.2.0",
    repo_context: { framework: "next", has_database: false, has_ci: true },
  },
  {
    action_type: "PackageInstall",
    ecosystem: "npm",
    command: "npm install typescript@5.0.0",
    package: "typescript",
    version: "5.0.0",
    repo_context: { framework: null, has_database: false, has_ci: false },
  },
];
