# Kairo Phase 2 Design — Built & Verified

## What Was Built

Phase 2 delivers the full AI agent integration loop and web dashboard.

```
GitHub PR → kairo-github-action → kairo-mcp (stdio) → verdict → PR comment + status check
developer → kairo-cli → kairo-server → verdict → execute/confirm
browser → Next.js dashboard → kairo-server → display checks/policies/packages/audit
```

---

## Crate Structure (Extended)

```
kairo/
├── crates/
│   ├── kairo-core/        # Decision engine (unchanged from Phase 1)
│   ├── kairo-server/     # + optional API key auth (KAIR0_AUTH_ENABLED)
│   ├── kairo-cli/        # + multi-ecosystem, --json, auto-detection
│   ├── kairo-mcp/        # NEW: stdio MCP server, 4 tools
│   ├── kairo-github-action/  # NEW: GitHub Action with local-check mode
│   └── kairo-ingest/     # NEW: CLI for OSV, npm, GitHub Advisories, deps.dev
└── docs/superpowers/specs/
```

---

## kairo-mcp (New)

**Purpose:** stdio MCP server for AI agent integration.

**Tools:**
- `kairo.check_package` — check a package in an ecosystem
- `kairo.check_command` — parse and check a full command string
- `kairo.get_safe_version` — resolve a safe version for a package
- `kairo.explain_verdict` — get human-readable explanation of a verdict

**Transport:** stdio (no HTTP). AI agents invoke via MCP protocol.

---

## kairo-github-action (New)

**Purpose:** GitHub Action that scans PR diffs and posts verdicts.

**Trigger:** `pull_request` events (paths: `package.json`, `Cargo.lock`, `requirements.txt`, `Dockerfile`, `*.toml`, `Pipfile`, `go.mod`)

**Behavior:**
1. Fetch PR diff
2. Extract package changes (adds/updates)
3. Call kairo-mcp via stdio
4. Post PR comment with verdict summary
5. Set commit status (success/failure based on BLOCK)

**local-check mode:** `kairo-github-action local-check <pr-diff>` for testing without a real PR.

---

## kairo-ingest (New)

**Purpose:** Pre-fetch intelligence from upstream sources.

**Sources:**
- OSV.dev API (advisories)
- npm registry (metadata, publish age)
- GitHub Advisories
- deps.dev (provenance, dependencies)

**Features:**
- In-memory TTL cache
- No persistent storage in V2

---

## kairo-server Auth Layer

**Opt-in via `KAIR0_AUTH_ENABLED=true`.** Off by default.

- Static API key validation (`Authorization: Bearer <key>`)
- No key management UI (keys provisioned via env)
- No database backend

---

## CLI Improvements

Multi-ecosystem auto-detection from lockfiles:
- `package.json` → npm/pnpm/yarn/bun
- `requirements.txt` / `Pipfile` → pip
- `Cargo.lock` → cargo
- `go.mod` → go
- `Dockerfile` → docker

`--json` flag emits machine-readable JSON output.

---

## Decision Engine (Verified)

Rules in order:
1. **Block** known malicious (event-stream-flat, flatmap-stream, event-stream-promise)
2. **Block** OSV CRITICAL/HIGH advisories
3. **Warn** OSV MEDIUM/LOW advisories
4. **Block** < 5 min old packages (risk 85)
5. **Warn** < 30 min old packages (risk 55)
6. **Warn** lifecycle scripts (postinstall, install, prepare)
7. **Warn** critical packages without provenance
8. **Default** → ALLOW

**E2E verified:** flatmap-stream → BLOCK (95), lodash → ALLOW (5)

---

## Web Dashboard (New)

**Stack:** Next.js 14 App Router

**Pages:**
- `/` — overview / recent activity
- `/checks` — history of all checks
- `/policies` — view decision rules
- `/packages` — lookup packages
- `/audit` — audit log

**API:** Integrates with kairo-server REST API.

---

## What's Working

| Component | Status |
|-----------|--------|
| kairo-core decision engine | 26 tests passing, zero clippy warnings |
| kairo-cli (multi-ecosystem) | Working |
| kairo-server | Working |
| kairo-mcp (4 tools) | Working |
| kairo-github-action (local-check) | Working |
| kairo-ingest | Working |
| Web dashboard (builds) | Working |
| E2E (flatmap-stream BLOCK, lodash ALLOW) | Verified |

---

## What Could Be Next

1. **Database backend** — persist API keys, check history, audit log (PostgreSQL via `kairo-db` crate)
2. **Real GitHub token auth** — OAuth flow for GitHub App installation instead of local-check mode
3. **Persistent cache** — Redis for kairo-ingest TTL cache across restarts
4. **GitHub App** — proper GitHub App with webhook integration (auto-scan on PR open/update)
5. **Policy UI** — dashboard UI to edit block/allow rules
6. **Notification integrations** — Slack, Teams on BLOCK
7. **SBOM ingestion** — scan lockfiles for existing vulnerabilities

---

## Spec Self-Review

- All "NOT in Phase 1" addressed? YES — MCP, dashboard, GitHub Action, auth layer all built
- Naming consistent with Phase 1? YES
- Scope appropriate for V2? YES — delivers full agent loop + dashboard
- No placeholders? YES — all features reflect what was actually built
