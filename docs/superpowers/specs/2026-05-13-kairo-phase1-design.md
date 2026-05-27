# Kairo Phase 1 Design — CLI + Decision Server

## Product: Kairo
**Phase 1 goal:** Working demo of the core loop:
```
developer/agent command → kairo-cli → kairo-server → verdict → CLI prints ALLOW/WARN/BLOCK
```

---

## Crate Structure

```
kairo/
├── crates/
│   ├── kairo-core/      # Shared types, decision models, risk engine
│   ├── kairo-server/    # Decision Server (Axum HTTP API)
│   └── kairo-cli/       # CLI adapter (clap, reqwest)
└── Cargo.toml           # Workspace manifest
```

---

## kairo-core

**Purpose:** Shared types and pure decision logic. No I/O, no network calls.

**Exposed types:**

```rust
// Action that an AI agent or developer wants to perform
pub struct Action {
    pub action_type: ActionType,       // e.g. PackageInstall, CommandExec
    pub ecosystem: Ecosystem,         // npm, pnpm, yarn, bun, pip, cargo
    pub command: String,              // raw command string
    pub package: Option<String>,      // e.g. "@tanstack/react-router"
    pub version: Option<String>,      // e.g. "latest", "1.2.3"
    pub repo_context: RepoContext,    // framework, has_database, has_ci
}

// Verdict returned by the decision engine
pub struct Verdict {
    pub verdict: VerdictType,        // ALLOW, WARN, BLOCK
    pub risk_score: u8,              // 0-100
    pub title: String,
    pub summary: String,
    pub recommended_action: Option<String>,
    pub safe_command: Option<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Copy)]
pub enum VerdictType { Allow, Warn, Block }

pub enum ActionType {
    PackageInstall,
    CommandExec,
    CiChange,
    Migration,
    InfraEdit,
}

pub enum Ecosystem { npm, pnpm, yarn, bun, pip, cargo, go, docker }
```

**Decision engine (pure function):**

```rust
pub fn decide(action: &Action, intelligence: &PackageIntelligence) -> Verdict
```

Rules evaluated in order:
1. Hardcoded block list (malicious packages)
2. Publish age check (package < 30 min old → WARN)
3. Lifecycle script check (has postinstall/prepare scripts → WARN/BLOCK)
4. OSV advisory match → BLOCK/WARN by severity
5. Provenance check (no provenance on critical package → WARN)
6. Default → ALLOW

---

## kairo-server

**Purpose:** HTTP server that receives action payloads and returns verdicts.

- **Transport:** HTTP (no TLS in V1)
- **Address:** `127.0.0.1:8080`
- **Framework:** Axum
- **No auth in V1**

### Endpoints

#### `POST /v1/decide`

**Request:**
```json
{
  "action_type": "package_install",
  "ecosystem": "npm",
  "command": "pnpm add some-package@latest",
  "package": "some-package",
  "version": "latest",
  "repo_context": {
    "framework": "nextjs",
    "has_database": true,
    "has_ci": true
  }
}
```

**Response:**
```json
{
  "verdict": "warn",
  "risk_score": 72,
  "title": "Fresh high-risk package install",
  "summary": "This package was published 8 minutes ago and includes a postinstall script.",
  "recommended_action": "Pin a known stable version or wait 24h.",
  "safe_command": "pnpm add some-package@1.0.0",
  "evidence": [
    { "type": "publish_age", "source": "npm_registry", "detail": "8 minutes old" },
    { "type": "lifecycle_script", "source": "npm_package_json", "detail": "postinstall script present" }
  ]
}
```

#### `GET /health`

Returns `{"status": "ok"}` — for sanity checking.

### Server-side Integrations (V1)

These are looked up at request time (not pre-ingested):

- **OSV.dev API** — `GET https://api.osv.dev/v1/query` — check if package+version has advisories
- **npm Registry** — `GET https://registry.npmjs.org/<package>` — get publish time, lifecycle scripts, version info
- **Hardcoded rules** — in-memory blocklist of known malicious packages

### Data Flow

```
Request JSON
    ↓
parse into kairo_core::Action
    ↓
fetch intelligence (OSV + npm registry in parallel)
    ↓
kairo_core::decide(&action, &intelligence)
    ↓
serialize Verdict → JSON response
```

---

## kairo-cli

**Purpose:** Developer-facing CLI that captures commands and queries the Decision Server.

### Commands

#### `kairo check "<command>"`
Parse the command string, send to Decision Server, print verdict.
Does NOT execute the command.

#### `kairo run -- <command>`
Parse the command, send to Decision Server.
If ALLOW → execute the command.
If WARN → print warning + prompt for confirmation, then execute if confirmed.
If BLOCK → print verdict + exit 1 without executing.

#### `kairo check-package <ecosystem> <package> <version>`
Direct package check without a full command string.

### Command Parsing

The CLI must parse common package manager commands:

```
pnpm add <package>@<version>
npm install <package>@<version>
yarn add <package>@<version>
bun add <package>@<version>
pip install <package>==<version>
cargo install <package>
```

Extract: ecosystem, package name, version.

### Output Format

```
$ kairo run -- pnpm add suspicious-package

╔══════════════════════════════════════╗
║  KAIRO                              ║
╠══════════════════════════════════════╣
║  VERDICT    WARN                    ║
║  RISK       72 / 100                ║
║  TITLE      Fresh high-risk package ║
╠══════════════════════════════════════╣
║  Package: suspicious-package@latest  ║
║  Summary: published 8 minutes ago,  ║
║  has postinstall script             ║
║  RECOMMEND: pin stable version      ║
╚══════════════════════════════════════╝

Continue? [y/N]
```

### Error Handling

- Server unreachable → print error + exit 1
- Invalid response → print error + exit 1
- Timeout (5s default) → print error + exit 1

---

## Build & Run

```bash
# Terminal 1 — start Decision Server
cargo run -p kairo-server

# Terminal 2 — run CLI
cargo run -p kairo-cli -- run -- pnpm add some-package@latest
cargo run -p kairo-cli -- check "npm install express"
cargo run -p kairo-cli -- check-package npm lodash 4.17.21
```

---

## V1 Demo Scenario

1. Server starts on `127.0.0.1:8080`
2. `cargo run -p kairo-cli -- run -- pnpm add some-new-package@latest`
3. CLI parses command → extracts `some-new-package`, `latest`, `pnpm`
4. CLI sends to `POST /v1/decide`
5. Server checks npm registry (publish age < 30 min → WARN)
6. Server checks OSV (no advisory → ALLOW with note)
7. Verdict returned: `WARN, risk_score=45`
8. CLI prints formatted output
9. If user confirms, command executes

---

## What's NOT in Phase 1

- No MCP server
- No dashboard
- No GitHub Action
- No auth/API keys
- No pre-ingested intelligence graph
- No hosted/cloud deployment
- No PR review
- No code analysis

Phase 1 proves the core loop only.

---

## Spec Self-Review

- All "TBD" resolved? YES — no placeholders
- Consistent naming? YES — kairo-core, kairo-server, kairo-cli throughout
- Architecture matches PRD intent? YES
- Scope appropriate for V1? YES — minimal viable demo
- Ambiguity resolved? YES — local-only, no auth, no cloud branding
