# Kairo

[![CI](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/ci.yml)

**Real-time cloud intelligence layer for AI coding agents.**

Kairo intercepts package installs, terminal commands, and CI/CD changes before execution and validates them against live software risk data from OSV, npm registry, GitHub Advisories, and deps.dev.

```
Agent wants to: npm install lodash@4.17.21
Kairo: ALLOW — risk 5

Agent wants to: npm install flatmap-stream@0.1.1
Kairo: BLOCK — risk 95 (known malicious)
```

---

## Quick Start

### 1. Start the Server

```bash
./start.sh
```

Or manually:

```bash
cargo run -p kairo-server
```

Server runs at `http://127.0.0.1:8080`.

### 2. Use the CLI

```bash
# Check a package
kairo check "npm install lodash@4.17.21"

# Run a command after risk check
kairo run -- npm install express

# Show configuration and connectivity status
kairo doctor
```

### 3. Run the MCP Server

```bash
cargo run -p kairo-mcp
```

### 4. Run the Web Dashboard

```bash
cd apps/web && bun install && bun run dev
```

---

## CLI Commands

The `kairo` CLI provides comprehensive package and command risk analysis.

### Check a Command

```bash
kairo check "pnpm add lodash@4.17.21"
kairo check "npm install express@4.18.0"
kairo check "cargo add tokio"
```

### Run a Command with Risk Check

```bash
kairo run -- npm install express
# Prompts for confirmation on WARN, blocks on BLOCK
```

### Check a Specific Package

```bash
kairo check-package npm lodash 4.17.21
kairo check-package pnpm express 4.18.0
kairo check-package cargo tokio --ecosystem cargo
```

### Check Docker Images

```bash
kairo docker scan node:18-alpine
kairo docker scan nginx:latest
```

### Scan Project Dependencies

```bash
kairo scan ./my-project
```

### Scan Git Changes (Pre-commit)

```bash
# Scan staged changes
kairo git-scan

# Scan unstaged changes
kairo git-scan --unstaged
```

### Blocklist Management

```bash
# Show current block list
kairo blocklist list

# Add a package to block list
kairo blocklist add evil-package

# Remove from block list
kairo blocklist remove evil-package

# Check if package is blocked
kairo blocklist check some-package
```

### Trust Management

```bash
# List trusted packages
kairo trust list

# Add to trust list (bypass warnings, but not hard blocks)
kairo trust add lodash

# Remove from trust list
kairo trust remove lodash
```

### Shell Completions

```bash
kairo completions bash > /etc/bash_completion.d/kairo
kairo completions zsh > /usr/local/share/zsh/site-functions/_kairo
```

### Daemon Mode

```bash
kairo daemon
```

### Version Info

```bash
kairo version
kairo version --check  # Check for updates
```

### Doctor (Diagnostics)

```bash
kairo doctor
```

### Supported Ecosystems

npm, pnpm, yarn, bun, pip, cargo, go, docker

---

## MCP Tools

The Kairo MCP server exposes 13 tools via stdio JSON-RPC:

| Tool | Description |
|------|-------------|
| `kairo.check_package` | Check a package for security risks before installing |
| `kairo.check_batch` | Check multiple packages for security risks at once |
| `kairo.check_command` | Check a terminal command for risk before running |
| `kairo.get_safe_version` | Get a recommended safe version for a package |
| `kairo.explain_verdict` | Get a human-readable explanation of a Kairo verdict |
| `kairo.search_packages` | Search for packages by name across npm, PyPI, and crates.io |
| `kairo.doctor` | Run comprehensive diagnostics on the Kairo MCP server |
| `kairo.health` | Check if the Kairo server is reachable and healthy |
| `kairo.trust_list` | List all trusted packages |
| `kairo.trust_add` | Add a package to the trust store |
| `kairo.blocklist_list` | List all blocked packages |
| `kairo.blocklist_add` | Add a package to the local blocklist |
| `kairo.blocklist_check` | Check if a package is on any block list |

---

## Decision Rules

| # | Rule | Severity |
|---|------|----------|
| 1 | Block known malicious packages (event-stream-flat, flatmap-stream, etc.) | BLOCK (risk 95-100) |
| 2 | Block packages published < 5 min ago | BLOCK (risk 85) |
| 3 | Warn if package published < 30 min ago | WARN (risk 55) |
| 4 | Warn on lifecycle scripts (postinstall, install, prepare) | WARN |
| 5 | Block on CRITICAL/HIGH OSV advisories, warn on MEDIUM/LOW | BLOCK/WARN |
| 6 | Warn on critical packages without npm provenance | WARN |

---

## Verdict Reference

| Verdict | Risk Score | Behavior |
|---------|------------|----------|
| ALLOW | 0-49 | Executes immediately |
| WARN | 50-89 | Prompts for confirmation |
| BLOCK | 90-100 | Blocks without executing |

---

## Environment Variables

### kairo-server

| Variable | Default | Description |
|----------|---------|-------------|
| `KAIR0_HOST` | `127.0.0.1` | Server bind address |
| `KAIR0_PORT` | `8080` | Server port |
| `KAIR0_AUTH_ENABLED` | `false` | Enable API key authentication |
| `KAIR0_ADMIN_KEYS` | (none) | Comma-separated admin API keys |
| `KAIR0_RATE_LIMIT` | `100` | Max requests per minute |
| `KAIR0_LOG_LEVEL` | `info` | Log level: trace, debug, info, warn, error |
| `KAIR0_LOG_JSON` | `false` | Enable JSON logging format |

### kairo-mcp

| Variable | Default | Description |
|----------|---------|-------------|
| `KAIR0_API_URL` | `http://127.0.0.1:8080` | Kairo server URL |

### kairo-ingest

| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | (none) | GitHub API token for advisory database access |

---

## Docker & Docker Compose

### Using Docker Compose

```bash
# Start all services
docker-compose up

# Start in background
docker-compose up -d

# Stop services
docker-compose down
```

### Manual Docker Build

```bash
# Build the server image
docker build -t kairo-server .

# Run the server
docker run -p 8080:8080 kairo-server
```

### Environment Variables for Docker

| Variable | Default | Description |
|----------|---------|-------------|
| `KAIRO_PORT` | `8080` | Server port |
| `KAIRO_LOG_LEVEL` | `info` | Log level |
| `KAIRO_DATABASE_URL` | `sqlite::memory:` | Database connection string |

### Docker Compose Services

- **kairo-server** — Decision server on port 8080
- **kairo-web** — Dashboard on port 3000

---

## Architecture

```
kairo/
├── crates/
│   ├── kairo-core/           # Decision engine + types (pure Rust, no I/O)
│   ├── kairo-server/         # Axum HTTP server (127.0.0.1:8080)
│   ├── kairo-cli/            # CLI with check, check-package, run, doctor
│   ├── kairo-mcp/            # MCP server (stdio JSON-RPC, 13 tools)
│   ├── kairo-github-action/  # GitHub Action for PR comments + commit status
│   └── kairo-ingest/         # Intelligence ingestion from OSV, npm, GHSA, deps.dev
└── apps/
    └── web/                  # Dashboard (Next.js + bun)
```

**Decision flow:**

```
CLI / MCP / GitHub Action
        │
        ▼
POST /v1/decide { action }
        │
        ▼
kairo-server
  ├─ fetch OSV advisories
  ├─ fetch npm registry metadata
  └─ kairo-core (pure decision)
        │
        ▼
Verdict: ALLOW / WARN / BLOCK
```

---

## API

### POST /v1/decide

Evaluate an action and get a risk verdict.

```bash
curl -X POST http://127.0.0.1:8080/v1/decide \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "PackageInstall",
    "ecosystem": "npm",
    "command": "npm install lodash@4.17.21",
    "package": "lodash",
    "version": "4.17.21",
    "repo_context": {
      "framework": null,
      "has_database": false,
      "has_ci": false
    }
  }'
```

**Response:**

```json
{
  "verdict": "ALLOW",
  "risk_score": 5,
  "title": "Low risk package",
  "summary": "Package is well-established with no known vulnerabilities.",
  "recommended_action": "Safe to install"
}
```

### GET /health

Health check endpoint.

---

## Crates

### kairo-core

Pure Rust decision engine. No network, no I/O — deterministic rules only.

- `Action` — describes what an agent wants to do
- `Verdict` — the risk decision with score and explanation
- `decide()` — pure function that evaluates risk

### kairo-server

Axum HTTP server on `127.0.0.1:8080`. Fetches intelligence from external sources and runs decisions through kairo-core.

- `GET /health` — health check
- `POST /v1/decide` — evaluate an action

### kairo-cli

Developer CLI with subcommands:

| Command | Description |
|---------|-------------|
| `check` | Parse a command and check risk without executing |
| `run` | Check risk, then execute (prompt on WARN) |
| `check-package` | Check a specific package version |
| `doctor` | Show CLI configuration and connectivity status |
| `scan` | Scan a project directory for risky dependencies |
| `docker scan` | Scan Docker images for security issues |
| `git-scan` | Scan packages changed in git (for pre-commit) |
| `blocklist` | Manage local block list |
| `trust` | Manage trusted packages |
| `completions` | Generate shell completion scripts |
| `daemon` | Start daemon mode for live security scanning |
| `update` | Check for available updates |
| `version` | Show version information |

### kairo-mcp

Model Context Protocol server exposing 13 tools:

| Tool | Description |
|------|-------------|
| `kairo.check_package` | Check a package by ecosystem, name, version |
| `kairo.check_batch` | Check multiple packages at once |
| `kairo.check_command` | Check a full command string |
| `kairo.get_safe_version` | Get a safe version recommendation |
| `kairo.explain_verdict` | Explain a previous verdict decision |
| `kairo.search_packages` | Search packages across registries |
| `kairo.doctor` | Run diagnostics |
| `kairo.health` | Check server health |
| `kairo.trust_list` | List trusted packages |
| `kairo.trust_add` | Add to trust store |
| `kairo.blocklist_list` | List blocked packages |
| `kairo.blocklist_add` | Add to blocklist |
| `kairo.blocklist_check` | Check blocklist status |

### kairo-ingest

Background intelligence pipeline. Sources:
- **OSV.dev** — vulnerability advisories
- **npm Registry** — package freshness and lifecycle scripts
- **GitHub Advisories (GHSA)** — security advisories database
- **deps.dev** — dependency vulnerability data

### kairo-github-action

GitHub Action for PR checks. Posts:
- PR comments with risk analysis
- Commit status (success/failure)

Has a local-check mode for testing without GitHub.

---

## Verified Status

- **26 tests passing**
- **Clippy clean** — no lints
- **Web dashboard builds** successfully
- **E2E verified**:
  - `flatmap-stream` — BLOCKED (risk 95)
  - `lodash` — ALLOW (risk 5)
- **MCP server** — 13 tools operational
- **CLI** — pretty-box output rendering correctly
- **GitHub Action** — local-check mode functional

---

## Development

### Prerequisites

- Rust 1.80+
- Bun (for web dashboard)
- Cargo

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Lint

```bash
cargo clippy --workspace --all-targets
cargo fmt --check
```

---

## License

MIT
