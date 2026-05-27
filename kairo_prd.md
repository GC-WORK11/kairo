# Kairo PRD

**Product Name:** Kairo  
**Category:** Cloud intelligence layer for AI coding agents  
**Document Version:** PRD v1  
**Primary Users:** Developers and teams using Cursor, Codex, Claude Code, GitHub Copilot, Windsurf, terminal agents, or CI/CD automation  
**Core Promise:** Give AI coding agents fresh, real-time software intelligence before they run risky actions.

---

## 1. Plain-English Summary

### What is Kairo?

**Kairo is a real-time cloud intelligence API for AI coding agents.**

When an AI coding agent tries to install a package, edit CI/CD, run a migration, touch infrastructure, use stale docs, or execute a risky terminal command, Kairo checks live internet and software-supply-chain data and returns a decision:

```txt
ALLOW
WARN
BLOCK
REWRITE
ASK HUMAN
```

Kairo is not another AI coding tool.

It does not replace Cursor, Codex, Claude Code, Copilot, or Windsurf.

It sits beside them as a **freshness and risk intelligence layer**.

The simple idea:

> Coding agents are fast. Kairo makes them aware of what is dangerous today.

---

## 2. The Problem

AI coding agents can now do real work:

```txt
write code
edit files
install packages
run terminal commands
change CI/CD workflows
modify infrastructure
create database migrations
deploy apps
```

But these agents have a weakness:

> They may not know what changed on the internet five minutes ago.

Examples:

```txt
A package was compromised today.
A maintainer account was hijacked.
A new package version was published with a malicious postinstall script.
A framework changed its recommended API last week.
A GitHub Actions pattern became known-dangerous.
A package was deprecated yesterday.
A Docker image received a critical vulnerability.
A migration command can wipe the database.
```

The model may still confidently continue.

That creates a new category of developer risk:

> Agentic software risk.

Not just vulnerable code.  
Not just bad dependencies.  
But **AI agents taking unsafe actions with stale context**.

---

## 3. Kairo’s Purpose

Kairo exists to answer one question:

> **Should this AI coding agent be allowed to do this action right now?**

Not:

```txt
Is the code beautiful?
Can we generate better code?
Can we review this PR?
Can we replace Cursor?
```

Kairo’s job is action judgment.

Examples:

```txt
Should the agent install this npm package?
Should the agent use latest?
Should the agent run this migration?
Should the agent edit this GitHub Actions file?
Should the agent run this Docker image?
Should the agent execute this shell command?
Should the agent use this outdated framework API?
Should the agent touch production configuration?
```

Kairo gives the answer using live cloud intelligence.

---

## 4. What Kairo Is

Kairo is:

```txt
A cloud-first intelligence layer.
A real-time decision API.
A supply-chain risk graph.
A package freshness engine.
A command-risk evaluator.
A coding-agent safety companion.
A source of fresh software context for agents.
A bridge between AI coding tools and live internet/software intelligence.
```

Kairo integrates through:

```txt
MCP
CLI adapter
terminal command shim
Claude Code hook
Codex-compatible wrapper
VS Code/Cursor extension
GitHub Action
CI/CD check
```

---

## 5. What Kairo Is Not

Kairo is **not**:

```txt
Not an AI coding editor.
Not a Cursor competitor.
Not a Claude Code competitor.
Not a Codex competitor.
Not a CodeRabbit clone.
Not a normal PR review bot.
Not just an SCA scanner.
Not just a CVE lookup tool.
Not a local LLM.
Not an offline product.
Not a general chatbot.
Not a replacement for GitHub security tools.
Not a full DevSecOps platform at MVP.
```

Most importantly:

```txt
Kairo will never support local models as a core feature.
```

Why?

Because the product needs:

```txt
fresh internet data
fast advisory ingestion
live package-registry monitoring
cloud risk graph
multi-source correlation
model routing
global cache
high-speed API responses
```

A local model cannot provide that reliably.

---

## 6. Core Product Positioning

### Short positioning

```txt
Kairo is live internet intelligence for AI coding agents.
```

### Stronger positioning

```txt
Kairo checks agentic coding actions against real-time software risk before they execute.
```

### Developer-facing tagline

```txt
Let agents code. Kairo tells them what changed today.
```

### Enterprise-facing tagline

```txt
Real-time action intelligence for AI-powered software development.
```

### Brutal one-liner

```txt
Kairo stops stale AI agents from making fresh production mistakes.
```

---

## 7. Why Now?

The timing is strong because agentic coding tools are becoming action engines.

They do not just suggest code. They run workflows.

Current tools already provide execution surfaces:

```txt
Cursor has MCP support.
Claude Code has hooks.
Codex has sandboxing and approvals.
GitHub Copilot supports MCP integrations.
```

This means Kairo does not need to invent a new coding agent.

Kairo attaches to the ecosystem that already exists.

---

## 8. Core User Personas

### Persona 1: Solo AI Power Developer

Uses:

```txt
Cursor
Claude Code
Codex CLI
pnpm
npm
bun
GitHub
Vercel
Supabase
Railway
```

Pain:

```txt
Moves fast with agents but worries the agent may install random packages, use wrong docs, or break infra.
```

Needs:

```txt
Fast warnings.
Simple CLI.
No heavy dashboard.
No enterprise setup.
```

---

### Persona 2: Startup Engineering Team

Uses:

```txt
Cursor
Copilot
GitHub Actions
Docker
Terraform
Postgres
Kubernetes
```

Pain:

```txt
Many engineers are using agents. Security team cannot manually watch every AI-generated change.
```

Needs:

```txt
Team policy.
CI gate.
Audit trail.
Package risk alerts.
Agent action logs.
```

---

### Persona 3: Security-Conscious Engineering Lead

Pain:

```txt
AI tools are being adopted faster than security controls.
```

Needs:

```txt
Visibility into agent actions.
Block dangerous actions.
Require approvals for infra and database commands.
Enforce package policies.
```

---

### Persona 4: Open-Source Maintainer

Pain:

```txt
Users install fresh package versions immediately after release, even during incident windows.
```

Needs:

```txt
Package reputation signals.
Incident warnings.
Safe-version recommendations.
```

---

## 9. Core Use Cases

### Use Case 1: AI Agent Tries to Install a Risky Package

Agent runs:

```bash
pnpm add some-package@latest
```

Kairo checks:

```txt
package age
registry metadata
install scripts
known advisories
provenance
maintainer changes
similar package names
recent security chatter
```

Kairo returns:

```txt
WARN: latest version is 14 minutes old and includes postinstall script.
Recommended: pin previous stable version.
```

---

### Use Case 2: AI Agent Tries to Install a Compromised Package Version

Agent runs:

```bash
npm install package@bad-version
```

Kairo returns:

```txt
BLOCK: this package/version is linked to a known active advisory.
```

---

### Use Case 3: AI Agent Edits GitHub Actions Dangerously

Agent creates:

```yaml
on:
  pull_request_target:
```

with high permissions and untrusted checkout.

Kairo returns:

```txt
BLOCK: dangerous CI pattern. This can expose secrets to untrusted pull requests.
```

---

### Use Case 4: AI Agent Runs Database-Destructive Command

Agent runs:

```bash
prisma migrate reset --force
```

Kairo checks repo context and environment names.

Kairo returns:

```txt
BLOCK: destructive database reset command. Human approval required.
```

---

### Use Case 5: AI Agent Uses Stale Docs

Agent proposes an old framework or library pattern.

Kairo checks current docs, changelogs, known deprecations, and framework release notes.

Kairo returns:

```txt
WARN: this API pattern is deprecated. Use the current recommended API.
```

---

### Use Case 6: AI Agent Runs Unknown `npx`

Agent runs:

```bash
npx random-cli
```

Kairo returns:

```txt
WARN or BLOCK: unknown executable package, recent publish, lifecycle script present, low reputation.
```

---

### Use Case 7: Team Policy Enforcement

Company policy:

```txt
Do not allow latest installs in production repos.
Do not allow packages younger than 24 hours.
Do not allow missing provenance for critical packages.
Do not allow AI agents to edit infra without review.
Do not allow destructive database commands.
```

Kairo enforces that in CLI, IDE, MCP, and CI.

---

## 10. Core Product Capabilities

### 10.1 Action Decision API

This is the heart of Kairo.

Endpoint:

```http
POST /v1/decide
```

Input:

```json
{
  "action_type": "package_install",
  "tool": "cursor",
  "ecosystem": "npm",
  "command": "pnpm add @tanstack/react-router",
  "package": "@tanstack/react-router",
  "version": "latest",
  "repo_context": {
    "framework": "nextjs",
    "has_database": true,
    "has_ci": true
  }
}
```

Output:

```json
{
  "verdict": "warn",
  "risk_score": 78,
  "title": "Fresh high-risk package install",
  "summary": "The selected version is very recent and includes lifecycle scripts.",
  "recommended_action": "Pin a known stable version or wait for confidence window.",
  "safe_command": "pnpm add @tanstack/react-router@known-safe-version",
  "evidence": [
    {
      "type": "registry_metadata",
      "source": "npm"
    },
    {
      "type": "advisory",
      "source": "osv"
    }
  ]
}
```

Verdict types:

```txt
ALLOW
WARN
BLOCK
REWRITE
ASK_HUMAN
```

---

### 10.2 Package Intelligence

Kairo should understand packages deeply.

For npm, PyPI, crates.io, Go, Maven, Docker, and GitHub Actions, Kairo should know:

```txt
latest version
publish age
maintainer metadata
known advisories
provenance status
registry signatures
dependency graph
install scripts
binary blobs
obfuscated files
suspicious new files
typosquat similarity
download anomalies
yanked/deprecated status
recent incident mentions
```

---

### 10.3 Fresh Internet Intelligence

Kairo should continuously watch:

```txt
security advisories
vendor blogs
package registry events
GitHub issues
GitHub releases
changelogs
Hacker News
Reddit developer/security communities
framework docs
maintainer announcements
package deprecations
incident postmortems
```

This is where Kairo becomes more than OSV or GitHub Advisories.

Kairo should detect weak signals before they become clean CVEs.

Examples:

```txt
maintainer says do not install version X
package was yanked
GitHub issues exploding after release
security researcher posted exploit notes
framework release broke previous API
Docker image was rebuilt with vulnerable base
```

---

### 10.4 Command Risk Engine

Kairo should classify terminal commands.

Categories:

```txt
safe
network
package install
script execution
filesystem destructive
database destructive
infra destructive
secret access
deployment
container execution
CI/CD mutation
```

Example risky commands:

```bash
rm -rf
sudo
curl | bash
npx unknown-cli
npm install latest
pip install unknown
docker run --privileged
kubectl apply
terraform apply
prisma migrate reset
psql DROP DATABASE
gh secret list
```

Kairo does not block everything.

It checks context.

Example:

```txt
rm -rf node_modules = usually okay
rm -rf / = block
prisma migrate dev on local db = warn
prisma migrate reset with production-looking env = block
```

---

### 10.5 CI/CD Risk Engine

Kairo should analyze:

```txt
.github/workflows/*
GitLab CI
CircleCI
Dockerfiles
Terraform
Kubernetes YAML
Vercel config
Netlify config
Railway config
```

High-risk patterns:

```txt
pull_request_target with unsafe checkout
broad GitHub token permissions
secrets exposed to PRs
curl | bash in CI
untrusted third-party actions
unpinned GitHub Actions
Docker privileged mode
deployment on untrusted branch
```

---

### 10.6 Docs Freshness Engine

Kairo should help agents avoid stale APIs.

Inputs:

```txt
framework name
current project version
agent’s proposed code
docs/changelog/release notes
```

Output:

```txt
This pattern is current.
This pattern is deprecated.
This API changed in version X.
Use this newer pattern instead.
```

MVP should support:

```txt
Next.js
React
TypeScript
Prisma
TanStack
Vite
Supabase
Tailwind
Node.js
Python FastAPI
```

---

### 10.7 MCP Server

Kairo should expose MCP tools:

```txt
kairo.check_package
kairo.check_command
kairo.check_diff
kairo.check_ci_change
kairo.check_migration
kairo.get_safe_version
kairo.search_current_docs
kairo.explain_verdict
```

This allows tools like Cursor and Claude Code to ask Kairo before acting.

---

### 10.8 CLI Adapter

Command examples:

```bash
kairo check "pnpm add zod"
kairo run -- pnpm add zod
kairo check-package npm zod latest
kairo check-diff
kairo doctor
kairo login
kairo init
```

The CLI does not think locally.

It sends metadata to Kairo Cloud.

---

### 10.9 IDE Extension

Supports:

```txt
VS Code
Cursor
possibly Windsurf and VS Code forks
```

Features:

```txt
package.json inline warnings
lockfile risk warnings
CI workflow warnings
migration warnings
ask Kairo command
blocked action history
repo risk summary
```

---

### 10.10 GitHub Action

Example:

```yaml
name: Kairo Check

on:
  pull_request:

jobs:
  kairo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kairo/check@v1
        with:
          policy: strict
```

Checks:

```txt
dependency diff
lockfile diff
CI/CD diff
Docker diff
infrastructure diff
migration diff
```

---

## 11. Competitive Landscape

### Current Coding Tools

| Tool | What it does | Kairo’s relationship |
|---|---|---|
| Cursor | AI coding editor with agent features and MCP | Kairo feeds it live risk intelligence |
| Claude Code | Agentic coding tool with hooks and command execution | Kairo plugs into hooks and MCP |
| Codex | Agentic coding with sandboxing/approvals | Kairo adds live risk judgment |
| GitHub Copilot | AI coding assistant with MCP integrations | Kairo can expose MCP tools and CI checks |
| Windsurf | AI coding IDE | Kairo can support through extension/CLI surfaces |

Kairo should not compete with these tools.

Kairo should become the intelligence layer they need.

---

### Current Security Tools

| Category | Examples | Difference |
|---|---|---|
| SCA | Snyk, Dependabot, Endor, Socket | Kairo focuses on agent action-time decisions |
| SAST | Semgrep, CodeQL | Kairo is not primarily static code scanning |
| PR review | CodeRabbit, Greptile-style tools | Kairo acts before execution, not only after PR |
| CI security | GitHub Advanced Security, security scanners | Kairo is optimized for AI-generated actions |
| Secrets scanning | Gitleaks, GitHub secret scanning | Kairo may integrate, but not core MVP |

Kairo’s core differentiation:

```txt
Traditional tools ask:
“Is this repo vulnerable?”

Kairo asks:
“Should this agent do this action right now?”
```

---

## 12. Product Architecture

```txt
AI Coding Tool
Cursor / Codex / Claude Code / Copilot / Windsurf / Terminal Agent
        |
        | MCP / CLI / hook / extension / CI
        v
Kairo Adapter
Tiny installed bridge. No local model.
        |
        | action payload
        v
Kairo Cloud API
Low-latency decision endpoint
        |
        v
Decision Engine
Rules + graph lookup + model reasoning
        |
        v
Kairo Intelligence Graph
Packages / advisories / docs / incidents / registry metadata
        |
        v
Verdict
ALLOW / WARN / BLOCK / REWRITE / ASK HUMAN
```

Separate ingestion system:

```txt
Registries + advisories + web + docs + changelogs
        |
        v
Ingestion workers
        |
        v
Normalization
        |
        v
Artifact analysis
        |
        v
Risk graph
        |
        v
Edge cache
```

---

## 13. Technical Stack

### 13.1 Client Adapter

Use:

```txt
Rust
```

Why:

```txt
fast startup
single binary
cross-platform
low memory
secure systems language
good for CLI tools
good for command wrapping
good for macOS/Linux/Windows distribution
```

Libraries:

```txt
clap                 CLI
tokio                async runtime
reqwest              HTTP client
serde                JSON
tracing              logging
miette               beautiful errors
notify               file watching
git2                 git diff/context
tree-sitter          code parsing
ignore/globset       repo traversal
rustls               TLS
```

Output binaries:

```txt
kairo-darwin-arm64
kairo-darwin-x64
kairo-linux-x64
kairo-linux-arm64
kairo-windows-x64.exe
```

Important:

```txt
The Rust binary is not the intelligence engine.
It is only the bridge to Kairo Cloud.
```

---

### 13.2 Cloud API

Recommended:

```txt
Rust + Axum
```

Why:

```txt
high performance
type safety
shared models with CLI
good concurrency
fits security-sensitive infra
```

Cloud API services:

```txt
Decision API
Auth API
Policy API
Org API
Billing API
Event API
MCP API
```

Core endpoints:

```txt
POST /v1/decide
POST /v1/package/check
POST /v1/command/check
POST /v1/diff/check
POST /v1/docs/check
GET  /v1/verdict/:id
GET  /v1/package/:ecosystem/:name
```

---

### 13.3 Data Infrastructure

Use:

```txt
PostgreSQL
ClickHouse
Redis or Dragonfly
S3/R2 object storage
NATS JetStream or Redpanda
Qdrant or pgvector
```

Purpose:

```txt
PostgreSQL      users, orgs, policies, billing, metadata
ClickHouse      events, telemetry, action logs, analytics
Redis/Dragonfly hot cache for verdicts and package lookups
S3/R2           package artifacts, snapshots, crawled docs
NATS/Redpanda   ingestion event pipeline
Qdrant/pgvector semantic search over docs/incidents/changelogs
```

---

### 13.4 Intelligence Sources

Start with:

```txt
OSV
GitHub Security Advisories
deps.dev
npm registry
PyPI
crates.io
Go module proxy
Docker Hub/GHCR metadata
NVD
CISA KEV
OpenSSF Scorecard
package changelogs
GitHub issues/releases
official framework docs
security blogs
```

---

### 13.5 Web Intelligence

Use:

```txt
Exa
Tavily
Firecrawl
Jina Reader
GitHub Search API
custom crawlers
RSS feeds
```

Goal:

```txt
Find fresh incidents before they are cleanly represented in CVE/advisory databases.
```

---

### 13.6 AI Model Layer

Use a model router.

Do not make one model the product.

Model usage:

```txt
Fast deterministic rules for obvious cases.
Small classifier for cheap triage.
Frontier model for ambiguous reasoning.
Long-context model for big diffs/docs.
```

Recommended model strategy:

```txt
GPT-5.5 for deep coding/security reasoning
Claude for long-context code/diff analysis
Gemini for huge-context extraction and docs
small internal model later for cheap classification
```

Important rule:

```txt
LLM is not the source of truth.
The Kairo Intelligence Graph is the source of truth.
```

The LLM only explains, correlates, and reasons when rules are not enough.

---

### 13.7 AI Gateway / Reliability

Use an AI gateway for:

```txt
provider fallback
rate limits
analytics
request retries
caching
cost control
```

---

### 13.8 Frontend / Dashboard

Use:

```txt
Next.js
TypeScript
Tailwind
shadcn/ui
Framer Motion
TanStack Query
Recharts
```

Dashboard sections:

```txt
Actions
Policies
Packages
Incidents
Repos
Team
Billing
Audit Log
```

Design direction:

```txt
minimal
white/stone/neutral
premium
not cyberpunk
not hacker green
not generic security SaaS
Cursor + Linear + Vercel style
```

---

### 13.9 Desktop App

Do not build desktop app in MVP.

Later:

```txt
Tauri 2 + React + Rust bridge
```

Purpose:

```txt
show active agent sessions
blocked actions
installed adapters
local command settings
```

But MVP should not start here.

---

## 14. Kairo Decision Engine

The decision engine has three layers.

### Layer 1: Deterministic Rules

Fast rules.

Examples:

```txt
Known malicious version = block
Known critical CVE with reachable install = block/warn
Package younger than 30 min + install script = warn/block
Missing provenance for critical package = warn
Destructive DB command + production env = block
CI secret exposure pattern = block
Unpinned GitHub Action in strict policy = warn/block
```

### Layer 2: Intelligence Graph Lookup

Kairo checks:

```txt
package reputation
maintainer history
advisories
package release history
artifact diff
docs freshness
incident mentions
team policy
org allowlist/blocklist
```

### Layer 3: Model Reasoning

Only when needed.

Examples:

```txt
Is this migration destructive?
Is this CI workflow unsafe?
Is this framework API stale?
Is this new package release suspicious compared to the previous version?
Is this command dangerous in this repo context?
```

---

## 15. Risk Scoring

Each decision gets:

```txt
risk_score: 0-100
confidence: 0-1
verdict
reason
evidence
safe alternative
```

Example scoring dimensions:

```txt
Known advisory severity
Exploit maturity
Package publish age
Maintainer reputation
Install-time execution
Artifact anomaly
Provenance/signature status
Repo sensitivity
Command destructiveness
CI secret exposure
Team policy
```

Example:

```txt
0-24      allow
25-49     allow with note
50-74     warn
75-89     strong warn / ask human
90-100    block
```

---

## 16. MVP Scope

### MVP Goal

Build a working Kairo that can:

```txt
catch package installs
check fresh cloud intelligence
warn/block risky installs
integrate with at least one agent workflow
show a viral demo
```

### MVP Must-Have Features

```txt
Cloud Decision API
Rust CLI adapter
npm/pnpm/yarn/bun support
OSV integration
GitHub Advisories integration
npm registry metadata
publish-age detection
install-script detection
basic provenance/signature check
basic MCP server
basic Claude Code hook support
simple web dashboard
```

### MVP Commands

```bash
kairo login
kairo init
kairo check "pnpm add package"
kairo run -- pnpm add package
kairo check-package npm package latest
kairo mcp start
kairo doctor
```

### MVP Verdict Example

```txt
Kairo: WARN

Package: example-package@latest
Reason: latest version was published 18 minutes ago and includes a postinstall script.
Recommendation: pin previous stable version or wait for 24h confidence window.
```

### MVP Viral Demo

```txt
Open Cursor or Claude Code.
Ask agent to install a risky package.
Agent attempts package install.
Kairo intercepts/checks.
Kairo warns or blocks.
Kairo explains with live evidence.
Agent changes plan.
```

---

## 17. V1 Shipping Version

The final shipping V1 should be able to do this:

### Agent Integrations

```txt
Cursor MCP
Claude Code MCP
Claude Code hook
Codex-compatible CLI wrapper
VS Code/Cursor extension
GitHub Action
generic REST API
```

### Package Ecosystems

```txt
npm
pnpm/yarn/bun package flows
PyPI
uv/pip
crates.io
Go modules
Docker images
GitHub Actions
```

### Risk Categories

```txt
package compromise
fresh release risk
malware indicators
deprecated package
stale docs
dangerous shell command
dangerous DB command
dangerous CI/CD change
dangerous Docker config
dangerous infra config
```

### Team Features

```txt
org policies
repo-level policies
allowlist/blocklist
risk threshold controls
audit logs
Slack alerts
GitHub PR comments
billing
API keys
SSO later
```

### Developer UX

```txt
fast CLI
clear explanations
safe command suggestions
minimal false positives
beautiful dashboard
no heavy setup
```

---

## 18. Non-Goals

Do not build these early:

```txt
full code review agent
full SAST scanner
full IDE competitor
local model
offline mode
giant enterprise dashboard
mobile app
autonomous fixing agent
full malware sandbox for every ecosystem
custom package registry
```

Especially:

```txt
No local model support.
No local AI reasoning.
No “works offline” promise.
```

---

## 19. Privacy Model

Since Kairo is cloud-first, privacy must be clear.

Kairo should avoid uploading full source code by default.

Default payload should include:

```txt
command
package name
package version
ecosystem
dependency diff metadata
file path type
framework metadata
policy ID
anonymous repo fingerprint
```

Optional advanced mode:

```txt
send CI diff
send migration diff
send package.json diff
send Dockerfile diff
send selected file snippets
```

Enterprise mode:

```txt
self-hosted control plane later
private cloud deployment later
strict data retention
audit logs
no training on customer code
```

Important wording:

```txt
Kairo is cloud-first, but not reckless with code.
It sends action metadata by default, not entire repos.
```

---

## 20. Pricing

### Free

```txt
single developer
limited checks/month
npm/PyPI checks
CLI
basic MCP
```

### Pro

```txt
$12-$20/month
higher check limits
all ecosystems
fresh docs checks
IDE extension
command history
```

### Team

```txt
$15-$30/user/month
shared policies
GitHub Action
audit logs
Slack alerts
team dashboard
```

### Enterprise

```txt
custom
SSO
custom retention
private deployment
policy controls
priority intelligence
```

---

## 21. Success Metrics

### Developer Metrics

```txt
time to first check < 3 minutes
CLI decision latency < 500ms for cached decisions
CLI decision latency < 2s for normal cloud checks
false positive rate under 5-8% for strict warnings
weekly active developers
checks per developer per week
blocked high-risk actions
```

### Business Metrics

```txt
free-to-pro conversion
team workspace creation
GitHub Action installs
MCP installs
retention after 4 weeks
number of org policies created
```

### Intelligence Metrics

```txt
time from advisory publication to Kairo detection
time from package publish to risk score
coverage by ecosystem
incident detection accuracy
safe-version recommendation accuracy
```

---

## 22. Engineering Roadmap

### Week 1-2: Prototype

```txt
Rust CLI
POST /v1/decide
npm package parser
OSV lookup
npm metadata lookup
basic WARN/BLOCK response
```

### Week 3-4: Cloud Core

```txt
Auth
Postgres
Redis cache
package intelligence schema
decision logs
basic dashboard
```

### Week 5-6: Agent Integration

```txt
MCP server
Claude Code hook
Cursor MCP config docs
basic command wrapper
```

### Week 7-8: Intelligence Expansion

```txt
GitHub Advisories
deps.dev
npm provenance/signature checks
install script extraction
publish-age confidence windows
```

### Week 9-10: Public Beta

```txt
landing page
CLI install script
docs
viral demo
GitHub Action
waitlist/pro accounts
```

---

## 23. Suggested Repo Structure

```txt
kairo/
  apps/
    web/                 Next.js dashboard
    docs/                Documentation site
  crates/
    kairo-cli/           Rust CLI
    kairo-core/          shared Rust types
    kairo-adapter/       command parsing/context extraction
    kairo-mcp/           MCP bridge
  services/
    api/                 Rust Axum API
    ingest/              ingestion workers
    decision/            decision engine
    analyzer/            artifact analyzer
  packages/
    vscode-extension/    TypeScript extension
    github-action/       GitHub Action
  infra/
    terraform/
    docker/
  docs/
    prd.md
    architecture.md
    api.md
```

---

## 24. External Reference Sources To Verify During Build

These are useful sources for engineering validation and integration planning:

```txt
MCP Specification:
https://modelcontextprotocol.io/

Cursor MCP Docs:
https://cursor.com/docs/mcp

Claude Code Docs:
https://code.claude.com/docs/

OpenAI Codex Docs:
https://developers.openai.com/codex/

OSV:
https://osv.dev/

GitHub Security Advisories API:
https://docs.github.com/en/rest/security-advisories/global-advisories

deps.dev API:
https://docs.deps.dev/api/v3alpha/

npm Provenance:
https://docs.npmjs.com/generating-provenance-statements/

npm Registry Signatures:
https://docs.npmjs.com/about-registry-signatures/

CISA KEV:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

NVD API:
https://nvd.nist.gov/developers

OpenSSF Scorecard:
https://github.com/ossf/scorecard

Exa:
https://exa.ai/

Tavily:
https://www.tavily.com/

Firecrawl:
https://www.firecrawl.dev/

Jina Reader:
https://jina.ai/reader/
```

---

## 25. Final Product Vision

Kairo should become the default live-intelligence layer for agentic development.

The long-term product is:

```txt
Every AI coding agent asks Kairo before doing risky software actions.
```

The future state:

```txt
Cursor wants current package safety → asks Kairo.
Claude Code wants to run command → asks Kairo.
Codex wants to edit infra → asks Kairo.
Copilot wants current docs → asks Kairo.
CI wants dependency diff risk → asks Kairo.
Engineering teams want AI-agent policy → use Kairo.
```

---

## 26. Final Definition

```txt
Kairo is a cloud-first real-time intelligence layer for AI coding agents.

It checks package installs, terminal commands, CI/CD changes, migrations, infrastructure edits, and stale framework usage against live software risk data.

It does not write code.
It does not replace coding agents.
It does not run local models.

It gives agents the one thing they do not reliably have:

fresh judgment at the exact moment of action.
```
