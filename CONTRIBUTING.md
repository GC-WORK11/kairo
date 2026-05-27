# Contributing to Kairo

## Getting Started

1. Clone the repo
2. `cargo build --workspace` to verify everything compiles
3. `cargo test --workspace` to run all tests

## Project Structure

```
kairo/
├── crates/
│   ├── kairo-core/           # Decision engine — pure logic, rule evaluation
│   ├── kairo-server/         # HTTP server for decision API
│   ├── kairo-cli/            # CLI client
│   ├── kairo-mcp/            # MCP server (stdio transport)
│   ├── kairo-github-action/  # GitHub Action with local-check mode
│   └── kairo-ingest/         # Intelligence sources and ingestion
└── apps/
    └── web/                  # Web dashboard (Bun + TypeScript)
```

## Crates

| Crate | Purpose |
|-------|---------|
| `kairo-core` | Decision engine — add decision rules here |
| `kairo-server` | HTTP server on `127.0.0.1:8080` |
| `kairo-cli` | CLI client for the decision server |
| `kairo-mcp` | MCP server via stdio |
| `kairo-github-action` | GitHub Action with local-check mode |
| `kairo-ingest` | Intelligence sources (add new sources here) |

## Building and Testing

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Lint (must pass — no warnings allowed)
cargo clippy --workspace
```

## Running the Decision Server

```bash
cargo run -p kairo-server
# Server listens on 127.0.0.1:8080
```

## Running the Web Dashboard

```bash
cd apps/web
bun install
bun run dev
```

## Code Style

- `cargo fmt` before committing
- `cargo clippy --workspace` must pass with zero warnings
- Tests required for all new decision rules

## Adding a New Decision Rule

1. Add rule to `kairo-core/src/decision.rs` in the `decide()` function
2. Add test cases in the test module
3. Rules are evaluated in order — order matters

## Adding a New Intelligence Source

1. Add source module to `kairo-ingest/src/sources/`
2. Implement `IntelligenceSource` trait
3. Add parallel fetch in `fetch_intelligence()`
4. Add tests

## Auth Layer

Auth is optional and disabled by default. Enable it via configuration if needed.

## Commit Messages

Use conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `test:` test additions
- `docs:` documentation
- `refactor:` code restructure

## Pull Requests

- Run all tests: `cargo test --workspace`
- Run linting: `cargo clippy --workspace`
- PR description should explain WHAT changed and WHY
