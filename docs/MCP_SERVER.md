# Kairo MCP Server

A stdio-based Model Context Protocol (MCP) server that exposes Kairo's security risk assessment capabilities to AI coding agents.

## Overview

The Kairo MCP server enables AI coding agents (Claude Code, Cursor, etc.) to check packages and terminal commands for security risks before installing or executing them. It communicates over stdio using JSON-RPC 2.0.

## Prerequisites

- Rust 1.70+
- Kairo server running at `http://127.0.0.1:8080`

## Building

```bash
cargo build -p kairo-mcp
```

The binary will be at `target/debug/kairo-mcp` (or `target/release/kairo-mcp` with `--release`).

## Running

Start the Kairo server first, then run the MCP server:

```bash
# In one terminal, start kairo-server
./start.sh

# In another terminal, run the MCP server
./target/debug/kairo-mcp
```

The server reads JSON-RPC requests from stdin and writes responses to stdout.

## Tools

The MCP server exposes 4 tools:

### kairo.check_package

Check a package for security risks before installing.

**Parameters:**
- `ecosystem` (string): Package ecosystem (`npm`, `pnpm`, `yarn`, `bun`, `pip`, `cargo`, `go`, `docker`). Default: `npm`.
- `package` (string): Package name.
- `version` (string): Package version. Default: `latest`.

**Example:**
```json
{
  "name": "kairo.check_package",
  "arguments": {
    "ecosystem": "npm",
    "package": "lodash",
    "version": "4.17.21"
  }
}
```

### kairo.check_command

Check a terminal command for risk before running.

**Parameters:**
- `command` (string): Full command to check (e.g., `pnpm add lodash@4`).

**Example:**
```json
{
  "name": "kairo.check_command",
  "arguments": {
    "command": "pip install requests==2.28.0"
  }
}
```

### kairo.get_safe_version

Get a recommended safe version for a package. Returns a version that is:
- At least 30 days old
- Has no CRITICAL/HIGH OSV advisories

**Parameters:**
- `ecosystem` (string): Package ecosystem (`npm`, `pnpm`, `yarn`, `bun`, `pip`, `cargo`).
- `package` (string): Package name.

**Example:**
```json
{
  "name": "kairo.get_safe_version",
  "arguments": {
    "ecosystem": "npm",
    "package": "express"
  }
}
```

### kairo.explain_verdict

Get a human-readable explanation of a Kairo verdict.

**Parameters:**
- `verdict` (string): Verdict type (`Block`, `Warn`, `Allow`).
- `risk_score` (integer): Risk score (0-100).
- `title` (string): Verdict title.
- `summary` (string): Verdict summary.
- `recommended_action` (string, optional): Recommended action.
- `evidence` (array, optional): Array of evidence objects with `type`, `source`, and `detail`.

**Example:**
```json
{
  "name": "kairo.explain_verdict",
  "arguments": {
    "verdict": "Block",
    "risk_score": 95,
    "title": "Known malicious package",
    "summary": "This package is on the Kairo block list"
  }
}
```

## JSON-RPC Protocol

The server implements the MCP protocol with these methods:

### initialize

Returns server capabilities and protocol version.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": { "tools": {} },
    "serverInfo": { "name": "kairo", "version": "0.1.0" }
  }
}
```

### tools/list

Returns available tools.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

### tools/call

Call a tool by name with arguments.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "kairo.check_package",
    "arguments": {
      "ecosystem": "npm",
      "package": "lodash",
      "version": "4.17.21"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\n  \"verdict\": \"Allow\",\n  \"risk_score\": 15,\n  ...\n}"
    }]
  }
}
```

### ping

Health check.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "ping",
  "params": {}
}
```

## AI Agent Configuration

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "kairo": {
      "command": "cargo",
      "args": ["run", "--package", "kairo-mcp"],
      "cwd": "/path/to/kairo"
    }
  }
}
```

Or with the built binary:

```json
{
  "mcpServers": {
    "kairo": {
      "command": "/path/to/kairo/target/release/kairo-mcp"
    }
  }
}
```

### Cursor

Add to Cursor settings (Settings > AI > MCP Servers):

```json
{
  "mcpServers": {
    "kairo": {
      "command": "cargo",
      "args": ["run", "--package", "kairo-mcp"],
      "cwd": "/path/to/kairo"
    }
  }
}
```

### Other MCP-Compatible Agents

Most MCP-compatible agents follow the same pattern. Use the command that launches the server:

```bash
# Option 1: Run with cargo
cargo run --package kairo-mcp

# Option 2: Run the pre-built binary
./target/release/kairo-mcp
```

## Verdict Response Format

The `kairo.check_package` and `kairo.check_command` tools return a JSON verdict:

```json
{
  "verdict": "Allow|Warn|Block",
  "risk_score": 0-100,
  "title": "Brief title",
  "summary": "Description of the verdict",
  "recommended_action": "What to do next",
  "evidence": [
    {
      "type": "osv_advisory|typosquat|block_rule|...",
      "source": "OSV|Kairo Blocklist|...",
      "detail": "Specific details"
    }
  ]
}
```

### Risk Levels

- **0-30 (LOW)**: Minimal threat indicators
- **31-60 (MEDIUM)**: Some concerns detected
- **61-85 (HIGH)**: Significant threat indicators
- **86-100 (CRITICAL)**: Immediate danger

### Verdict Types

- **Block**: Package/command is dangerous and should NOT be installed or executed
- **Warn**: Package/command has risk factors that should be reviewed
- **Allow**: Package/command appears safe based on available data

## Example Workflow

1. AI agent receives task: "Install the express package"
2. Agent calls `kairo.check_package` with `ecosystem: "npm"`, `package: "express"`
3. MCP server queries kairo-server at `http://127.0.0.1:8080/v1/decide`
4. Returns verdict to agent
5. If `Block`: agent informs user and refuses to install
6. If `Warn`: agent warns user and asks for confirmation
7. If `Allow`: agent proceeds with installation
