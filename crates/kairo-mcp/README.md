# kairo-mcp

MCP server exposing Kairo risk intelligence to AI coding agents.

## Overview

kairo-mcp is a Model Context Protocol server that exposes Kairo's security risk assessment capabilities to AI tools like Cursor and Claude Code. AI agents can call Kairo tools before taking actions like installing packages or running terminal commands.

## Tools

- `kairo.check_package` — Check a package for security risks before installing
- `kairo.check_command` — Check a terminal command for risk before running
- `kairo.get_safe_version` — Get a recommended safe version for a package
- `kairo.explain_verdict` — Get a human-readable explanation of a verdict

## Usage

The MCP server communicates over stdio. Configure your AI tool to connect to it:

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

## Requirements

- Kairo server running at `http://127.0.0.1:8080`
- Rust 1.70+
