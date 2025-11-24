# MCP Sentinel Overview

MCP Sentinel is a security toolkit for Model Context Protocol (MCP) servers. It focuses on common risks such as unbounded outbound network calls, unsafe filesystem access, and accidental exposure of secrets. Instead of a heavy sandbox, MCP Sentinel provides static scanning, policy-as-code validation, and lightweight runtime helpers suitable for cooperative FastMCP-style servers.

## Components
- **Scanner**: Parses your MCP server code and flags risky patterns such as HTTP calls to unknown domains, SMTP usage, filesystem writes, and secrets misuse.
- **Policy Engine**: Uses a YAML policy file (`mcp_sentinel.yml`) to describe least-privilege expectations for each tool, including allowed domains and filesystem modes.
- **Runtime Helpers**: Secure HTTP client and filesystem wrapper that enforce policy choices in cooperative servers.
- **CLI**: `mcp-sentinel` command with subcommands for scanning and policy validation.
