# MCP Sentinel

MCP Sentinel is a static security scanner and runtime helper toolkit for Model Context Protocol (MCP) servers. It highlights risky network or filesystem behaviors, validates your server against a least-privilege policy, and offers lightweight runtime guards for cooperative servers built on FastMCP-style patterns.

## Features
- **Static scanning** for outbound network use, dangerous filesystem access, and basic secrets misuse.
- **Policy-as-code** using YAML and Pydantic models to express allowed domains and filesystem modes per tool.
- **Runtime helpers** like secure HTTP clients and filesystem wrappers to enforce policy at runtime.
- **CLI** suitable for local use and CI pipelines.

## Quick start
```bash
pip install .
# or pip install mcp_sentinel when published
mcp-sentinel mcp-scan .
```

See the `docs/` folder for detailed usage, policy examples, CI snippets, and runtime guidance.
