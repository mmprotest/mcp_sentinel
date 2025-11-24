from __future__ import annotations

from pathlib import Path
from typing import List

from .ast_utils import find_python_files, iter_imports, parse_file

MCP_IMPORT_HINTS = {
    "modelcontextprotocol",
    "mcp.server",
    "fastmcp",
    "mcp.server.fastmcp",
}

STARTUP_PATTERNS = {"FastMCP", "mcp.run"}


def is_mcp_project(path: Path) -> bool:
    """Best-effort detection of MCP project by scanning imports and startup calls."""

    for file_path in find_python_files(path):
        tree = parse_file(file_path)
        if not tree:
            continue
        for module, _ in iter_imports(tree):
            if module in MCP_IMPORT_HINTS:
                return True
        source = file_path.read_text(errors="ignore")
        for pattern in STARTUP_PATTERNS:
            if pattern in source:
                return True
    return False


__all__ = ["is_mcp_project", "find_python_files", "MCP_IMPORT_HINTS"]
