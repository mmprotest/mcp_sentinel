from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from ..scanner.ast_utils import find_python_files, get_call_name, parse_file
from ..scanner.findings import Finding
from .models import Policy


POLICY_RULE_IDS = {
    "missing_tool": "POL001",
    "outbound_without_permission": "POL002",
    "missing_allowed_domains": "POL003",
    "filesystem_violation": "POL004",
}


def _function_uses_network(func: ast.FunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            name = get_call_name(node)
            if name.startswith("requests") or name.startswith("httpx") or name.startswith("aiohttp"):
                return True
    return False


def _function_uses_filesystem(func: ast.FunctionDef) -> bool:
    filesystem_calls = {"open", "os.remove", "os.rmdir", "shutil.rmtree", "os.walk"}
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and get_call_name(node) in filesystem_calls:
            return True
    return False


def validate_policy_against_code(path: Path, policy: Policy) -> List[Finding]:
    """Validate that code at path aligns with the provided policy."""

    findings: List[Finding] = []
    for file_path in find_python_files(path):
        tree = parse_file(file_path)
        if not tree:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                tool_policy = policy.get_tool(func_name)
                uses_network = _function_uses_network(node)
                uses_fs = _function_uses_filesystem(node)

                if (uses_network or uses_fs) and tool_policy is None:
                    findings.append(
                        Finding(
                            id=POLICY_RULE_IDS["missing_tool"],
                            severity="high",
                            description=f"Tool '{func_name}' uses privileged operations but is missing from policy.",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            rule_name="Policy missing tool",
                            details={"tool": func_name},
                        )
                    )
                    continue
                if not tool_policy:
                    continue

                if uses_network:
                    if not tool_policy.outbound_http:
                        findings.append(
                            Finding(
                                id=POLICY_RULE_IDS["outbound_without_permission"],
                                severity="high",
                                description=f"Tool '{func_name}' performs outbound HTTP but policy forbids it.",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                rule_name="Policy outbound HTTP violation",
                                details={"tool": func_name},
                            )
                        )
                    elif not tool_policy.allowed_domains:
                        findings.append(
                            Finding(
                                id=POLICY_RULE_IDS["missing_allowed_domains"],
                                severity="medium",
                                description=f"Tool '{func_name}' allows outbound HTTP but has no allowed_domains configured.",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                rule_name="Policy missing allowed domains",
                                details={"tool": func_name},
                            )
                        )

                if uses_fs:
                    if tool_policy.filesystem == "none":
                        findings.append(
                            Finding(
                                id=POLICY_RULE_IDS["filesystem_violation"],
                                severity="high",
                                description=f"Tool '{func_name}' accesses filesystem but policy disallows it.",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                rule_name="Policy filesystem violation",
                                details={"tool": func_name},
                            )
                        )
    return findings
