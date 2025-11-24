from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .ast_utils import find_python_files, find_strings_in_call, get_call_name, parse_file
from .findings import Finding, ScanResult
from .rules import Rule
from ..policy.models import Policy


NETWORK_CALL_PREFIXES = ["requests.", "httpx.", "aiohttp."]
SMTP_CALLS = {"smtplib.SMTP", "smtplib.SMTP_SSL", "smtplib.SMTP.sendmail"}
FILESYSTEM_CALLS = {"open", "os.remove", "os.rmdir", "shutil.rmtree", "os.walk"}


def _extract_domains(strings: Iterable[str]) -> List[str]:
    domains: List[str] = []
    for value in strings:
        parsed = urlparse(value)
        if parsed.hostname:
            domains.append(parsed.hostname)
    return domains


def _is_environ_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            return node.value.value.id == "os" and node.value.attr == "environ"
    return False


def _find_secrets_misuse(tree: ast.AST, file_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue) and _is_environ_access(value.value):
                    findings.append(
                        Finding(
                            id="SEC001",
                            severity="medium",
                            description="Environment variable interpolated directly into string (possible secret leak).",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            rule_name="Secret interpolation",
                            details=None,
                        )
                    )
        if isinstance(node, ast.Call):
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                if _is_environ_access(arg):
                    findings.append(
                        Finding(
                            id="SEC001",
                            severity="medium",
                            description="Environment variable used directly in call arguments (possible secret leak).",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            rule_name="Secret direct use",
                            details=None,
                        )
                    )
    return findings


def _evaluate_network_call(
    call: ast.Call,
    call_name: str,
    rule: Rule,
    file_path: Path,
    allowed_domains: Optional[List[str]],
) -> Optional[Finding]:
    string_args = find_strings_in_call(call)
    domains = _extract_domains(string_args)
    details: Dict[str, object] = {"domains": domains}
    severity = rule.severity

    if allowed_domains and domains:
        for domain in domains:
            if domain.lower() not in [d.lower() for d in allowed_domains]:
                severity = "high"
                details["unauthorized_domain"] = domain
    return Finding(
        id=rule.id,
        severity=severity,
        description=rule.description,
        file_path=str(file_path),
        line_number=call.lineno,
        rule_name=rule.name,
        details=details,
    )


def scan_path(path: Path, rules: List[Rule], policy: Optional[Policy] = None) -> ScanResult:
    """Scan a path for rule violations."""

    findings: List[Finding] = []
    allowed_domains: Optional[List[str]] = None
    if policy:
        domains: List[str] = []
        for tool in policy.tools:
            if tool.allowed_domains:
                domains.extend(tool.allowed_domains)
        allowed_domains = domains or None

    rule_index: Dict[str, Rule] = {rule.id: rule for rule in rules}

    for file_path in find_python_files(path):
        tree = parse_file(file_path)
        if not tree:
            continue

        # Secret misuse
        findings.extend(_find_secrets_misuse(tree, file_path))

        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            call_name = get_call_name(call)
            # Network detection
            if any(call_name.startswith(prefix) for prefix in NETWORK_CALL_PREFIXES):
                rule = rule_index.get("NET001")
                if rule:
                    finding = _evaluate_network_call(call, call_name, rule, file_path, allowed_domains)
                    findings.append(finding)
            if call_name in SMTP_CALLS:
                rule = rule_index.get("NET002")
                if rule:
                    findings.append(
                        Finding(
                            id=rule.id,
                            severity=rule.severity,
                            description=rule.description,
                            file_path=str(file_path),
                            line_number=call.lineno,
                            rule_name=rule.name,
                            details=None,
                        )
                    )
            # Filesystem detection
            if call_name in FILESYSTEM_CALLS:
                rule = rule_index.get("FS001")
                if rule:
                    findings.append(
                        Finding(
                            id=rule.id,
                            severity=rule.severity,
                            description=rule.description,
                            file_path=str(file_path),
                            line_number=call.lineno,
                            rule_name=rule.name,
                            details={"call": call_name},
                        )
                    )

    return ScanResult(findings=findings)
