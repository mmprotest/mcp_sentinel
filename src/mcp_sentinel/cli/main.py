from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from ..policy.loader import load_policy
from ..policy.validator import validate_policy_against_code
from ..scanner.core import scan_path
from ..scanner.rules import load_rules

app = typer.Typer(add_completion=False)
console = Console()


@app.command("mcp-scan")
def mcp_scan(
    path: Path = typer.Argument(Path("."), help="Path to scan"),
    format: str = typer.Option("table", "--format", help="Output format: table or json"),
    fail_on: str = typer.Option("high", "--fail-on", help="Fail threshold: low, medium, high"),
    rules_file: Optional[Path] = typer.Option(None, "--rules-file", help="Extra rules file"),
    policy_file: Optional[Path] = typer.Option(None, "--policy-file", help="Policy file"),
) -> None:
    rules = load_rules([rules_file] if rules_file else None)
    policy = load_policy(policy_file) if policy_file else load_policy(path)
    result = scan_path(path, rules, policy)

    threshold_order = {"low": 1, "medium": 2, "high": 3}
    threshold_value = threshold_order.get(fail_on, 3)

    if format == "json":
        console.print(json.dumps(result.to_dict(), indent=2))
    else:
        table = Table(title="MCP Sentinel Scan Findings")
        table.add_column("Rule ID")
        table.add_column("Severity")
        table.add_column("Description")
        table.add_column("File")
        table.add_column("Line")
        for finding in result.findings:
            table.add_row(
                finding.id,
                finding.severity,
                finding.description,
                finding.file_path,
                str(finding.line_number or ""),
            )
        console.print(table)
        console.print(f"Summary: {result.severity_counts}")

    highest = max((threshold_order.get(f.severity, 0) for f in result.findings), default=0)
    if highest >= threshold_value:
        raise typer.Exit(code=1)


@app.command("mcp-policy-validate")
def mcp_policy_validate(
    path: Path = typer.Argument(Path("."), help="Path to project"),
    policy_file: Optional[Path] = typer.Option(None, "--policy-file", help="Policy file"),
) -> None:
    policy = load_policy(policy_file) if policy_file else load_policy(path)
    if not policy:
        console.print("No policy found.")
        raise typer.Exit(code=1)

    findings = validate_policy_against_code(path, policy)
    if not findings:
        console.print("Policy validation passed.")
        raise typer.Exit(code=0)

    table = Table(title="Policy Validation Findings")
    table.add_column("Rule ID")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("File")
    table.add_column("Line")
    for finding in findings:
        table.add_row(
            finding.id,
            finding.severity,
            finding.description,
            finding.file_path,
            str(finding.line_number or ""),
        )
    console.print(table)
    highest = max((f.severity for f in findings), default="low")
    if any(f.severity == "high" for f in findings):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
