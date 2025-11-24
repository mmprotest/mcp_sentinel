"""Public API for MCP Sentinel.

This module exposes the core scanning and policy validation helpers so users can
import a minimal surface for scripting or embedding MCP Sentinel.
"""

from __future__ import annotations

from .scanner.core import scan_path
from .scanner.rules import load_rules
from .policy.loader import load_policy
from .policy.validator import validate_policy_against_code
from .scanner.findings import Finding, ScanResult
from .policy.models import Policy

__all__ = [
    "scan_path",
    "load_rules",
    "load_policy",
    "validate_policy_against_code",
    "Finding",
    "ScanResult",
    "Policy",
]
