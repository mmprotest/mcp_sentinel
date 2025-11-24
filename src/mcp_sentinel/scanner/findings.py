from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high"]


class Finding(BaseModel):
    """Represents a single security finding produced by the scanner."""

    id: str
    severity: Severity
    description: str
    file_path: str
    line_number: Optional[int] = Field(default=None)
    rule_name: str
    details: Optional[Dict[str, Any]] = Field(default=None)


class ScanResult(BaseModel):
    """Collection of findings with summary statistics."""

    findings: List[Finding] = Field(default_factory=list)

    @property
    def severity_counts(self) -> Dict[Severity, int]:
        counts: Dict[Severity, int] = {"low": 0, "medium": 0, "high": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def has_high_severity(self) -> bool:
        return any(finding.severity == "high" for finding in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.model_dump() for f in self.findings],
            "severity_counts": self.severity_counts,
        }
