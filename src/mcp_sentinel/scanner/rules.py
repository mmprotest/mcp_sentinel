from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ValidationError

RuleMatchType = Literal["ast", "regex", "config"]
Severity = Literal["low", "medium", "high"]


class Rule(BaseModel):
    """Defines a security rule used by the scanner."""

    id: str
    name: str
    description: str
    severity: Severity
    category: str
    match_type: RuleMatchType
    config: Dict[str, Any] = {}


class RuleLoadError(RuntimeError):
    pass


def _load_yaml_rules(path: Path) -> List[Rule]:
    try:
        data = yaml.safe_load(path.read_text()) or []
    except Exception as exc:  # pragma: no cover - defensive
        raise RuleLoadError(f"Failed to read rules file {path}: {exc}")

    rules: List[Rule] = []
    if not isinstance(data, list):
        raise RuleLoadError(f"Rules file {path} must contain a list of rules")
    for entry in data:
        try:
            rules.append(Rule.model_validate(entry))
        except ValidationError as exc:
            raise RuleLoadError(f"Invalid rule in {path}: {exc}")
    return rules


def load_rules(extra_rule_files: Optional[List[Path]] = None) -> List[Rule]:
    """Load default rules and optional extra rule files."""

    repo_root = Path(__file__).resolve().parents[3]
    rules_dir = repo_root / "rules"
    default_rules_path = rules_dir / "default_rules.yml"
    rules = _load_yaml_rules(default_rules_path)

    for extra in extra_rule_files or []:
        rules.extend(_load_yaml_rules(extra))
    return rules
