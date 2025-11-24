from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from .models import Policy


class PolicyLoadError(RuntimeError):
    pass


def _search_policy_file(path: Path) -> Optional[Path]:
    current = path
    if current.is_file():
        current = current.parent
    for parent in [current, *current.parents]:
        candidate = parent / "mcp_sentinel.yml"
        if candidate.exists():
            return candidate
    return None


def load_policy(path: Optional[Path] = None) -> Optional[Policy]:
    """Load policy from mcp_sentinel.yml in the provided path or its parents."""

    search_path = path or Path.cwd()
    policy_path = _search_policy_file(search_path)
    if not policy_path:
        return None
    try:
        data = yaml.safe_load(policy_path.read_text()) or {}
        return Policy.model_validate(data)
    except ValidationError as exc:  # pragma: no cover - defensive
        raise PolicyLoadError(f"Invalid policy file {policy_path}: {exc}")
    except Exception as exc:  # pragma: no cover - defensive
        raise PolicyLoadError(f"Failed to load policy file {policy_path}: {exc}")
