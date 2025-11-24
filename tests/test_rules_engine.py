from pathlib import Path

from mcp_sentinel.scanner.rules import Rule, RuleLoadError, load_rules


def test_default_rules_load():
    rules = load_rules()
    ids = {r.id for r in rules}
    assert "NET001" in ids and "FS001" in ids


def test_load_custom_rules(tmp_path: Path):
    custom = tmp_path / "rules.yml"
    custom.write_text(
        """
- id: "CUST001"
  name: "Custom"
  description: "Custom rule"
  severity: "low"
  category: "custom"
  match_type: "regex"
  config: {}
"""
    )
    rules = load_rules([custom])
    assert any(r.id == "CUST001" for r in rules)
