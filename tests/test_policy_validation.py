from pathlib import Path

from mcp_sentinel.policy.models import Policy, ToolPolicy
from mcp_sentinel.policy.validator import validate_policy_against_code


def test_policy_missing_allowed_domains(tmp_path: Path):
    code = tmp_path / "tool.py"
    code.write_text("import requests\n\ndef send_tool():\n    requests.get('https://example.com')\n")

    policy = Policy(
        tools=[ToolPolicy(name="send_tool", outbound_http=True, allowed_domains=None, filesystem="none")]
    )

    findings = validate_policy_against_code(tmp_path, policy)
    assert any(f.id == "POL003" for f in findings)


def test_policy_missing_tool_entry(tmp_path: Path):
    code = tmp_path / "tool.py"
    code.write_text("import requests\n\ndef send_tool():\n    requests.get('https://example.com')\n")

    policy = Policy(tools=[])
    findings = validate_policy_against_code(tmp_path, policy)
    assert any(f.id == "POL001" for f in findings)
