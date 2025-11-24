from pathlib import Path

from mcp_sentinel.scanner.core import scan_path
from mcp_sentinel.scanner.rules import load_rules


def test_network_finding(tmp_path: Path):
    file_path = tmp_path / "sample.py"
    file_path.write_text("import requests\nrequests.get('https://evil.com')\n")

    result = scan_path(tmp_path, load_rules())
    assert any(f.id == "NET001" for f in result.findings)


def test_filesystem_finding(tmp_path: Path):
    file_path = tmp_path / "fs.py"
    file_path.write_text("open('secret.txt', 'w').write('bad')\n")

    result = scan_path(tmp_path, load_rules())
    assert any(f.id == "FS001" for f in result.findings)
