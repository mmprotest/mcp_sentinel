# Usage

## Installation
```bash
pip install .
```

## Scanning a project
```bash
mcp-sentinel mcp-scan .
```
- `--format json` outputs machine-readable JSON.
- `--fail-on medium` will fail CI if any medium+ severity finding exists.

## Example output
Findings are displayed in a table with rule id, severity, description, file, and line number. Summary counts per severity are shown at the end.
