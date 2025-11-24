# CI Integration

## GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install .
      - run: mcp-sentinel mcp-scan . --fail-on high
```

## GitLab CI
```yaml
stages:
  - security

mcp_scan:
  stage: security
  image: python:3.11
  script:
    - pip install .
    - mcp-sentinel mcp-scan . --fail-on high
  allow_failure: false
```
