# Policy

Policies live in `mcp_sentinel.yml` and describe least-privilege expectations per MCP tool.

```yaml
server:
  name: my-mcp-server

tools:
  - name: send_email
    outbound_http: true
    allowed_domains:
      - "api.postmarkapp.com"
    filesystem: "none"
  - name: manage_files
    outbound_http: false
    filesystem: "read_only"
```

- `outbound_http`: whether the tool is allowed to make HTTP requests.
- `allowed_domains`: list of hostnames permitted for HTTP calls when `outbound_http` is true.
- `filesystem`: one of `none`, `read_only`, `read_write`.

During scanning, MCP Sentinel uses this policy to highlight unknown domains and missing tool entries. The validator cross-checks that functions performing HTTP or filesystem access have matching tool policies.
