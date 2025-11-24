# Runtime Helpers

MCP Sentinel includes opt-in runtime helpers for cooperative servers.

## SecureHTTPClient
```python
from mcp_sentinel.runtime.secure_http import SecureHTTPClient
client = SecureHTTPClient(["api.postmarkapp.com"])
client.post("https://api.postmarkapp.com/email", json={...})  # raises if domain not allowed
```

## SecureFS
```python
from mcp_sentinel.runtime.secure_fs import SecureFS
fs = SecureFS(root_dir="/workspace/data", mode="read_only")
with fs.open("/workspace/data/file.txt") as handle:
    print(handle.read())
```
- `mode="none"` blocks all operations.
- `mode="read_only"` allows reads/listing only.
- `mode="read_write"` allows writes within the optional `root_dir`.

## FastMCP-style wrapper
```python
from mcp_sentinel.runtime.fastmcp_wrapper import tool_with_policy
from mcp_sentinel.policy.loader import load_policy

policy = load_policy()

@tool_with_policy("send_email", policy)
def send_email(ctx, to: str, subject: str, body: str):
    ctx.http.post("https://api.postmarkapp.com/email", json={"to": to, "subject": subject, "body": body})
```
The decorator injects `ctx.http` and `ctx.fs` based on the policy entry for the tool name.
