"""Secure-ish example showing runtime helpers."""

from pathlib import Path

from mcp_sentinel.runtime.fastmcp_wrapper import tool_with_policy
from mcp_sentinel.runtime.secure_fs import SecureFS
from mcp_sentinel.runtime.secure_http import SecureHTTPClient
from mcp_sentinel.policy.loader import load_policy

policy = load_policy(Path(__file__).parent)


@tool_with_policy("send_email", policy)
def send_email(ctx, to: str, subject: str, body: str):
    assert ctx.http
    ctx.http.post("https://api.postmarkapp.com/email", json={"to": to, "subject": subject, "body": body})


@tool_with_policy("read_logs", policy)
def read_logs(ctx, filename: str):
    assert ctx.fs
    with ctx.fs.open(Path("logs") / filename, "r") as handle:
        return handle.read()


if __name__ == "__main__":
    print(send_email("user@example.com", "Hello", "body"))
