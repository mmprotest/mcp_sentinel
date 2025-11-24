from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..policy.models import Policy
from .secure_fs import SecureFS
from .secure_http import SecureHTTPClient


@dataclass
class ToolContext:
    http: Optional[SecureHTTPClient]
    fs: Optional[SecureFS]


def tool_with_policy(tool_name: str, policy: Policy) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to wrap tool functions with policy-aware helpers."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        tool_policy = policy.get_tool(tool_name)

        def wrapper(*args, **kwargs):
            http_client: Optional[SecureHTTPClient] = None
            fs_client: Optional[SecureFS] = None
            if tool_policy:
                if tool_policy.outbound_http and tool_policy.allowed_domains:
                    http_client = SecureHTTPClient(tool_policy.allowed_domains)
                if tool_policy.filesystem != "none":
                    fs_client = SecureFS(mode=tool_policy.filesystem)
            ctx = ToolContext(http=http_client, fs=fs_client)
            return func(ctx, *args, **kwargs)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator


__all__ = ["tool_with_policy", "ToolContext"]
