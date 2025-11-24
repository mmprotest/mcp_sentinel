from __future__ import annotations

class PolicyViolationError(Exception):
    """Raised when runtime access violates the policy."""


class UnauthorizedDomainError(PolicyViolationError):
    """Raised when outbound HTTP attempts target an unauthorized domain."""


class FilesystemAccessError(PolicyViolationError):
    """Raised when filesystem access violates configured mode."""


__all__ = [
    "PolicyViolationError",
    "UnauthorizedDomainError",
    "FilesystemAccessError",
]
