from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional

from . import FilesystemAccessError


class SecureFS:
    """Wrapper that enforces filesystem policies."""

    def __init__(self, root_dir: Optional[Path] = None, mode: str = "none"):
        self.root_dir = Path(root_dir).resolve() if root_dir else None
        self.mode = mode

    def _assert_allowed(self, operation: str, target: Path) -> Path:
        if self.mode == "none":
            raise FilesystemAccessError(f"Filesystem access forbidden for operation {operation}")
        resolved = target.resolve()
        if self.root_dir and self.root_dir not in resolved.parents and resolved != self.root_dir:
            raise FilesystemAccessError(
                f"Path {resolved} escapes allowed root {self.root_dir}"
            )
        if self.mode == "read_only" and operation not in {"read", "list", "exists"}:
            raise FilesystemAccessError(
                f"Filesystem mode read_only forbids operation {operation} on {resolved}"
            )
        return resolved

    def open(self, path: os.PathLike | str, mode: str = "r", **kwargs):
        operation = "write" if any(flag in mode for flag in ["w", "a", "+"]) else "read"
        resolved = self._assert_allowed(operation, Path(path))
        return open(resolved, mode, **kwargs)

    def listdir(self, path: os.PathLike | str):
        resolved = self._assert_allowed("list", Path(path))
        return os.listdir(resolved)

    def exists(self, path: os.PathLike | str) -> bool:
        resolved = self._assert_allowed("exists", Path(path))
        return resolved.exists()

    def remove(self, path: os.PathLike | str):
        resolved = self._assert_allowed("write", Path(path))
        os.remove(resolved)

    def makedirs(self, path: os.PathLike | str, exist_ok: bool = False):
        resolved = self._assert_allowed("write", Path(path))
        os.makedirs(resolved, exist_ok=exist_ok)


__all__ = ["SecureFS"]
