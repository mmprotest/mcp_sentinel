from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple


SKIP_DIRS = {"venv", ".venv", "__pycache__", ".git", "node_modules"}


def parse_file(path: Path) -> Optional[ast.AST]:
    """Safely parse a Python file into an AST."""

    try:
        return ast.parse(path.read_text())
    except SyntaxError:
        return None
    except UnicodeDecodeError:
        return None


def iter_imports(tree: ast.AST) -> Iterator[Tuple[str, Optional[str]]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, alias.asname
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            yield module, None


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def call_matches_name(call: ast.Call, full_name: str) -> bool:
    parts = full_name.split(".")
    node = call.func
    for part in reversed(parts):
        if isinstance(node, ast.Attribute) and node.attr == part:
            node = node.value
            continue
        if isinstance(node, ast.Name) and node.id == part and part == parts[0]:
            return True
        if isinstance(node, ast.Name) and node.id == part:
            return True
        return False
    return False


def get_call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        parts: List[str] = []
        node = call.func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def find_strings_in_call(call: ast.Call) -> List[str]:
    values: List[str] = []
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            values.append(arg.value)
    for kw in call.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            values.append(kw.value.value)
    return values


def find_python_files(path: Path) -> List[Path]:
    paths: List[Path] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            if file.endswith(".py"):
                paths.append(Path(root) / file)
    return paths

import os  # at end to avoid confusion in function definitions
