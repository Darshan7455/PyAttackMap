"""Taint source detection within Python AST nodes."""

from __future__ import annotations

import ast
from typing import Sequence


def get_call_name(node: ast.AST) -> str | None:
    """Extract string representation of a call target (e.g., 'os.getenv' or 'input')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = get_call_name(node.value)
        if value_name:
            return f"{value_name}.{node.attr}"
        return node.attr
    return None


class SourceDetector:
    """Detects expressions representing untrusted external inputs."""

    BUILTIN_CALL_SOURCES: set[str] = {
        "input",
        "sys.argv",
        "os.getenv",
        "os.environ.get",
    }

    BUILTIN_ATTR_SOURCES: set[str] = {
        "request.args",
        "request.form",
        "request.values",
        "request.data",
        "request.json",
        "request.params",
        "request.GET",
        "request.POST",
        "request.body",
        "os.environ",
    }

    def __init__(self, custom_sources: Sequence[str] | None = None) -> None:
        self.call_sources = set(self.BUILTIN_CALL_SOURCES)
        self.attr_sources = set(self.BUILTIN_ATTR_SOURCES)
        if custom_sources:
            for src in custom_sources:
                self.call_sources.add(src)
                self.attr_sources.add(src)

    def is_source(self, node: ast.AST) -> tuple[bool, str]:
        """Check if AST node represents an untrusted taint source."""
        # 1. Call to source functions (e.g., input(), os.getenv('X'))
        if isinstance(node, ast.Call):
            call_name = get_call_name(node.func)
            if call_name and (
                call_name in self.call_sources
                or any(call_name == s or call_name.endswith("." + s) for s in self.call_sources)
            ):
                return True, f"call to {call_name}()"

        # 2. Attribute accesses (e.g., request.args, request.data)
        if isinstance(node, ast.Attribute):
            attr_name = get_call_name(node)
            if attr_name and (
                attr_name in self.attr_sources
                or any(attr_name == s or attr_name.endswith("." + s) for s in self.attr_sources)
            ):
                return True, f"access to {attr_name}"

        # 3. Subscripts on source dicts (e.g., request.args['id'], os.environ['VAR'], sys.argv[1])
        if isinstance(node, ast.Subscript):
            target_name = get_call_name(node.value)
            if target_name and (target_name in self.attr_sources or target_name in self.call_sources or target_name == "sys.argv" or target_name == "os.environ"):
                return True, f"subscript access on {target_name}"

        return False, ""

