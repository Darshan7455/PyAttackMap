"""Sanitizer and neutralizer detection within Python AST nodes."""

from __future__ import annotations

import ast
from typing import Sequence

from pyattackmap.dataflow.sources import get_call_name


class SanitizerDetector:
    """Detects sanitization routines that neutralize tainted values."""

    BUILTIN_SANITIZERS: set[str] = {
        "shlex.quote",
        "int",
        "float",
        "bool",
        "sql.Literal",
        "psycopg2.sql.Literal",
        "escape_string",
    }

    def __init__(self, custom_sanitizers: Sequence[str] | None = None) -> None:
        self.sanitizers = set(self.BUILTIN_SANITIZERS)
        if custom_sanitizers:
            for s in custom_sanitizers:
                self.sanitizers.add(s)

    def is_sanitizer_call(self, call_node: ast.Call) -> tuple[bool, str]:
        """Check if call represents a recognized sanitizer function."""
        call_name = get_call_name(call_node.func)
        if not call_name:
            return False, ""
        if call_name in self.sanitizers or any(
            call_name == s or call_name.endswith("." + s) for s in self.sanitizers
        ):
            return True, call_name
        return False, ""

