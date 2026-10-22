"""Taint sink detection within Python AST nodes."""

from __future__ import annotations

import ast
from typing import Sequence

from pyattackmap.dataflow.sources import get_call_name


class SinkDetector:
    """Detects security-sensitive operation sinks."""

    SQL_SINKS: set[str] = {
        "execute",
        "executemany",
        "cursor.execute",
        "connection.execute",
        "session.execute",
        "engine.execute",
        "db.execute",
    }

    COMMAND_SINKS: set[str] = {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }

    DESERIALIZATION_SINKS: set[str] = {
        "pickle.load",
        "pickle.loads",
        "_pickle.load",
        "_pickle.loads",
        "cPickle.load",
        "cPickle.loads",
    }

    def __init__(self, custom_sinks: Sequence[str] | None = None) -> None:
        self.custom_sinks = set(custom_sinks or [])

    def is_sql_sink(self, call_node: ast.Call) -> tuple[bool, str]:
        call_name = get_call_name(call_node.func)
        if not call_name:
            return False, ""
        if call_name in self.SQL_SINKS or call_name.endswith(".execute") or call_name.endswith(".executemany"):
            return True, call_name
        if call_name in self.custom_sinks:
            return True, call_name
        return False, ""

    def is_command_sink(self, call_node: ast.Call) -> tuple[bool, str]:
        call_name = get_call_name(call_node.func)
        if not call_name:
            return False, ""
        if call_name in self.COMMAND_SINKS:
            return True, call_name
        # Short names like 'system' or 'popen' if imported directly from os
        if call_name in {"system", "popen"}:
            return True, call_name
        if call_name in self.custom_sinks:
            return True, call_name
        return False, ""

    def is_deserialization_sink(self, call_node: ast.Call) -> tuple[bool, str]:
        call_name = get_call_name(call_node.func)
        if not call_name:
            return False, ""
        if call_name in self.DESERIALIZATION_SINKS:
            return True, call_name
        if call_name in self.custom_sinks:
            return True, call_name
        return False, ""

