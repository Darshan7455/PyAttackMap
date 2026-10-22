"""PAM001: SQL Injection Detection Rule."""

from __future__ import annotations

import ast

from pyattackmap.config import ScanConfig
from pyattackmap.dataflow.engine import IntraProceduralTaintTracker, TaintTrace
from pyattackmap.dataflow.sanitizers import SanitizerDetector
from pyattackmap.dataflow.sinks import SinkDetector
from pyattackmap.dataflow.sources import get_call_name
from pyattackmap.models import Confidence, Finding, Severity
from pyattackmap.parser import ParsedSource
from pyattackmap.rules.base import Rule


def is_dynamic_string_construction(node: ast.AST) -> tuple[bool, str]:
    """Check if an AST expression constructs a string dynamically."""
    if isinstance(node, ast.JoinedStr):
        return True, "f-string formatting"
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return True, "string concatenation (+)"
        if isinstance(node.op, ast.Mod):
            return True, "percent formatting (%)"
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True, "str.format() method"
    return False, ""


class SqlInjectionRule(Rule):
    """Detects unsafe dynamic SQL query construction reaching execution calls."""

    rule_id = "PAM001"
    title = "Potential SQL Injection via Dynamic Query Construction"
    description = (
        "Dynamically constructed SQL queries using string formatting, f-strings, "
        "or concatenation can allow attackers to alter query logic."
    )
    severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    cwe = "CWE-89"

    REMEDIATION = (
        "Use parameterized queries with database driver place-holders instead of string formatting.\n"
        "Example (Safe Parameterization):\n"
        "    # Parameterized query (driver handles escaping):\n"
        "    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))"
    )

    def run(self, parsed: ParsedSource, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        sink_detector = SinkDetector(config.sinks)
        sanitizer_detector = SanitizerDetector(config.sanitizers)

        # Track variables that were assigned from explicit sanitizer calls
        sanitized_vars: set[str] = set()
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Call):
                    is_san, _ = sanitizer_detector.is_sanitizer_call(node.value)
                    if is_san:
                        sanitized_vars.add(node.targets[0].id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                if isinstance(node.value, ast.Call):
                    is_san, _ = sanitizer_detector.is_sanitizer_call(node.value)
                    if is_san:
                        sanitized_vars.add(node.target.id)

        # 1. Run taint analysis to find verified data-flow paths reaching SQL sinks
        taint_tracker = IntraProceduralTaintTracker(parsed, config)
        taint_traces = taint_tracker.analyze()

        taint_by_call: dict[int, TaintTrace] = {}
        for trace in taint_traces:
            is_sql, _ = sink_detector.is_sql_sink(trace.sink_call)
            if is_sql:
                taint_by_call[id(trace.sink_call)] = trace

        # Track assignments in the file to resolve variable references (e.g. query = f"...")
        assigned_dynamic: dict[str, tuple[str, int]] = {}
        for node in ast.walk(parsed.tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                is_dyn, dyn_kind = is_dynamic_string_construction(node.value)
                if is_dyn:
                    referenced = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                    if not (referenced and referenced.issubset(sanitized_vars)):
                        assigned_dynamic[node.targets[0].id] = (dyn_kind, node.lineno)

        # 2. Walk AST to examine all SQL sink calls
        for node in ast.walk(parsed.tree):
            if not isinstance(node, ast.Call):
                continue

            is_sql, call_name = sink_detector.is_sql_sink(node)
            if not is_sql or not node.args:
                continue

            query_arg = node.args[0]
            lineno = getattr(node, "lineno", 1)
            col = getattr(node, "col_offset", 0)
            end_lineno = getattr(node, "end_lineno", lineno)
            end_col = getattr(node, "end_col_offset", col)
            snippet = parsed.get_snippet(lineno, end_lineno)

            # Check if this call has a verified taint trace
            trace = taint_by_call.get(id(node))
            if trace:
                finding_id = f"PAM001-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"Call to '{call_name}' executes a SQL query receiving tainted input from "
                            f"{trace.source_node.label} at line {trace.source_node.line}."
                        ),
                        severity=self.severity,
                        confidence=Confidence.HIGH,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Tainted data reaches query argument in '{call_name}()'.",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=trace.graph if config.show_dataflow else None,
                        metadata={"sink": call_name, "pattern": "taint_flow"},
                    )
                )
                continue

            # Check direct dynamic string construction in first argument
            is_dyn, dyn_kind = is_dynamic_string_construction(query_arg)
            referenced = {n.id for n in ast.walk(query_arg) if isinstance(n, ast.Name)}
            if is_dyn and referenced and referenced.issubset(sanitized_vars):
                continue

            if is_dyn:
                finding_id = f"PAM001-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Call to '{call_name}' executes an inline query constructed via {dyn_kind}.",
                        severity=self.severity,
                        confidence=Confidence.MEDIUM,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Dynamic SQL constructed using {dyn_kind}.",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=None,
                        metadata={"sink": call_name, "pattern": dyn_kind},
                    )
                )
                continue

            # Check if passing a variable that was constructed dynamically in the same scope
            if isinstance(query_arg, ast.Name) and query_arg.id in assigned_dynamic:
                dyn_kind, assign_line = assigned_dynamic[query_arg.id]
                finding_id = f"PAM001-{parsed.file_path}-{lineno}-{col}"
                findings.append(
                    Finding(
                        id=finding_id,
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"Call to '{call_name}' executes query variable '{query_arg.id}', "
                            f"constructed dynamically via {dyn_kind} at line {assign_line}."
                        ),
                        severity=self.severity,
                        confidence=Confidence.MEDIUM,
                        file=parsed.file_path,
                        line=lineno,
                        end_line=end_lineno,
                        col=col,
                        end_col=end_col,
                        snippet=snippet,
                        evidence=f"Query variable '{query_arg.id}' built via {dyn_kind}.",
                        remediation=self.REMEDIATION,
                        cwe=self.cwe,
                        dataflow=None,
                        metadata={"sink": call_name, "variable": query_arg.id, "pattern": dyn_kind},
                    )
                )

        return findings
