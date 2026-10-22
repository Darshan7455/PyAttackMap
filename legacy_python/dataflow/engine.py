"""Intra-procedural taint analysis engine for tracking untrusted data flow."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Iterator

from pyattackmap.config import ScanConfig
from pyattackmap.dataflow.graph import DataFlowGraphBuilder
from pyattackmap.dataflow.sanitizers import SanitizerDetector
from pyattackmap.dataflow.sinks import SinkDetector
from pyattackmap.dataflow.sources import SourceDetector, get_call_name
from pyattackmap.models import (
    DataFlowEdge,
    DataFlowGraph,
    DataFlowNode,
    DataFlowNodeKind,
)
from pyattackmap.parser import ParsedSource


@dataclass
class TaintTrace:
    """A verified source-to-sink data-flow trace."""

    sink_call: ast.Call
    sink_name: str
    source_node: DataFlowNode
    propagation_nodes: list[DataFlowNode]
    sink_node: DataFlowNode
    graph: DataFlowGraph
    tainted_arg: ast.AST


@dataclass
class VariableTaint:
    """Taint state for a single variable name within a lexical scope."""

    name: str
    source_node: DataFlowNode
    trace: list[DataFlowNode] = field(default_factory=list)


class ScopeTaintState:
    """Maintains tainted variable bindings across statements in a function or module."""

    def __init__(self, builder: DataFlowGraphBuilder) -> None:
        self.builder = builder
        self.tainted_vars: dict[str, VariableTaint] = {}

    def set_taint(self, var_name: str, source_node: DataFlowNode, trace: list[DataFlowNode]) -> None:
        self.tainted_vars[var_name] = VariableTaint(
            name=var_name,
            source_node=source_node,
            trace=list(trace),
        )

    def clear_taint(self, var_name: str) -> None:
        self.tainted_vars.pop(var_name, None)

    def get_taint(self, var_name: str) -> VariableTaint | None:
        return self.tainted_vars.get(var_name)


class IntraProceduralTaintTracker:
    """Performs intra-procedural taint tracking on AST trees."""

    def __init__(self, parsed: ParsedSource, config: ScanConfig) -> None:
        self.parsed = parsed
        self.config = config
        self.source_detector = SourceDetector(config.sources)
        self.sink_detector = SinkDetector(config.sinks)
        self.sanitizer_detector = SanitizerDetector(config.sanitizers)

    def analyze(self) -> list[TaintTrace]:
        """Analyze all lexical scopes (module top-level, functions, async functions, methods)."""
        traces: list[TaintTrace] = []

        # 1. Top-level module statements
        traces.extend(self._analyze_statements(self.parsed.tree.body))

        # 2. Function definitions inside module and classes
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                traces.extend(self._analyze_statements(node.body))

        return traces

    def _analyze_statements(self, statements: list[ast.stmt]) -> list[TaintTrace]:
        builder = DataFlowGraphBuilder(self.parsed.file_path)
        state = ScopeTaintState(builder)
        traces: list[TaintTrace] = []

        for stmt in statements:
            # Do not re-analyze nested function definitions within this statement list
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # Handle assignments: x = ...
            if isinstance(stmt, ast.Assign):
                self._handle_assign(stmt, state, builder)
            elif isinstance(stmt, ast.AnnAssign):
                self._handle_ann_assign(stmt, state, builder)
            elif isinstance(stmt, ast.AugAssign):
                self._handle_aug_assign(stmt, state, builder)

            # Scan expressions in the statement for direct sink calls
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call):
                    trace = self._check_call_sink(child, state, builder)
                    if trace:
                        traces.append(trace)

        return traces

    def _handle_ann_assign(
        self,
        stmt: ast.AnnAssign,
        state: ScopeTaintState,
        builder: DataFlowGraphBuilder,
    ) -> None:
        if isinstance(stmt.target, ast.Name) and stmt.value is not None:
            var_name = stmt.target.id
            is_tainted, src_node, trace_nodes = self._evaluate_taint(stmt.value, state, builder)
            if is_tainted and src_node is not None:
                snippet = self.parsed.get_snippet(stmt.lineno, stmt.end_lineno or stmt.lineno)
                prop_node = builder.add_node(
                    kind=DataFlowNodeKind.PROPAGATION,
                    line=stmt.lineno,
                    col=stmt.col_offset,
                    label=f"Assign tainted expression to '{var_name}'",
                    snippet=snippet.strip(),
                )
                new_trace = list(trace_nodes) + [prop_node]
                state.set_taint(var_name, src_node, new_trace)
            else:
                state.clear_taint(var_name)

    def _handle_assign(
        self,
        stmt: ast.Assign,
        state: ScopeTaintState,
        builder: DataFlowGraphBuilder,
    ) -> None:
        value = stmt.value
        # Check if right hand side is tainted
        is_tainted, src_node, trace_nodes = self._evaluate_taint(value, state, builder)

        for target in stmt.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if is_tainted and src_node is not None:
                    # Create propagation node for assignment
                    snippet = self.parsed.get_snippet(stmt.lineno, stmt.end_lineno or stmt.lineno)
                    prop_node = builder.add_node(
                        kind=DataFlowNodeKind.PROPAGATION,
                        line=stmt.lineno,
                        col=stmt.col_offset,
                        label=f"Assign tainted expression to '{var_name}'",
                        snippet=snippet.strip(),
                    )
                    new_trace = list(trace_nodes) + [prop_node]
                    state.set_taint(var_name, src_node, new_trace)
                else:
                    state.clear_taint(var_name)

    def _handle_aug_assign(
        self,
        stmt: ast.AugAssign,
        state: ScopeTaintState,
        builder: DataFlowGraphBuilder,
    ) -> None:
        if isinstance(stmt.target, ast.Name):
            var_name = stmt.target.id
            is_tainted, src_node, trace_nodes = self._evaluate_taint(stmt.value, state, builder)
            current_taint = state.get_taint(var_name)

            if is_tainted and src_node is not None:
                snippet = self.parsed.get_snippet(stmt.lineno, stmt.end_lineno or stmt.lineno)
                prop_node = builder.add_node(
                    kind=DataFlowNodeKind.PROPAGATION,
                    line=stmt.lineno,
                    col=stmt.col_offset,
                    label=f"Augmented assign to '{var_name}'",
                    snippet=snippet.strip(),
                )
                new_trace = list(trace_nodes) + [prop_node]
                state.set_taint(var_name, src_node, new_trace)
            elif current_taint is not None:
                snippet = self.parsed.get_snippet(stmt.lineno, stmt.end_lineno or stmt.lineno)
                prop_node = builder.add_node(
                    kind=DataFlowNodeKind.PROPAGATION,
                    line=stmt.lineno,
                    col=stmt.col_offset,
                    label=f"Augmented assign on tainted '{var_name}'",
                    snippet=snippet.strip(),
                )
                new_trace = list(current_taint.trace) + [prop_node]
                state.set_taint(var_name, current_taint.source_node, new_trace)

    def _evaluate_taint(
        self,
        node: ast.AST,
        state: ScopeTaintState,
        builder: DataFlowGraphBuilder,
    ) -> tuple[bool, DataFlowNode | None, list[DataFlowNode]]:
        """Recursively evaluate if an AST expression produces a tainted value."""
        # 1. Direct source check
        is_src, src_desc = self.source_detector.is_source(node)
        if is_src:
            lineno = getattr(node, "lineno", 1)
            col = getattr(node, "col_offset", 0)
            end_line = getattr(node, "end_lineno", lineno)
            snippet = self.parsed.get_snippet(lineno, end_line)
            src_node = builder.add_node(
                kind=DataFlowNodeKind.SOURCE,
                line=lineno,
                col=col,
                label=f"Taint source ({src_desc})",
                snippet=snippet.strip(),
            )
            return True, src_node, [src_node]

        # 2. Check for sanitizer calls
        if isinstance(node, ast.Call):
            is_san, san_name = self.sanitizer_detector.is_sanitizer_call(node)
            if is_san:
                # Sanitized! Taint is neutralized
                return False, None, []

        # 3. Variable reference
        if isinstance(node, ast.Name):
            t = state.get_taint(node.id)
            if t:
                return True, t.source_node, list(t.trace)
            return False, None, []

        # 4. F-string (JoinedStr)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    is_t, src_node, trace = self._evaluate_taint(value.value, state, builder)
                    if is_t:
                        return True, src_node, trace
            return False, None, []

        # 5. Binary operations (e.g. "SELECT " + var or "cmd %s" % var)
        if isinstance(node, ast.BinOp):
            left_t, left_src, left_trace = self._evaluate_taint(node.left, state, builder)
            if left_t:
                return True, left_src, left_trace
            right_t, right_src, right_trace = self._evaluate_taint(node.right, state, builder)
            if right_t:
                return True, right_src, right_trace
            return False, None, []

        # 6. Call expressions (e.g. "... {}".format(var))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                # Check target and arguments
                for arg in node.args:
                    is_t, src_node, trace = self._evaluate_taint(arg, state, builder)
                    if is_t:
                        return True, src_node, trace
                for kw in node.keywords:
                    is_t, src_node, trace = self._evaluate_taint(kw.value, state, builder)
                    if is_t:
                        return True, src_node, trace

        return False, None, []

    def _check_call_sink(
        self,
        call: ast.Call,
        state: ScopeTaintState,
        builder: DataFlowGraphBuilder,
    ) -> TaintTrace | None:
        """Inspect if call is a known sink and receives tainted data."""
        sink_name = ""
        is_sink = False

        is_sql, name_sql = self.sink_detector.is_sql_sink(call)
        if is_sql:
            is_sink, sink_name = True, name_sql
        else:
            is_cmd, name_cmd = self.sink_detector.is_command_sink(call)
            if is_cmd:
                is_sink, sink_name = True, name_cmd
            else:
                is_deser, name_deser = self.sink_detector.is_deserialization_sink(call)
                if is_deser:
                    is_sink, sink_name = True, name_deser

        if not is_sink:
            return None

        # Check positional and keyword arguments passed to the sink
        candidate_args = list(call.args) + [kw.value for kw in call.keywords]
        for arg in candidate_args:
            is_t, src_node, trace = self._evaluate_taint(arg, state, builder)
            if is_t and src_node is not None:
                lineno = getattr(call, "lineno", 1)
                col = getattr(call, "col_offset", 0)
                end_line = getattr(call, "end_lineno", lineno)
                snippet = self.parsed.get_snippet(lineno, end_line)

                sink_node = builder.add_node(
                    kind=DataFlowNodeKind.SINK,
                    line=lineno,
                    col=col,
                    label=f"Sink call '{sink_name}' receives tainted data",
                    snippet=snippet.strip(),
                )

                # Build an isolated graph specifically for this trace
                prop_nodes: list[DataFlowNode] = []
                seen_ids: set[str] = {src_node.id}
                trace_nodes = [src_node]
                trace_edges: list[DataFlowEdge] = []
                current_id = src_node.id

                for p_node in trace:
                    if p_node.id not in seen_ids:
                        seen_ids.add(p_node.id)
                        trace_nodes.append(p_node)
                        prop_nodes.append(p_node)
                        trace_edges.append(
                            DataFlowEdge(source_id=current_id, target_id=p_node.id, label="propagates")
                        )
                        current_id = p_node.id

                trace_nodes.append(sink_node)
                trace_edges.append(
                    DataFlowEdge(source_id=current_id, target_id=sink_node.id, label="reaches sink")
                )

                graph = DataFlowGraph(nodes=trace_nodes, edges=trace_edges)
                return TaintTrace(
                    sink_call=call,
                    sink_name=sink_name,
                    source_node=src_node,
                    propagation_nodes=prop_nodes,
                    sink_node=sink_node,
                    graph=graph,
                    tainted_arg=arg,
                )

        return None

