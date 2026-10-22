"""Tests for intra-procedural taint analysis and data-flow propagation."""

from pyattackmap.config import ScanConfig
from pyattackmap.dataflow.engine import IntraProceduralTaintTracker
from pyattackmap.models import DataFlowNodeKind
from pyattackmap.parser import SafeParser


def test_taint_propagation_linear() -> None:
    code = """
import os

def handle():
    user_val = input("Name: ")
    cmd = "echo " + user_val
    os.system(cmd)
"""
    parsed = SafeParser.parse_string(code, "test_flow.py")
    tracker = IntraProceduralTaintTracker(parsed, ScanConfig())
    traces = tracker.analyze()

    assert len(traces) == 1
    trace = traces[0]
    assert trace.sink_name == "os.system"
    assert trace.source_node.kind == DataFlowNodeKind.SOURCE
    assert "input" in trace.source_node.label
    assert len(trace.propagation_nodes) >= 1
    assert trace.sink_node.kind == DataFlowNodeKind.SINK


def test_taint_cleared_by_sanitizer() -> None:
    code = """
import os
import shlex

def handle_safe():
    user_val = input("Name: ")
    safe_val = shlex.quote(user_val)
    cmd = "echo " + safe_val
    os.system(cmd)
"""
    parsed = SafeParser.parse_string(code, "test_sanitizer.py")
    tracker = IntraProceduralTaintTracker(parsed, ScanConfig())
    traces = tracker.analyze()
    # Taint should be neutralized by shlex.quote
    assert len(traces) == 0


def test_taint_cleared_by_constant_reassignment() -> None:
    code = """
import os

def handle_overwrite():
    val = input()
    val = "constant_safe_value"
    os.system(val)
"""
    parsed = SafeParser.parse_string(code, "test_overwrite.py")
    tracker = IntraProceduralTaintTracker(parsed, ScanConfig())
    traces = tracker.analyze()
    assert len(traces) == 0


def test_taint_in_fstring() -> None:
    code = """
import os

def run_fstring():
    ip = input("IP: ")
    target = f"ping -c 1 {ip}"
    os.system(target)
"""
    parsed = SafeParser.parse_string(code, "test_fstring.py")
    tracker = IntraProceduralTaintTracker(parsed, ScanConfig())
    traces = tracker.analyze()
    assert len(traces) == 1
    assert "input" in traces[0].source_node.label


def test_taint_with_type_annotation() -> None:
    code = """
import os

def run_annotated():
    cmd_val: str = input("Command: ")
    os.system(cmd_val)
"""
    parsed = SafeParser.parse_string(code, "test_ann.py")
    tracker = IntraProceduralTaintTracker(parsed, ScanConfig())
    traces = tracker.analyze()
    assert len(traces) == 1
    assert traces[0].sink_name == "os.system"


def test_taint_with_keyword_arguments() -> None:
    code = """
import subprocess

def run_kw():
    target = input()
    subprocess.run(args=target, shell=True)
"""
    parsed = SafeParser.parse_string(code, "test_kw.py")
    tracker = IntraProceduralTaintTracker(parsed, ScanConfig())
    traces = tracker.analyze()
    assert len(traces) == 1
    assert "subprocess.run" in traces[0].sink_name

