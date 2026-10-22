"""Tests for core data models, serialization, and result aggregations."""

from pathlib import Path
import json
import pytest

from pyattackmap.models import (
    AnalysisResult,
    Confidence,
    DataFlowEdge,
    DataFlowGraph,
    DataFlowNode,
    DataFlowNodeKind,
    Finding,
    ScanStatistics,
    Severity,
)


def test_severity_ordering_and_parsing() -> None:
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO
    assert Severity.HIGH >= "HIGH"
    assert Severity.HIGH >= "MEDIUM"
    assert Severity.LOW <= Severity.HIGH

    assert Severity.from_string("high") == Severity.HIGH
    assert Severity.from_string("CRITICAL") == Severity.CRITICAL

    with pytest.raises(ValueError):
        Severity.from_string("UNKNOWN")


def test_confidence_parsing() -> None:
    assert Confidence.from_string("high") == Confidence.HIGH
    with pytest.raises(ValueError):
        Confidence.from_string("INVALID")


def test_finding_and_graph_serialization(tmp_path: Path) -> None:
    node1 = DataFlowNode(
        id="n1",
        kind=DataFlowNodeKind.SOURCE,
        file="app.py",
        line=10,
        col=4,
        label="input()",
        snippet="u = input()",
    )
    node2 = DataFlowNode(
        id="n2",
        kind=DataFlowNodeKind.SINK,
        file="app.py",
        line=12,
        col=4,
        label="os.system()",
        snippet="os.system(u)",
    )
    edge = DataFlowEdge(source_id="n1", target_id="n2", label="flows to")
    graph = DataFlowGraph(nodes=[node1, node2], edges=[edge])

    mermaid = graph.to_mermaid()
    assert "flowchart TD" in mermaid
    assert "n1 -->|flows to| n2" in mermaid

    finding = Finding(
        id="F001",
        rule_id="PAM002",
        title="Command Injection",
        description="Vulnerable call",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="app.py",
        line=12,
        end_line=12,
        col=4,
        end_col=16,
        snippet="os.system(u)",
        evidence="Tainted var reaches sink",
        remediation="Use subprocess.run without shell",
        cwe="CWE-78",
        dataflow=graph,
    )

    result = AnalysisResult(
        findings=[finding],
        statistics=ScanStatistics(files_scanned=1, total_findings=1),
    )

    assert len(result) == 1
    assert result[0].rule_id == "PAM002"
    assert len(result.filter(severity=Severity.HIGH)) == 1
    assert len(result.filter(severity=Severity.CRITICAL)) == 0
    assert len(result.filter(rule_id="PAM002")) == 1
    assert len(result.filter(rule_id="PAM001")) == 0

    # Test summary formatting
    summary = result.summary()
    assert "PyAttackMap Security Scan Summary" in summary
    assert "Total Findings: 1" in summary

    # Test to_json writing
    out_file = tmp_path / "out.json"
    written_path = result.to_json(out_file)
    assert Path(written_path).exists()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded["statistics"]["total_findings"] == 1
    assert loaded["findings"][0]["rule_id"] == "PAM002"

