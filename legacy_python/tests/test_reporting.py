"""Tests for text and JSON reporting outputs."""

import json
from pathlib import Path

from pyattackmap.models import (
    AnalysisError,
    AnalysisResult,
    Confidence,
    Finding,
    ScanStatistics,
    Severity,
)
from pyattackmap.reporting import JsonReporter, TextReporter


def test_text_reporter_formatting() -> None:
    finding = Finding(
        id="PAM001-test",
        rule_id="PAM001",
        title="SQL Injection",
        description="Dynamic query execution",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="app.py",
        line=15,
        end_line=15,
        col=4,
        end_col=20,
        snippet="cursor.execute(f'SELECT {x}')",
        evidence="Dynamic f-string in SQL execute",
        remediation="Use parameterized queries",
        cwe="CWE-89",
    )
    error = AnalysisError(file="bad.py", error_type="ParseError", message="Syntax error at line 1", line=1)
    result = AnalysisResult(
        findings=[finding],
        statistics=ScanStatistics(files_scanned=2, parse_errors=1, total_findings=1),
        errors=[error],
    )

    formatted = TextReporter.format_result(result)
    assert "PyAttackMap Security Scan Summary" in formatted
    assert "Analysis / Parse Errors" in formatted
    assert "bad.py:1: Syntax error" in formatted
    assert "[HIGH] PAM001: SQL Injection" in formatted
    assert "cursor.execute" in formatted


def test_json_reporter_file_write(tmp_path: Path) -> None:
    result = AnalysisResult(
        findings=[],
        statistics=ScanStatistics(files_scanned=5, total_findings=0),
        errors=[],
    )
    out_file = tmp_path / "report.json"
    written = JsonReporter.write_to_file(result, out_file)
    assert Path(written).exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["statistics"]["files_scanned"] == 5
    assert data["findings"] == []

