"""Reporting utilities for text and structured representations of scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO
import sys

from pyattackmap.models import AnalysisResult, Finding, Severity


class TextReporter:
    """Formats AnalysisResult into readable, structured terminal output."""

    @staticmethod
    def format_finding(finding: Finding) -> str:
        lines: list[str] = [
            f"[{finding.severity.value}] {finding.rule_id}: {finding.title}",
            f"  Location  : {finding.file}:{finding.line}:{finding.col}",
            f"  Confidence: {finding.confidence.value} | CWE: {finding.cwe or 'N/A'}",
        ]
        if finding.snippet:
            lines.append("  Code Snippet:")
            for s_line in finding.snippet.splitlines():
                lines.append(f"    | {s_line}")
        if finding.evidence:
            lines.append(f"  Evidence  : {finding.evidence}")

        if finding.dataflow and finding.dataflow.nodes:
            lines.append("  Data-Flow Trace:")
            for node in finding.dataflow.nodes:
                lines.append(f"    --> [{node.kind.value}] {node.label} ({Path(node.file).name}:{node.line})")

        if finding.remediation:
            lines.append("  Remediation:")
            for r_line in finding.remediation.splitlines():
                lines.append(f"    {r_line}")

        return "\n".join(lines)

    @classmethod
    def render(cls, result: AnalysisResult, stream: TextIO = sys.stdout) -> None:
        """Render complete report to the specified stream."""
        output = cls.format_result(result)
        stream.write(output + "\n")

    @classmethod
    def format_result(cls, result: AnalysisResult) -> str:
        parts: list[str] = []
        parts.append(result.summary())

        if result.errors:
            parts.append("\n" + "=" * 60)
            parts.append("Analysis / Parse Errors")
            parts.append("=" * 60)
            for err in result.errors:
                loc = f"{err.file}:{err.line}" if err.line else err.file
                parts.append(f"  [{err.error_type}] {loc}: {err.message}")

        if result.findings:
            parts.append("\n" + "=" * 60)
            parts.append("Security Findings")
            parts.append("=" * 60)
            for finding in result.findings:
                parts.append(cls.format_finding(finding))
                parts.append("-" * 60)

        return "\n".join(parts)


class JsonReporter:
    """Serializes scan results into standardized JSON."""

    @staticmethod
    def serialize(result: AnalysisResult, indent: int = 2) -> str:
        return json.dumps(result.to_dict(), indent=indent, default=str)

    @classmethod
    def write_to_file(cls, result: AnalysisResult, file_path: str | Path, indent: int = 2) -> str:
        p = Path(file_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        content = cls.serialize(result, indent=indent)
        p.write_text(content, encoding="utf-8")
        return str(p)

