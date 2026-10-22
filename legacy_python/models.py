"""Core data models, enums, and result containers for PyAttackMap."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Sequence


class Severity(str, Enum):
    """Vulnerability severity representing potential security impact."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return ranks[self]

    def __ge__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity.from_string(other)
        return self.rank >= other.rank

    def __gt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity.from_string(other)
        return self.rank > other.rank

    def __le__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity.from_string(other)
        return self.rank <= other.rank

    def __lt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity.from_string(other)
        return self.rank < other.rank

    @classmethod
    def from_string(cls, val: str) -> Severity:
        cleaned = val.strip().upper()
        try:
            return cls[cleaned]
        except KeyError:
            valid = ", ".join(f"'{m.name}'" for m in cls)
            raise ValueError(f"Invalid severity '{val}'. Must be one of: {valid}") from None


class Confidence(str, Enum):
    """Confidence level indicating the certainty of an analyzer finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        ranks = {
            Confidence.LOW: 1,
            Confidence.MEDIUM: 2,
            Confidence.HIGH: 3,
        }
        return ranks[self]

    @classmethod
    def from_string(cls, val: str) -> Confidence:
        cleaned = val.strip().upper()
        try:
            return cls[cleaned]
        except KeyError:
            valid = ", ".join(f"'{m.name}'" for m in cls)
            raise ValueError(f"Invalid confidence '{val}'. Must be one of: {valid}") from None


class DataFlowNodeKind(str, Enum):
    """Categorization of a node within an intra-procedural data-flow trace."""

    SOURCE = "SOURCE"
    PROPAGATION = "PROPAGATION"
    SANITIZER = "SANITIZER"
    SINK = "SINK"


@dataclass(frozen=True)
class DataFlowNode:
    """A discrete operation or variable node in the data-flow path."""

    id: str
    kind: DataFlowNodeKind
    file: str
    line: int
    col: int
    label: str
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "label": self.label,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class DataFlowEdge:
    """A directed edge representing data movement between two nodes."""

    source_id: str
    target_id: str
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "label": self.label,
        }


@dataclass
class DataFlowGraph:
    """Directed graph representing intra-procedural taint propagation."""

    nodes: list[DataFlowNode] = field(default_factory=list)
    edges: list[DataFlowEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_mermaid(self) -> str:
        """Render data-flow graph as a Mermaid flowchart diagram."""
        lines = ["flowchart TD"]
        for node in self.nodes:
            clean_label = node.label.replace('"', "'")
            lines.append(f'    {node.id}["[{node.kind.value}] {clean_label} (L{node.line})"]')
        for edge in self.edges:
            if edge.label:
                lines.append(f"    {edge.source_id} -->|{edge.label}| {edge.target_id}")
            else:
                lines.append(f"    {edge.source_id} --> {edge.target_id}")
        return "\n".join(lines)


@dataclass
class Finding:
    """Represents a discrete security finding detected by an AST or taint rule."""

    id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    end_line: int
    col: int
    end_col: int
    snippet: str
    evidence: str
    remediation: str
    cwe: str | None = None
    dataflow: DataFlowGraph | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "col": self.col,
            "end_col": self.end_col,
            "snippet": self.snippet,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "dataflow": self.dataflow.to_dict() if self.dataflow is not None else None,
            "metadata": self.metadata,
        }


@dataclass
class ScanStatistics:
    """Statistical summary of a scan execution."""

    files_scanned: int = 0
    files_skipped: int = 0
    parse_errors: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(
        default_factory=lambda: {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
    )
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisError:
    """Represents an error encountered while reading or parsing a file."""

    file: str
    error_type: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AnalysisResult:
    """Container holding findings, execution errors, and scan statistics."""

    def __init__(
        self,
        findings: Sequence[Finding] | None = None,
        statistics: ScanStatistics | None = None,
        errors: Sequence[AnalysisError] | None = None,
    ) -> None:
        self.findings: list[Finding] = list(findings or [])
        self.statistics: ScanStatistics = statistics or ScanStatistics()
        self.errors: list[AnalysisError] = list(errors or [])

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __getitem__(self, index: int) -> Finding:
        return self.findings[index]

    def filter(
        self,
        severity: Severity | str | None = None,
        rule_id: str | None = None,
    ) -> list[Finding]:
        """Filter findings by exact rule ID and/or minimum severity."""
        target_sev: Severity | None = None
        if severity is not None:
            target_sev = (
                Severity.from_string(severity)
                if isinstance(severity, str)
                else severity
            )

        matched: list[Finding] = []
        for finding in self.findings:
            if target_sev is not None and finding.severity < target_sev:
                continue
            if rule_id is not None and finding.rule_id != rule_id:
                continue
            matched.append(finding)
        return matched

    def summary(self) -> str:
        """Produce a clean human-readable summary of scan results."""
        lines = [
            "=" * 60,
            "PyAttackMap Security Scan Summary",
            "=" * 60,
            f"Files Scanned : {self.statistics.files_scanned}",
            f"Files Skipped : {self.statistics.files_skipped}",
            f"Parse Errors  : {self.statistics.parse_errors}",
            f"Scan Duration : {self.statistics.duration_seconds:.3f}s",
            "-" * 60,
            f"Total Findings: {len(self.findings)}",
        ]
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            cnt = self.statistics.findings_by_severity.get(sev.value, 0)
            lines.append(f"  - {sev.value:<10}: {cnt}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete analysis result to a JSON-compatible dictionary."""
        return {
            "statistics": self.statistics.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": [e.to_dict() for e in self.errors],
        }

    def to_json(self, path: str | Path | None = None, indent: int = 2) -> str:
        """Serialize results to JSON. If path is provided, writes to file and returns path."""
        data = self.to_dict()
        serialized = json.dumps(data, indent=indent, default=str)
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(serialized, encoding="utf-8")
            return str(p)
        return serialized

