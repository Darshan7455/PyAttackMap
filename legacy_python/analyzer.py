"""Core Analyzer orchestrator for static security analysis."""

from __future__ import annotations

import time
from pathlib import Path

from pyattackmap.config import ScanConfig
from pyattackmap.exceptions import ConfigError, FileAccessError, ParseError
from pyattackmap.models import (
    AnalysisError,
    AnalysisResult,
    Finding,
    ScanStatistics,
    Severity,
)
from pyattackmap.parser import SafeParser
from pyattackmap.paths import discover_python_files
from pyattackmap.rules.registry import RuleRegistry, default_registry


class Analyzer:
    """Orchestrates file discovery, parsing, rule execution, and finding aggregation."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        registry: RuleRegistry | None = None,
    ) -> None:
        self.config: ScanConfig = config if config is not None else ScanConfig()
        self.registry: RuleRegistry = registry if registry is not None else default_registry

    def scan(self, target: str | Path) -> AnalysisResult:
        """Scan a file or directory recursively."""
        if not target:
            raise ValueError("Target path must not be empty")

        target_path = Path(target)
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        start_time = time.perf_counter()
        files = discover_python_files(target_path, self.config)

        all_findings: list[Finding] = []
        all_errors: list[AnalysisError] = []
        files_scanned = 0
        parse_errors_count = 0

        rules = self.registry.get_enabled_instances(self.config)

        for file_path in files:
            files_scanned += 1
            try:
                parsed = SafeParser.parse_file(file_path, max_size_kb=self.config.max_file_size_kb)
            except ParseError as pe:
                parse_errors_count += 1
                all_errors.append(
                    AnalysisError(
                        file=pe.file_path,
                        error_type="ParseError",
                        message=str(pe),
                        line=pe.line,
                    )
                )
                continue
            except FileAccessError as fae:
                all_errors.append(
                    AnalysisError(
                        file=str(file_path),
                        error_type="FileAccessError",
                        message=str(fae),
                    )
                )
                continue
            except Exception as e:
                all_errors.append(
                    AnalysisError(
                        file=str(file_path),
                        error_type="UnexpectedError",
                        message=str(e),
                    )
                )
                continue

            # Execute rules on parsed AST
            for rule in rules:
                try:
                    rule_findings = rule.run(parsed, self.config)
                    for f in rule_findings:
                        # Check minimum severity threshold
                        if f.severity >= self.config.min_severity:
                            all_findings.append(f)
                except Exception as ex:
                    all_errors.append(
                        AnalysisError(
                            file=str(file_path),
                            error_type="RuleExecutionError",
                            message=f"Rule {rule.rule_id} failed: {ex}",
                        )
                    )

        # Deduplicate findings by unique ID
        deduped: dict[str, Finding] = {}
        for f in all_findings:
            if f.id not in deduped:
                deduped[f.id] = f

        # Stable sort: file path, line, column
        sorted_findings = sorted(deduped.values(), key=lambda f: (f.file, f.line, f.col))

        duration = time.perf_counter() - start_time

        # Compile statistics
        sev_counts: dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for f in sorted_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        stats = ScanStatistics(
            files_scanned=files_scanned,
            files_skipped=0,
            parse_errors=parse_errors_count,
            total_findings=len(sorted_findings),
            findings_by_severity=sev_counts,
            duration_seconds=duration,
        )

        return AnalysisResult(
            findings=sorted_findings,
            statistics=stats,
            errors=all_errors,
        )

    def scan_file(self, file_path: str | Path) -> AnalysisResult:
        """Scan a single Python file."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        return self.scan(p)

    def scan_code(self, code: str, file_path: str = "<string>") -> AnalysisResult:
        """Scan Python code provided directly as a string."""
        start_time = time.perf_counter()
        all_findings: list[Finding] = []
        all_errors: list[AnalysisError] = []

        try:
            parsed = SafeParser.parse_string(code, file_path=file_path)
        except ParseError as pe:
            all_errors.append(
                AnalysisError(
                    file=pe.file_path,
                    error_type="ParseError",
                    message=str(pe),
                    line=pe.line,
                )
            )
            stats = ScanStatistics(
                files_scanned=1,
                files_skipped=0,
                parse_errors=1,
                total_findings=0,
                duration_seconds=time.perf_counter() - start_time,
            )
            return AnalysisResult(findings=[], statistics=stats, errors=all_errors)

        rules = self.registry.get_enabled_instances(self.config)
        for rule in rules:
            try:
                rule_findings = rule.run(parsed, self.config)
                for f in rule_findings:
                    if f.severity >= self.config.min_severity:
                        all_findings.append(f)
            except Exception as ex:
                all_errors.append(
                    AnalysisError(
                        file=file_path,
                        error_type="RuleExecutionError",
                        message=f"Rule {rule.rule_id} failed: {ex}",
                    )
                )

        deduped: dict[str, Finding] = {}
        for f in all_findings:
            if f.id not in deduped:
                deduped[f.id] = f

        sorted_findings = sorted(deduped.values(), key=lambda f: (f.file, f.line, f.col))
        duration = time.perf_counter() - start_time

        sev_counts: dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for f in sorted_findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        stats = ScanStatistics(
            files_scanned=1,
            files_skipped=0,
            parse_errors=0,
            total_findings=len(sorted_findings),
            findings_by_severity=sev_counts,
            duration_seconds=duration,
        )

        return AnalysisResult(
            findings=sorted_findings,
            statistics=stats,
            errors=all_errors,
        )

