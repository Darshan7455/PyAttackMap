"""Tests for Analyzer orchestration, file exclusions, and scan statistics."""

from pathlib import Path
import pytest

from pyattackmap.analyzer import Analyzer
from pyattackmap.config import ScanConfig
from pyattackmap.models import Severity


def test_analyzer_scan_directory(fixtures_dir: Path) -> None:
    analyzer = Analyzer(config=ScanConfig(min_severity="LOW"))
    result = analyzer.scan(fixtures_dir)

    assert result.statistics.files_scanned >= 6
    assert len(result.findings) >= 6
    assert result.statistics.parse_errors == 0
    assert result.statistics.duration_seconds > 0


def test_analyzer_scan_file(vulnerable_dir: Path) -> None:
    analyzer = Analyzer()
    result = analyzer.scan_file(vulnerable_dir / "sql_injection.py")

    assert result.statistics.files_scanned == 1
    assert len(result.findings) >= 2


def test_analyzer_file_exclusions(fixtures_dir: Path) -> None:
    # Exclude vulnerable folder entirely
    config = ScanConfig(exclude=["vulnerable", "vulnerable/*"])
    analyzer = Analyzer(config=config)
    result = analyzer.scan(fixtures_dir)

    # Only safe fixtures scanned, 0 findings
    assert len(result.findings) == 0
    assert result.statistics.files_scanned >= 3


def test_analyzer_handles_syntax_error_gracefully(tmp_path: Path) -> None:
    good_file = tmp_path / "good.py"
    good_file.write_text("import os; os.system('ls')", encoding="utf-8")
    bad_file = tmp_path / "bad.py"
    bad_file.write_text("def broken(:\n    pass", encoding="utf-8")

    analyzer = Analyzer()
    result = analyzer.scan(tmp_path)

    assert result.statistics.files_scanned == 2
    assert result.statistics.parse_errors == 1
    assert len(result.errors) == 1
    assert result.errors[0].error_type == "ParseError"
    # The valid file was still analyzed successfully!
    assert len(result.findings) >= 1

