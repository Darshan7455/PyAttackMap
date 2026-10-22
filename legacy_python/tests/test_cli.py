"""Tests for PyAttackMap command-line interface execution and exit codes."""

from pathlib import Path
import pytest

from pyattackmap.cli import (
    EXIT_EXECUTION_ERROR,
    EXIT_FINDINGS_FOUND,
    EXIT_SUCCESS,
    main,
)


def test_cli_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["rules"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "PAM001" in captured.out
    assert "PAM002" in captured.out
    assert "PAM003" in captured.out


def test_cli_scan_clean(capsys: pytest.CaptureFixture[str], safe_dir: Path) -> None:
    code = main(["scan", str(safe_dir)])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "Total Findings: 0" in captured.out


def test_cli_scan_findings(capsys: pytest.CaptureFixture[str], vulnerable_dir: Path) -> None:
    code = main(["scan", str(vulnerable_dir)])
    assert code == EXIT_FINDINGS_FOUND
    captured = capsys.readouterr()
    assert "Total Findings:" in captured.out
    assert "PAM001" in captured.out


def test_cli_scan_invalid_path(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "this_path_does_not_exist_xyz"])
    assert code == EXIT_EXECUTION_ERROR
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_scan_json_output(capsys: pytest.CaptureFixture[str], safe_dir: Path) -> None:
    code = main(["scan", str(safe_dir), "--format", "json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert '"statistics"' in captured.out
    assert '"findings": []' in captured.out

