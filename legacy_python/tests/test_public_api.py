"""Tests verifying the stability and contracts of PyAttackMap's public API."""

import inspect
from pathlib import Path
import pytest

import pyattackmap as pam


def test_package_version_and_symbols() -> None:
    assert hasattr(pam, "__version__")
    assert isinstance(pam.__version__, str)
    assert pam.__version__ == "0.1.0"

    # Core public functions
    assert callable(pam.scan)
    assert callable(pam.scan_file)
    assert callable(pam.scan_code)

    # Core public classes
    assert inspect.isclass(pam.Analyzer)
    assert inspect.isclass(pam.ScanConfig)
    assert inspect.isclass(pam.AnalysisResult)
    assert inspect.isclass(pam.Finding)
    assert inspect.isclass(pam.Severity)
    assert inspect.isclass(pam.Confidence)
    assert inspect.isclass(pam.DataFlowGraph)

    # Exceptions
    assert issubclass(pam.ConfigError, pam.PyAttackMapError)
    assert issubclass(pam.ParseError, pam.PyAttackMapError)
    assert issubclass(pam.FileAccessError, pam.PyAttackMapError)


def test_public_scan_api_validations() -> None:
    with pytest.raises(ValueError):
        pam.scan("")

    with pytest.raises(FileNotFoundError):
        pam.scan("/non/existent/path/for/pyattackmap/testing")


def test_public_scan_code_basic() -> None:
    code = "import os; os.system('ls')"
    result = pam.scan_code(code)
    assert isinstance(result, pam.AnalysisResult)
    assert len(result) >= 1
    assert result.statistics.files_scanned == 1
    assert result.statistics.parse_errors == 0

