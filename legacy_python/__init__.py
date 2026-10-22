"""PyAttackMap: Explainable Static Security Analysis and Data-Flow Visualization for Python.

Public API styled after high-quality Python scientific libraries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pyattackmap.analyzer import Analyzer
from pyattackmap.config import ScanConfig
from pyattackmap.exceptions import (
    ConfigError,
    FileAccessError,
    ParseError,
    PyAttackMapError,
    RuleError,
    ScanError,
)
from pyattackmap.models import (
    AnalysisError,
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
from pyattackmap.rules import Rule, RuleRegistry, default_registry, register_rule

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "scan",
    "scan_file",
    "scan_code",
    "Analyzer",
    "ScanConfig",
    "AnalysisResult",
    "Finding",
    "Severity",
    "Confidence",
    "DataFlowGraph",
    "DataFlowNode",
    "DataFlowEdge",
    "DataFlowNodeKind",
    "ScanStatistics",
    "AnalysisError",
    "Rule",
    "RuleRegistry",
    "default_registry",
    "register_rule",
    "PyAttackMapError",
    "ConfigError",
    "ParseError",
    "FileAccessError",
    "RuleError",
    "ScanError",
]


def scan(
    target: str | Path,
    config: ScanConfig | None = None,
    **kwargs: Any,
) -> AnalysisResult:
    """Scan a target directory or file using PyAttackMap.

    Parameters
    ----------
    target : str or Path
        Target directory or Python file to analyze.
    config : ScanConfig, optional
        Custom scan configuration. If omitted, default configuration is used.
    **kwargs : Any
        Override options for ScanConfig (e.g. min_severity="HIGH", exclude=[...]).

    Returns
    -------
    AnalysisResult
        Structured scan result containing findings, errors, and statistics.
    """
    if config is None:
        config = ScanConfig(**kwargs) if kwargs else ScanConfig()
    analyzer = Analyzer(config=config)
    return analyzer.scan(target)


def scan_file(
    file_path: str | Path,
    config: ScanConfig | None = None,
    **kwargs: Any,
) -> AnalysisResult:
    """Scan a single Python source file.

    Parameters
    ----------
    file_path : str or Path
        Path to the Python file to analyze.
    config : ScanConfig, optional
        Custom scan configuration.
    **kwargs : Any
        Override options for ScanConfig.

    Returns
    -------
    AnalysisResult
        Structured scan result for the file.
    """
    if config is None:
        config = ScanConfig(**kwargs) if kwargs else ScanConfig()
    analyzer = Analyzer(config=config)
    return analyzer.scan_file(file_path)


def scan_code(
    code: str,
    file_path: str = "<string>",
    config: ScanConfig | None = None,
    **kwargs: Any,
) -> AnalysisResult:
    """Scan Python source code provided directly as a string.

    Parameters
    ----------
    code : str
        Python source code string to analyze.
    file_path : str, optional
        Virtual file path associated with the snippet (default: '<string>').
    config : ScanConfig, optional
        Custom scan configuration.
    **kwargs : Any
        Override options for ScanConfig.

    Returns
    -------
    AnalysisResult
        Structured scan result for the snippet.
    """
    if config is None:
        config = ScanConfig(**kwargs) if kwargs else ScanConfig()
    analyzer = Analyzer(config=config)
    return analyzer.scan_code(code, file_path=file_path)

