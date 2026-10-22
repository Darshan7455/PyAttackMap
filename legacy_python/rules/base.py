"""Base rule definition and interface for PyAttackMap analyzers."""

from __future__ import annotations

import abc
from pyattackmap.config import ScanConfig
from pyattackmap.models import Confidence, Finding, Severity
from pyattackmap.parser import ParsedSource


class Rule(abc.ABC):
    """Abstract base class for static security analysis rules."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    default_confidence: Confidence
    cwe: str | None = None

    @abc.abstractmethod
    def run(self, parsed: ParsedSource, config: ScanConfig) -> list[Finding]:
        """Execute rule analysis against parsed source code and return findings."""
        raise NotImplementedError

