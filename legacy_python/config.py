"""Configuration models and validator for PyAttackMap scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from pyattackmap.exceptions import ConfigError
from pyattackmap.models import Severity

DEFAULT_EXCLUDES: list[str] = [
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "dist",
    "build",
    "*.egg-info",
    "site-packages",
    "node_modules",
]


@dataclass
class ScanConfig:
    """Configuration options controlling scan scope, rules, and analysis parameters."""

    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    min_severity: Severity = Severity.LOW
    enabled_rules: list[str] | None = None
    disabled_rules: list[str] = field(default_factory=list)
    max_file_size_kb: int = 2048
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    show_dataflow: bool = True

    def __post_init__(self) -> None:
        # Validate min_severity
        if isinstance(self.min_severity, str):
            try:
                self.min_severity = Severity.from_string(self.min_severity)
            except ValueError as err:
                raise ConfigError(str(err)) from err
        elif not isinstance(self.min_severity, Severity):
            raise ConfigError(f"min_severity must be a Severity enum or valid string, got {type(self.min_severity)}")

        # Validate max_file_size_kb
        if not isinstance(self.max_file_size_kb, (int, float)) or self.max_file_size_kb <= 0:
            raise ConfigError(f"max_file_size_kb must be a positive number, got {self.max_file_size_kb}")
        self.max_file_size_kb = int(self.max_file_size_kb)

        # Validate lists
        if not isinstance(self.exclude, Sequence) or isinstance(self.exclude, str):
            raise ConfigError("exclude must be a sequence of string patterns")
        self.exclude = list(self.exclude)

        if self.enabled_rules is not None:
            if not isinstance(self.enabled_rules, Sequence) or isinstance(self.enabled_rules, str):
                raise ConfigError("enabled_rules must be a sequence of rule IDs or None")
            self.enabled_rules = [r.strip().upper() for r in self.enabled_rules]

        if not isinstance(self.disabled_rules, Sequence) or isinstance(self.disabled_rules, str):
            raise ConfigError("disabled_rules must be a sequence of rule IDs")
        self.disabled_rules = [r.strip().upper() for r in self.disabled_rules]

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Determine if a rule should be executed based on configuration."""
        clean_id = rule_id.strip().upper()
        if clean_id in self.disabled_rules:
            return False
        if self.enabled_rules is not None:
            return clean_id in self.enabled_rules
        return True

