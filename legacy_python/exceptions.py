"""Custom exception hierarchy for PyAttackMap."""

from __future__ import annotations


class PyAttackMapError(Exception):
    """Base exception for all PyAttackMap errors."""


class ConfigError(PyAttackMapError):
    """Raised when scan configuration is invalid."""


class ParseError(PyAttackMapError):
    """Raised when source code cannot be parsed into an AST."""

    def __init__(self, file_path: str, message: str, line: int | None = None) -> None:
        self.file_path = file_path
        self.line = line
        prefix = f"Failed to parse '{file_path}'"
        if line is not None:
            prefix += f" at line {line}"
        super().__init__(f"{prefix}: {message}")


class FileAccessError(PyAttackMapError):
    """Raised when a file cannot be read due to permissions or missing path."""


class RuleError(PyAttackMapError):
    """Raised when a security rule fails execution or has invalid definition."""


class ScanError(PyAttackMapError):
    """Raised when scanning encounters an unrecoverable runtime issue."""

