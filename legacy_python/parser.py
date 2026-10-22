"""Safe AST parser and source snippet extractor for PyAttackMap."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from pyattackmap.exceptions import FileAccessError, ParseError


@dataclass
class ParsedSource:
    """Encapsulates parsed AST, original source lines, and file identity."""

    file_path: str
    source_code: str
    lines: list[str]
    tree: ast.AST

    def get_snippet(self, start_line: int, end_line: int | None = None) -> str:
        """Extract lines of code as a trimmed snippet (1-indexed)."""
        if not self.lines or start_line < 1:
            return ""
        end = end_line if end_line is not None and end_line >= start_line else start_line
        idx_start = max(0, start_line - 1)
        idx_end = min(len(self.lines), end)
        return "\n".join(self.lines[idx_start:idx_end])


class SafeParser:
    """Parser that safely converts source code into AST with diagnostics."""

    @staticmethod
    def parse_string(code: str, file_path: str = "<string>") -> ParsedSource:
        """Parse source string into ParsedSource, raising ParseError on syntax error."""
        try:
            tree = ast.parse(code, filename=file_path)
            lines = code.splitlines()
            return ParsedSource(file_path=file_path, source_code=code, lines=lines, tree=tree)
        except SyntaxError as e:
            raise ParseError(
                file_path=file_path,
                message=e.msg,
                line=e.lineno,
            ) from e

    @classmethod
    def parse_file(cls, path: str | Path, max_size_kb: int = 2048) -> ParsedSource:
        """Read and parse a file from disk with size and encoding checks."""
        target = Path(path).resolve()
        if not target.exists():
            raise FileAccessError(f"Target file does not exist: {path}")

        try:
            size_kb = target.stat().st_size / 1024.0
            if size_kb > max_size_kb:
                raise FileAccessError(
                    f"File '{target}' exceeds maximum allowed size ({size_kb:.1f} KB > {max_size_kb} KB)"
                )

            # Read with utf-8 and fallback replacement
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise FileAccessError(f"Cannot read file '{target}': {e}") from e

        return cls.parse_string(content, file_path=str(target))

