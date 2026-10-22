"""Tests for AST parsing and snippet extraction."""

from pathlib import Path
import pytest

from pyattackmap.exceptions import FileAccessError, ParseError
from pyattackmap.parser import SafeParser


def test_parse_valid_string() -> None:
    code = "def add(a, b):\n    return a + b\n"
    parsed = SafeParser.parse_string(code, file_path="math.py")
    assert parsed.file_path == "math.py"
    assert len(parsed.lines) == 2
    assert parsed.get_snippet(1, 2) == "def add(a, b):\n    return a + b"


def test_parse_syntax_error() -> None:
    broken = "def broken(:\n    pass"
    with pytest.raises(ParseError) as exc_info:
        SafeParser.parse_string(broken, file_path="bad.py")
    assert exc_info.value.line == 1
    assert "bad.py" in str(exc_info.value)


def test_parse_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "not_found.py"
    with pytest.raises(FileAccessError):
        SafeParser.parse_file(missing)


def test_parse_max_file_size(tmp_path: Path) -> None:
    large = tmp_path / "large.py"
    large.write_text("x = 1\n" * 1000, encoding="utf-8")
    # Restrict to very small max size (0.1 KB)
    with pytest.raises(FileAccessError):
        SafeParser.parse_file(large, max_size_kb=0.1)

