"""File discovery and path pattern filtering for PyAttackMap."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from pyattackmap.config import ScanConfig


def should_exclude(rel_path: str, exclude_patterns: list[str]) -> bool:
    """Check if relative path matches any exclusion pattern or contains excluded directory."""
    # Normalize separators
    normalized = rel_path.replace("\\", "/")
    parts = normalized.split("/")

    for pattern in exclude_patterns:
        pat = pattern.replace("\\", "/").rstrip("/")
        # Direct segment match (e.g. '.venv' in parts)
        if pat in parts:
            return True
        # Wildcard match against full relative path
        if fnmatch.fnmatch(normalized, pat) or fnmatch.fnmatch(normalized, f"*/{pat}/*") or fnmatch.fnmatch(normalized, f"{pat}/*"):
            return True
        # Match against filename
        if fnmatch.fnmatch(parts[-1], pat):
            return True

    return False


def discover_python_files(target: str | Path, config: ScanConfig) -> list[Path]:
    """Discover all eligible Python files at or under target path, applying exclusions."""
    base_path = Path(target).resolve()

    if not base_path.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")

    if base_path.is_file():
        # Single file target
        if base_path.suffix.lower() == ".py" or not base_path.suffix:
            # Check exclusions on filename
            if not should_exclude(base_path.name, config.exclude):
                return [base_path]
        return []

    discovered: list[Path] = []
    # Walk directory recursively
    for item in sorted(base_path.rglob("*.py")):
        if not item.is_file():
            continue
        try:
            rel_path = str(item.relative_to(base_path))
        except ValueError:
            rel_path = item.name

        if should_exclude(rel_path, config.exclude):
            continue

        discovered.append(item)

    return sorted(discovered)

