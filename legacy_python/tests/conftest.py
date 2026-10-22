"""Pytest fixtures and configuration for PyAttackMap tests."""

from pathlib import Path
import pytest

from pyattackmap.config import ScanConfig


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def vulnerable_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "vulnerable"


@pytest.fixture
def safe_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "safe"


@pytest.fixture
def default_config() -> ScanConfig:
    return ScanConfig(min_severity="INFO", exclude=[])

