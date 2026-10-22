"""Tests for security rules PAM001, PAM002, and PAM003."""

from pathlib import Path
import pytest

from pyattackmap.config import ScanConfig
from pyattackmap.models import Confidence, Severity
from pyattackmap.parser import SafeParser
from pyattackmap.rules.command_injection import CommandInjectionRule
from pyattackmap.rules.sql_injection import SqlInjectionRule
from pyattackmap.rules.unsafe_deserialization import UnsafeDeserializationRule


def test_pam001_sql_injection_vulnerable_and_safe(vulnerable_dir: Path, safe_dir: Path) -> None:
    rule = SqlInjectionRule()
    config = ScanConfig(min_severity="LOW")

    # Vulnerable fixture
    vuln_parsed = SafeParser.parse_file(vulnerable_dir / "sql_injection.py")
    findings = rule.run(vuln_parsed, config)
    assert len(findings) >= 2
    for f in findings:
        assert f.rule_id == "PAM001"
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-89"

    # Safe fixture
    safe_parsed = SafeParser.parse_file(safe_dir / "parameterized_sql.py")
    safe_findings = rule.run(safe_parsed, config)
    assert len(safe_findings) == 0


def test_pam002_command_injection_vulnerable_and_safe(vulnerable_dir: Path, safe_dir: Path) -> None:
    rule = CommandInjectionRule()
    config = ScanConfig(min_severity="LOW")

    # Vulnerable fixture
    vuln_parsed = SafeParser.parse_file(vulnerable_dir / "command_injection.py")
    findings = rule.run(vuln_parsed, config)
    assert len(findings) >= 2
    for f in findings:
        assert f.rule_id == "PAM002"
        assert f.cwe == "CWE-78"

    # Safe fixture
    safe_parsed = SafeParser.parse_file(safe_dir / "safe_subprocess.py")
    safe_findings = rule.run(safe_parsed, config)
    assert len(safe_findings) == 0


def test_pam003_unsafe_deserialization_vulnerable_and_safe(vulnerable_dir: Path, safe_dir: Path) -> None:
    rule = UnsafeDeserializationRule()
    config = ScanConfig(min_severity="LOW")

    # Vulnerable fixture
    vuln_parsed = SafeParser.parse_file(vulnerable_dir / "unsafe_deserialization.py")
    findings = rule.run(vuln_parsed, config)
    assert len(findings) >= 2
    # Verify tainted one gets HIGH confidence
    tainted_finding = next((f for f in findings if f.confidence == Confidence.HIGH), None)
    assert tainted_finding is not None
    assert tainted_finding.cwe == "CWE-502"

    # Safe fixture
    safe_parsed = SafeParser.parse_file(safe_dir / "safe_json.py")
    safe_findings = rule.run(safe_parsed, config)
    assert len(safe_findings) == 0


def test_command_injection_with_shlex_quote_is_safe() -> None:
    code = """
import os, shlex

def safe_cmd():
    raw = input()
    clean = shlex.quote(raw)
    os.system("echo " + clean)
"""
    rule = CommandInjectionRule()
    parsed = SafeParser.parse_string(code, "safe_quote.py")
    findings = rule.run(parsed, ScanConfig(min_severity="LOW"))
    assert len(findings) == 0


def test_config_case_insensitive_rules() -> None:
    config = ScanConfig(enabled_rules=["pam001", "PAM002"])
    assert config.is_rule_enabled("pam001") is True
    assert config.is_rule_enabled("PAM001") is True
    assert config.is_rule_enabled("PAM002") is True
    assert config.is_rule_enabled("PAM003") is False

