"""Example: Using custom analyzer configuration."""

from pathlib import Path
import pyattackmap as pam


def main() -> None:
    sample_dir = Path(__file__).parent / "sample_project"

    # Restrict scan to HIGH and CRITICAL findings only, and disable unsafe deserialization rule
    config = pam.ScanConfig(
        min_severity=pam.Severity.HIGH,
        disabled_rules=["PAM003"],
        exclude=["*.backup", "safe.py"],
    )

    analyzer = pam.Analyzer(config=config)
    result = analyzer.scan(sample_dir)

    print(result.summary())
    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.rule_id} at line {finding.line}")


if __name__ == "__main__":
    main()

