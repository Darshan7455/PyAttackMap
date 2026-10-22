"""Example: Basic recursive scanning of a directory."""

from pathlib import Path
import pyattackmap as pam


def main() -> None:
    sample_dir = Path(__file__).parent / "sample_project"
    print(f"Scanning target directory: {sample_dir}")

    result = pam.scan(sample_dir)

    print(result.summary())

    for finding in result.findings:
        print(f"\n[{finding.severity.value}] {finding.rule_id}: {finding.title}")
        print(f"  File: {finding.file}:{finding.line}")
        print(f"  Confidence: {finding.confidence.value} | CWE: {finding.cwe}")


if __name__ == "__main__":
    main()

