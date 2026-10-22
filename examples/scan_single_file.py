"""Example: Scanning a single Python file."""

from pathlib import Path
import pyattackmap as pam


def main() -> None:
    target_file = Path(__file__).parent / "sample_project" / "vulnerable.py"
    print(f"Scanning single file: {target_file}")

    result = pam.scan_file(target_file)

    print(f"Total findings: {len(result)}")
    for finding in result.findings:
        print(f"  {finding.file}:{finding.line} -> {finding.rule_id} ({finding.title})")


if __name__ == "__main__":
    main()

