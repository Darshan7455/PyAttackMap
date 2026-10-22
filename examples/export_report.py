"""Example: Exporting analysis results to JSON file."""

from pathlib import Path
import pyattackmap as pam


def main() -> None:
    sample_dir = Path(__file__).parent / "sample_project"
    output_path = Path(__file__).parent / "scan_report.json"

    result = pam.scan(sample_dir)

    # Export report to JSON on disk
    written = result.to_json(output_path)
    print(f"Report written to: {written}")

    # Inspect statistics programmatically
    report_dict = result.to_dict()
    print("Statistics dictionary:")
    print(report_dict["statistics"])


if __name__ == "__main__":
    main()

