"""Command-line interface for PyAttackMap built upon the library API."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from pyattackmap import __version__
from pyattackmap.analyzer import Analyzer
from pyattackmap.config import ScanConfig
from pyattackmap.exceptions import ConfigError, PyAttackMapError
from pyattackmap.models import Severity
from pyattackmap.reporting import JsonReporter, TextReporter
from pyattackmap.rules.registry import default_registry

EXIT_SUCCESS = 0
EXIT_FINDINGS_FOUND = 1
EXIT_USAGE_ERROR = 2
EXIT_EXECUTION_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyattackmap",
        description="PyAttackMap: Explainable Static Security Analysis and Data-Flow Visualization for Python",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Sub-commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan Python files or directories for security vulnerabilities")
    scan_parser.add_argument("target", help="File or directory path to scan")
    scan_parser.add_argument(
        "-s",
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity threshold (default: LOW)",
    )
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        help="Write report to specified output file path",
    )
    scan_parser.add_argument(
        "-e",
        "--exclude",
        action="append",
        default=[],
        help="Path or directory pattern to exclude (can be specified multiple times)",
    )
    scan_parser.add_argument(
        "--no-dataflow",
        action="store_true",
        help="Disable dataflow graph generation in findings",
    )

    # rules command
    subparsers.add_parser("rules", help="List all available static security rules")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    try:
        config = ScanConfig(
            min_severity=Severity.from_string(args.severity),
            exclude=ScanConfig().exclude + args.exclude,
            show_dataflow=not args.no_dataflow,
        )
    except ConfigError as ce:
        sys.stderr.write(f"Configuration error: {ce}\n")
        return EXIT_USAGE_ERROR

    analyzer = Analyzer(config=config)

    try:
        target_path = Path(args.target)
        if target_path.is_file():
            result = analyzer.scan_file(target_path)
        else:
            result = analyzer.scan(target_path)
    except FileNotFoundError as fnf:
        sys.stderr.write(f"Error: {fnf}\n")
        return EXIT_EXECUTION_ERROR
    except PyAttackMapError as pme:
        sys.stderr.write(f"Scan error: {pme}\n")
        return EXIT_EXECUTION_ERROR
    except Exception as exc:
        sys.stderr.write(f"Unexpected error: {exc}\n")
        return EXIT_EXECUTION_ERROR

    # Reporting
    if args.format == "json":
        json_output = JsonReporter.serialize(result)
        if args.output:
            Path(args.output).write_text(json_output, encoding="utf-8")
        else:
            sys.stdout.write(json_output + "\n")
    else:
        text_output = TextReporter.format_result(result)
        if args.output:
            Path(args.output).write_text(text_output, encoding="utf-8")
        else:
            sys.stdout.write(text_output + "\n")

    if len(result.findings) > 0:
        return EXIT_FINDINGS_FOUND
    return EXIT_SUCCESS


def run_rules() -> int:
    rules = default_registry.list_rules()
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write("Registered PyAttackMap Security Rules\n")
    sys.stdout.write("=" * 60 + "\n")
    for rule_cls in rules:
        cwe_str = f" | {rule_cls.cwe}" if getattr(rule_cls, "cwe", None) else ""
        sys.stdout.write(f"[{rule_cls.rule_id}] {rule_cls.title}\n")
        sys.stdout.write(f"  Severity: {rule_cls.severity.value} | Default Confidence: {rule_cls.default_confidence.value}{cwe_str}\n")
        sys.stdout.write(f"  Description: {rule_cls.description}\n\n")
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return EXIT_SUCCESS

    args = parser.parse_args(argv)

    if args.subcommand == "scan":
        return run_scan(args)
    elif args.subcommand == "rules":
        return run_rules()
    else:
        parser.print_help()
        return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())

