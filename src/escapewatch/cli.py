from __future__ import annotations

import argparse
import sys

from escapewatch import __version__
from escapewatch.models import Category, Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="escapewatch",
        description="Defensive container escape risk assessment framework",
        epilog="Example: escapewatch --format json --output report.json",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"escapewatch {__version__}",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["terminal", "compact", "json", "sarif"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--category", "-c",
        action="append",
        choices=[c.value for c in Category],
        help="Restrict to specific check categories (can be repeated)",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit non-zero if findings exceed threshold",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Minimum severity to trigger non-zero exit in CI mode (default: high)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    return parser


def severity_from_str(s: str) -> Severity:
    return Severity(s)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Import here to avoid import-time side effects
    from escapewatch.runner import run_assessment
    from escapewatch.formatters.terminal_fmt import TerminalFormatter
    from escapewatch.formatters.json_fmt import JSONFormatter
    from escapewatch.formatters.sarif_fmt import SARIFFormatter

    # Determine categories
    categories = None
    if args.category:
        categories = [Category(c) for c in args.category]

    # Run assessment
    result = run_assessment(categories=categories)

    # Format output
    if args.format == "json":
        formatter = JSONFormatter()
    elif args.format == "sarif":
        formatter = SARIFFormatter()
    elif args.format == "compact":
        formatter = TerminalFormatter(compact=True, no_color=args.no_color)
    else:
        formatter = TerminalFormatter(no_color=args.no_color)

    output_text = formatter.format(result)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
            f.write("\n")
        sys.stderr.write(f"Report written to {args.output}\n")
    else:
        print(output_text)

    # CI mode exit code
    if args.ci:
        threshold = severity_from_str(args.fail_on)
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        threshold_idx = severity_order.index(threshold)
        triggering = [
            f for f in result.findings
            if severity_order.index(f.severity) <= threshold_idx
        ]
        if triggering:
            sys.stderr.write(
                f"CI FAIL: {len(triggering)} finding(s) at or above "
                f"{threshold.value} severity\n"
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
