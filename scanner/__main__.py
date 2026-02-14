"""CLI entry point: python -m scanner [--json FILE] [--html FILE]"""

import argparse
import sys

from scanner.checks import run_all_checks
from scanner.report import print_report, export_json, export_html


def main() -> int:
    parser = argparse.ArgumentParser(
        description="macOS Säkerhetsskanner – analyserar nätverkssäkerhet"
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="Exportera resultat som JSON till angiven fil",
    )
    parser.add_argument(
        "--html", metavar="FILE",
        help="Exportera resultat som HTML till angiven fil",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Visa bara sammanfattningen i terminalen",
    )
    args = parser.parse_args()

    findings = run_all_checks()

    if not args.quiet:
        print_report(findings)

    if args.json:
        export_json(findings, args.json)

    if args.html:
        export_html(findings, args.html)

    # Exit code: 2 if red findings, 1 if yellow, 0 if all green
    severities = {f.severity.value for f in findings}
    if "red" in severities:
        return 2
    if "yellow" in severities:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
