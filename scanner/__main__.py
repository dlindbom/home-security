"""CLI entry point: python -m scanner [--json FILE] [--html FILE] [--no-browser]"""

import argparse
import os
import subprocess
import sys
import tempfile

from scanner.checks import run_all_checks
from scanner.report import print_report, export_json, export_html

_REPORT_DIR = os.path.join(tempfile.gettempdir(), "home-security")


def _open_in_browser(filepath: str) -> None:
    """Open a file in the default browser."""
    subprocess.Popen(["open", filepath],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
    parser.add_argument(
        "--no-browser", action="store_true",
        help="Öppna inte rapporterna i webbläsaren automatiskt",
    )
    args = parser.parse_args()

    findings = run_all_checks()

    if not args.quiet:
        print_report(findings)

    if args.json:
        export_json(findings, args.json)

    if args.html:
        export_html(findings, args.html)

    if not args.no_browser:
        # Auto-generate combined report and open it
        os.makedirs(_REPORT_DIR, exist_ok=True)
        report_path = os.path.join(_REPORT_DIR, "rapport.html")
        export_html(findings, report_path)

        print(f"  🌐 Öppnar säkerhetsrapport i webbläsaren…")
        _open_in_browser(report_path)

    # Exit code: 2 if red findings, 1 if yellow, 0 if all green
    severities = {f.severity.value for f in findings}
    if "red" in severities:
        return 2
    if "yellow" in severities:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
