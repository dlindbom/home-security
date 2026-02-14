"""Traffic light reporting: terminal formatting, JSON/HTML export."""

import json
import datetime
import platform
from collections import Counter

from scanner.utils import Finding, Severity


# ANSI color codes
_COLORS = {
    Severity.GREEN:  "\033[92m",
    Severity.YELLOW: "\033[93m",
    Severity.RED:    "\033[91m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_ICONS = {
    Severity.GREEN:  "🟢",
    Severity.YELLOW: "🟡",
    Severity.RED:    "🔴",
}

_LABELS = {
    Severity.GREEN:  "OK",
    Severity.YELLOW: "VARNING",
    Severity.RED:    "RISK",
}


def _colored(text: str, severity: Severity) -> str:
    return f"{_COLORS[severity]}{text}{_RESET}"


def print_header() -> None:
    """Print the scanner header with timestamp."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    node = platform.node()
    print()
    print(f"  {_BOLD}macOS Säkerhetsskanner v1.0{_RESET}")
    print(f"  {_DIM}{'─' * 40}{_RESET}")
    print(f"  {_DIM}Dator:{_RESET} {node}")
    print(f"  {_DIM}Tid:{_RESET}   {now}")
    print(f"  {_DIM}{'─' * 40}{_RESET}")
    print()


def print_section(title: str) -> None:
    """Print a section header."""
    print(f"  {_BOLD}▸ {title}{_RESET}")
    print()


def print_finding(finding: Finding) -> None:
    """Print a single finding with traffic light indicator."""
    icon = _ICONS[finding.severity]
    label = _LABELS[finding.severity]
    color = _COLORS[finding.severity]

    print(f"    {icon} {color}[{label}]{_RESET} {_BOLD}{finding.title}{_RESET}")
    if finding.description:
        for line in finding.description.splitlines():
            print(f"      {_DIM}{line}{_RESET}")
    if finding.recommendation:
        print(f"      💡 {finding.recommendation}")
    print()


def print_report(findings: list[Finding]) -> None:
    """Print the full report grouped by category."""
    print_header()

    # Group findings by category
    categories: dict[str, list[Finding]] = {}
    for f in findings:
        categories.setdefault(f.category, []).append(f)

    category_titles = {
        "firewall": "Brandvägg",
        "wifi": "WiFi-säkerhet",
        "dns": "DNS-konfiguration",
        "open_ports": "Öppna portar",
        "exposed_services": "Exponerade tjänster",
        "active_connections": "Aktiva anslutningar",
        "process": "Processanalys",
    }

    for cat, cat_findings in categories.items():
        title = category_titles.get(cat, cat.replace("_", " ").title())
        print_section(title)
        for f in cat_findings:
            print_finding(f)

    print_summary(findings)


def print_summary(findings: list[Finding]) -> None:
    """Print summary counts and overall verdict."""
    counts = Counter(f.severity for f in findings)
    g = counts.get(Severity.GREEN, 0)
    y = counts.get(Severity.YELLOW, 0)
    r = counts.get(Severity.RED, 0)

    print(f"  {_BOLD}{'─' * 40}{_RESET}")
    print(f"  {_BOLD}Sammanfattning{_RESET}")
    print(f"    🟢 Inga problem: {g}")
    print(f"    🟡 Bör ses över: {y}")
    print(f"    🔴 Åtgärda:      {r}")
    print()

    if r > 0:
        print(f"  {_COLORS[Severity.RED]}{_BOLD}⚠  {r} säkerhetsbrister hittades som bör åtgärdas.{_RESET}")
    elif y > 0:
        print(f"  {_COLORS[Severity.YELLOW]}{_BOLD}⚡ Inga akuta problem, men {y} saker kan förbättras.{_RESET}")
    else:
        print(f"  {_COLORS[Severity.GREEN]}{_BOLD}✓  Allt ser bra ut!{_RESET}")
    print()


def export_json(findings: list[Finding], filepath: str) -> None:
    """Export findings as structured JSON."""
    data = {
        "scanner": "macOS Säkerhetsskanner",
        "version": "1.0.0",
        "timestamp": datetime.datetime.now().isoformat(),
        "hostname": platform.node(),
        "findings": [
            {
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "recommendation": f.recommendation,
                "raw_data": f.raw_data,
            }
            for f in findings
        ],
        "summary": {
            "green": sum(1 for f in findings if f.severity == Severity.GREEN),
            "yellow": sum(1 for f in findings if f.severity == Severity.YELLOW),
            "red": sum(1 for f in findings if f.severity == Severity.RED),
        },
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"  📄 JSON exporterad till: {filepath}")


def export_html(findings: list[Finding], filepath: str) -> None:
    """Export findings as self-contained HTML with inline CSS."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_css = {
        "green": ("rgba(16,185,129,0.08)", "rgba(16,185,129,0.25)", "#10b981"),
        "yellow": ("rgba(245,158,11,0.06)", "rgba(245,158,11,0.2)", "#f59e0b"),
        "red": ("rgba(239,68,68,0.06)", "rgba(239,68,68,0.2)", "#ef4444"),
    }

    cards_html = []
    for f in findings:
        bg, border, dot = severity_css.get(f.severity.value, severity_css["yellow"])
        label = _LABELS[f.severity]
        rec_html = ""
        if f.recommendation:
            rec_html = f"""<div style="margin-top:12px;padding:10px 14px;border-radius:8px;
                background:rgba(255,255,255,0.03);border-left:3px solid {dot};
                font-size:13px;color:#cbd5e1;line-height:1.6">
                <strong>Rekommendation:</strong> {_escape_html(f.recommendation)}</div>"""

        desc_html = _escape_html(f.description).replace("\n", "<br>")

        cards_html.append(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:14px;padding:20px 24px;margin-bottom:14px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                <strong style="color:#e2e8f0;font-size:15px">{_escape_html(f.title)}</strong>
                <span style="background:{bg};border:1px solid {border};color:{dot};
                    padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600">{label}</span>
            </div>
            <div style="font-size:13px;color:#94a3b8;line-height:1.6">{desc_html}</div>
            {rec_html}
        </div>""")

    counts = Counter(f.severity for f in findings)
    g = counts.get(Severity.GREEN, 0)
    y = counts.get(Severity.YELLOW, 0)
    r = counts.get(Severity.RED, 0)

    html = f"""<!DOCTYPE html>
<html lang="sv">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Säkerhetsrapport – {now}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ min-height: 100vh; background: #0c0e14; color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    padding: 40px 20px; }}
  .wrap {{ max-width: 700px; margin: 0 auto; }}
  h1 {{ font-size: 24px; font-weight: 800; margin-bottom: 6px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 28px; }}
  .summary {{ display: flex; gap: 20px; margin-bottom: 28px; }}
  .stat {{ font-size: 14px; color: #94a3b8; }}
  .stat strong {{ color: #e2e8f0; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>macOS Sakerhetsrapport</h1>
  <div class="meta">{now} &middot; {platform.node()}</div>
  <div class="summary">
    <div class="stat">🟢 Inga problem: <strong>{g}</strong></div>
    <div class="stat">🟡 Bor ses over: <strong>{y}</strong></div>
    <div class="stat">🔴 Atgarda: <strong>{r}</strong></div>
  </div>
  {"".join(cards_html)}
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"  🌐 HTML exporterad till: {filepath}")


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
