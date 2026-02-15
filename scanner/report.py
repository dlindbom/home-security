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


def print_report(findings: list) -> None:
    """Print the full report grouped by category."""
    print_header()

    # Group findings by category
    categories = {}
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
        "traffic": "Trafikanalys",
        "system": "Systemsäkerhet",
        "network_advanced": "Nätverksanalys",
        "home_network": "Hemnätverk",
    }

    for cat, cat_findings in categories.items():
        title = category_titles.get(cat, cat.replace("_", " ").title())
        print_section(title)
        for f in cat_findings:
            print_finding(f)

    print_summary(findings)


def print_summary(findings: list) -> None:
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


def export_json(findings: list, filepath: str) -> None:
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


# ─── AI-analys ────────────────────────────────────────────────────────────────

def _generate_ai_summary(findings: list) -> str:
    """Generate a deterministic AI-style analysis summary as HTML."""
    cats = {}
    for f in findings:
        cats.setdefault(f.category, []).append(f)

    counts = Counter(f.severity for f in findings)
    g = counts.get(Severity.GREEN, 0)
    y = counts.get(Severity.YELLOW, 0)
    r = counts.get(Severity.RED, 0)
    total = g + y + r

    # --- Overall grade ---
    if r >= 3:
        grade = "Kritiskt"
        grade_color = "#ef4444"
        grade_icon = "🔴"
        grade_text = "Flera allvarliga säkerhetsbrister har identifierats som behöver åtgärdas omedelbart."
    elif r >= 1:
        grade = "Förbättra"
        grade_color = "#ef4444"
        grade_icon = "🔴"
        grade_text = "Säkerhetsrisker har hittats som bör åtgärdas snarast."
    elif y >= 5:
        grade = "Acceptabelt"
        grade_color = "#f59e0b"
        grade_icon = "🟡"
        grade_text = "Grundsäkerheten är på plats, men det finns flera förbättringsmöjligheter."
    elif y >= 1:
        grade = "Bra"
        grade_color = "#10b981"
        grade_icon = "🟢"
        grade_text = "Bra säkerhetsläge med några mindre förbättringsmöjligheter."
    else:
        grade = "Utmärkt"
        grade_color = "#10b981"
        grade_icon = "🟢"
        grade_text = "Utmärkt säkerhetsläge. Alla kontroller passerade utan anmärkning."

    sections = []

    # --- Grade header ---
    sections.append(
        f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:18px">'
        f'<span style="font-size:28px">{grade_icon}</span>'
        f'<div>'
        f'<div style="font-size:18px;font-weight:800;color:{grade_color}">{grade}</div>'
        f'<div style="font-size:13px;color:#94a3b8">{grade_text}</div>'
        f'</div></div>'
    )

    # --- Firewall & Network ---
    fw_findings = cats.get("firewall", []) + cats.get("wifi", []) + cats.get("dns", [])
    if fw_findings:
        items = []
        for f in fw_findings:
            icon = "✅" if f.severity == Severity.GREEN else "⚠️" if f.severity == Severity.YELLOW else "❌"
            items.append(f"{icon} {_escape_html(f.title)}: {_escape_html(f.description.split(chr(10))[0])}")
        sections.append(_ai_section("🔒 Nätverksskydd", items))

    # --- Ports & connections ---
    port_findings = cats.get("open_ports", [])
    conn_findings = cats.get("active_connections", [])
    if port_findings or conn_findings:
        items = []
        risky_ports = [f for f in port_findings if f.severity != Severity.GREEN]
        safe_ports = [f for f in port_findings if f.severity == Severity.GREEN]
        if risky_ports:
            items.append(f"⚠️ {len(risky_ports)} port{'ar' if len(risky_ports) > 1 else ''} lyssnar på alla gränssnitt och bör granskas")
        if safe_ports:
            items.append(f"✅ {len(safe_ports)} port{'ar' if len(safe_ports) > 1 else ''} lyssnar enbart lokalt")
        for f in conn_findings:
            if f.severity == Severity.GREEN:
                items.append(f"✅ {_escape_html(f.description.split(chr(10))[0])}")
        ext_conns = [f for f in conn_findings if f.severity != Severity.GREEN]
        if ext_conns:
            items.append(f"⚠️ {len(ext_conns)} externa anslutningar flaggade för granskning")
        sections.append(_ai_section("🚪 Portar & Anslutningar", items))

    # --- Traffic analysis ---
    traffic_findings = cats.get("traffic", [])
    if traffic_findings:
        items = []
        for f in traffic_findings:
            icon = "✅" if f.severity == Severity.GREEN else "⚠️" if f.severity == Severity.YELLOW else "❌"
            first_line = f.description.split("\n")[0] if f.description else f.title
            items.append(f"{icon} {_escape_html(f.title)}: {_escape_html(first_line)}")
        sections.append(_ai_section("📡 Trafikanalys", items))

    # --- Process analysis ---
    proc_findings = cats.get("process", [])
    if proc_findings:
        items = []
        for f in proc_findings:
            icon = "✅" if f.severity == Severity.GREEN else "⚠️" if f.severity == Severity.YELLOW else "❌"
            items.append(f"{icon} {_escape_html(f.description.split(chr(10))[0])}")
        sections.append(_ai_section("⚙️ Processer", items))

    # --- System security ---
    sys_findings = cats.get("system", [])
    if sys_findings:
        items = []
        for f in sys_findings:
            icon = "✅" if f.severity == Severity.GREEN else "⚠️" if f.severity == Severity.YELLOW else "❌"
            items.append(f"{icon} {_escape_html(f.title)}: {_escape_html(f.description.split(chr(10))[0])}")
        sections.append(_ai_section("🖥️ Systemsäkerhet", items))

    # --- ARP / network advanced ---
    arp_findings = cats.get("network_advanced", [])
    if arp_findings:
        items = []
        for f in arp_findings:
            icon = "✅" if f.severity == Severity.GREEN else "⚠️" if f.severity == Severity.YELLOW else "❌"
            items.append(f"{icon} {_escape_html(f.title)}: {_escape_html(f.description.split(chr(10))[0])}")
        sections.append(_ai_section("🔬 Nätverksanalys", items))

    # --- Home network ---
    home_findings = cats.get("home_network", [])
    if home_findings:
        items = []
        for f in home_findings:
            icon = "✅" if f.severity == Severity.GREEN else "⚠️" if f.severity == Severity.YELLOW else "❌"
            items.append(f"{icon} {_escape_html(f.title)}: {_escape_html(f.description.split(chr(10))[0])}")
        sections.append(_ai_section("🏠 Hemnätverk", items))

    # --- Recommendations ---
    recs = []
    red_findings = [f for f in findings if f.severity == Severity.RED and f.recommendation]
    yellow_findings = [f for f in findings if f.severity == Severity.YELLOW and f.recommendation]
    for f in red_findings[:5]:
        recs.append(f'<span style="color:#ef4444">❌</span> {_escape_html(f.recommendation)}')
    for f in yellow_findings[:5]:
        recs.append(f'<span style="color:#f59e0b">⚠️</span> {_escape_html(f.recommendation)}')
    if recs:
        sections.append(_ai_section("💡 Prioriterade rekommendationer", recs))

    return "\n".join(sections)


def _ai_section(title: str, items: list) -> str:
    """Render one section of the AI analysis."""
    li = "".join(
        f'<div style="font-size:13px;color:#cbd5e1;padding:4px 0;line-height:1.5">{item}</div>'
        for item in items
    )
    return (
        f'<div style="margin-bottom:16px">'
        f'<div style="font-size:14px;font-weight:700;margin-bottom:6px;color:#e2e8f0">{title}</div>'
        f'{li}</div>'
    )


# ─── HTML export ──────────────────────────────────────────────────────────────

def export_html(findings: list, filepath: str) -> None:
    """Export tabbed HTML report with overview, network, traffic & fingerprint tabs."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    node = platform.node()

    net_json = json.dumps([
        {
            "category": f.category,
            "title": f.title,
            "severity": f.severity.value,
            "description": f.description,
            "recommendation": f.recommendation,
        }
        for f in findings
    ], ensure_ascii=False)

    counts = Counter(f.severity for f in findings)
    g = counts.get(Severity.GREEN, 0)
    y = counts.get(Severity.YELLOW, 0)
    r = counts.get(Severity.RED, 0)

    ai_summary = _generate_ai_summary(findings)
    fp_js = _get_fingerprint_js()

    html = f"""<!DOCTYPE html>
<html lang="sv">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Säkerhetsrapport – {_escape_html(node)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    min-height: 100vh; background: #0c0e14; color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    padding: 0;
  }}
  .wrap {{ max-width: 760px; margin: 0 auto; padding: 32px 20px 40px; }}
  h1 {{ font-size: 24px; font-weight: 800; margin-bottom: 4px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 20px; }}

  /* ── Tab navigation ── */
  .tab-bar {{
    display: flex; gap: 0; margin-bottom: 24px;
    border-bottom: 1px solid rgba(255,255,255,0.08);
    overflow-x: auto; -webkit-overflow-scrolling: touch;
  }}
  .tab-btn {{
    flex-shrink: 0; padding: 12px 20px; font-size: 13px; font-weight: 600;
    color: #64748b; background: none; border: none; cursor: pointer;
    border-bottom: 2px solid transparent; transition: all 0.2s;
    white-space: nowrap;
  }}
  .tab-btn:hover {{ color: #94a3b8; background: rgba(255,255,255,0.02); }}
  .tab-btn.active {{
    color: #e2e8f0; border-bottom-color: #6366f1;
  }}
  .tab-btn .tab-badge {{
    display: inline-block; font-size: 10px; font-weight: 700;
    padding: 1px 6px; border-radius: 10px; margin-left: 6px;
    vertical-align: middle;
  }}
  .tab-badge-red {{ background: rgba(239,68,68,0.15); color: #ef4444; }}
  .tab-badge-yellow {{ background: rgba(245,158,11,0.12); color: #f59e0b; }}
  .tab-badge-green {{ background: rgba(16,185,129,0.12); color: #10b981; }}

  .tab-panel {{ display: none; animation: fadeIn 0.25s ease; }}
  .tab-panel.active {{ display: block; }}
  @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: translateY(0); }} }}

  /* ── Collapsible sections ── */
  .section {{
    border: 1px solid rgba(255,255,255,0.06); border-radius: 16px;
    margin-bottom: 16px; overflow: hidden;
    background: rgba(255,255,255,0.01);
  }}
  .section-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 18px 22px; cursor: pointer; user-select: none;
    transition: background 0.15s;
  }}
  .section-header:hover {{ background: rgba(255,255,255,0.03); }}
  .section-title {{
    font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 10px;
  }}
  .section-arrow {{
    font-size: 12px; color: #64748b; transition: transform 0.2s;
  }}
  .section.open .section-arrow {{ transform: rotate(90deg); }}
  .section-body {{
    max-height: 0; overflow: hidden; transition: max-height 0.3s ease;
    padding: 0 22px;
  }}
  .section.open .section-body {{
    max-height: 8000px; padding: 0 22px 18px;
  }}

  /* ── Cards ── */
  .card {{
    border-radius: 12px; padding: 16px 20px; margin-bottom: 10px;
    border: 1px solid rgba(255,255,255,0.06);
    background: rgba(255,255,255,0.02);
  }}
  .card.risk-green  {{ background: rgba(16,185,129,0.06); border-color: rgba(16,185,129,0.2); }}
  .card.risk-yellow {{ background: rgba(245,158,11,0.05); border-color: rgba(245,158,11,0.18); }}
  .card.risk-red    {{ background: rgba(239,68,68,0.05); border-color: rgba(239,68,68,0.18); }}
  .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }}
  .card-title {{ font-weight: 600; font-size: 14px; }}
  .badge {{
    font-size: 11px; font-weight: 600; padding: 2px 10px;
    border-radius: 20px; text-transform: uppercase;
  }}
  .badge-green  {{ background: rgba(16,185,129,0.12); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }}
  .badge-yellow {{ background: rgba(245,158,11,0.1); color: #f59e0b; border: 1px solid rgba(245,158,11,0.25); }}
  .badge-red    {{ background: rgba(239,68,68,0.1); color: #ef4444; border: 1px solid rgba(239,68,68,0.25); }}
  .card-value {{ font-size: 13px; color: #94a3b8; line-height: 1.6; word-break: break-all; }}
  .card-tip {{
    margin-top: 8px; font-size: 12px; color: #cbd5e1; padding: 8px 12px;
    border-left: 3px solid rgba(245,158,11,0.4); background: rgba(255,255,255,0.02); border-radius: 6px;
  }}

  /* ── AI analysis card ── */
  .ai-card {{
    border-radius: 16px; padding: 24px 28px; margin-bottom: 20px;
    background: linear-gradient(135deg, rgba(99,102,241,0.06), rgba(139,92,246,0.04));
    border: 1px solid rgba(99,102,241,0.15);
  }}
  .ai-card-header {{
    display: flex; align-items: center; gap: 10px; margin-bottom: 16px;
  }}
  .ai-card-header span:first-child {{ font-size: 20px; }}
  .ai-card-header span:last-child {{ font-size: 16px; font-weight: 700; }}

  /* ── Score display ── */
  .score-grid {{
    display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;
  }}
  .score-box {{
    flex: 1; min-width: 200px; padding: 16px 20px; border-radius: 14px;
    background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ Säkerhetsrapport</h1>
  <div class="meta">{_escape_html(now)} &middot; {_escape_html(node)}</div>

  <!-- Tab navigation -->
  <div class="tab-bar" id="tab-bar">
    <button class="tab-btn active" id="btn-overview">🛡️ Översikt<span class="tab-badge-slot"></span></button>
    <button class="tab-btn" id="btn-network">🔒 Nätverk<span class="tab-badge-slot"></span></button>
    <button class="tab-btn" id="btn-traffic">📡 Trafik<span class="tab-badge-slot"></span></button>
    <button class="tab-btn" id="btn-home_network">🏠 Hemnätverk<span class="tab-badge-slot"></span></button>
    <button class="tab-btn" id="btn-fingerprint">🔍 Fingeravtryck<span class="tab-badge-slot"></span></button>
  </div>

  <!-- Tab 1: Overview -->
  <div class="tab-panel active" id="panel-overview">
    <div id="score-area"></div>
    <div class="ai-card">
      <div class="ai-card-header">
        <span>🤖</span><span>Analys</span>
      </div>
      {ai_summary}
      <div id="ai-fp-section" style="margin-bottom:16px"></div>
    </div>
    <div id="verdict-area"></div>
  </div>

  <!-- Tab 2: Network -->
  <div class="tab-panel" id="panel-network">
    <div id="network-sections"></div>
  </div>

  <!-- Tab 3: Traffic -->
  <div class="tab-panel" id="panel-traffic">
    <div id="traffic-sections"></div>
  </div>

  <!-- Tab 4: Home Network -->
  <div class="tab-panel" id="panel-home_network">
    <div id="home-network-sections"></div>
  </div>

  <!-- Tab 5: Fingerprint -->
  <div class="tab-panel" id="panel-fingerprint">
    <div id="browser-sections"></div>
  </div>
</div>

<script>
// ── Tab switching ──
var tabMap = ['overview','network','traffic','home_network','fingerprint'];
function switchTab(idx) {{
  var btns = document.querySelectorAll('.tab-btn');
  var panels = document.querySelectorAll('.tab-panel');
  for (var i = 0; i < btns.length; i++) btns[i].className = 'tab-btn';
  for (var i = 0; i < panels.length; i++) panels[i].className = 'tab-panel';
  btns[idx].className = 'tab-btn active';
  document.getElementById('panel-' + tabMap[idx]).className = 'tab-panel active';
}}
document.getElementById('btn-overview').addEventListener('click', function() {{ switchTab(0); }});
document.getElementById('btn-network').addEventListener('click', function() {{ switchTab(1); }});
document.getElementById('btn-traffic').addEventListener('click', function() {{ switchTab(2); }});
document.getElementById('btn-home_network').addEventListener('click', function() {{ switchTab(3); }});
document.getElementById('btn-fingerprint').addEventListener('click', function() {{ switchTab(4); }});

// ── Network findings from scanner ──
var networkFindings = {net_json};

// ── Helpers ──
function riskLevel(r) {{
  if (r === 'green') return {{ cls: 'risk-green', badge: 'badge-green', label: 'OK' }};
  if (r === 'yellow') return {{ cls: 'risk-yellow', badge: 'badge-yellow', label: 'Varning' }};
  return {{ cls: 'risk-red', badge: 'badge-red', label: 'Risk' }};
}}
function esc(s) {{ return s ? s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : ''; }}

var categoryTitles = {{
  firewall: '🔥 Brandvägg',
  wifi: '📶 WiFi-säkerhet',
  dns: '🌐 DNS-konfiguration',
  open_ports: '🚪 Öppna portar',
  exposed_services: '⚠️ Exponerade tjänster',
  active_connections: '🔗 Aktiva anslutningar',
  process: '⚙️ Processanalys',
  traffic: '📡 Trafikanalys',
  system: '🖥️ Systemsäkerhet',
  network_advanced: '🔬 Nätverksanalys',
  home_network: '🏠 Hemnätverk',
}};

// Network categories (tab 2)
var networkCats = ['firewall','wifi','dns','open_ports','exposed_services','active_connections','process','system','network_advanced'];
// Traffic categories (tab 3)
var trafficCats = ['traffic'];
// Home network categories (tab 4)
var homeCats = ['home_network'];

function groupByCategory(items) {{
  var groups = {{}};
  items.forEach(function(f) {{
    var cat = f.category || f.cat;
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(f);
  }});
  return groups;
}}

function makeCard(f) {{
  var sev = f.severity || f.risk;
  var r = riskLevel(sev);
  var desc = (f.description || f.value || '').replace(/\\n/g, '<br>');
  var rec = f.recommendation || f.tip || '';
  var tipHtml = rec ? '<div class="card-tip">💡 ' + esc(rec) + '</div>' : '';
  return '<div class="card ' + r.cls + '">' +
    '<div class="card-header">' +
      '<span class="card-title">' + esc(f.title) + '</span>' +
      '<span class="badge ' + r.badge + '">' + r.label + '</span>' +
    '</div>' +
    '<div class="card-value">' + desc + '</div>' +
    tipHtml +
  '</div>';
}}

function makeSection(id, title, badge, items, isOpen) {{
  var cards = items.map(makeCard).join('');
  return '<div class="section ' + (isOpen ? 'open' : '') + '" id="' + id + '">' +
    '<div class="section-header">' +
      '<div class="section-title">' + title + ' ' + badge + '</div>' +
      '<span class="section-arrow">▶</span>' +
    '</div>' +
    '<div class="section-body">' + cards + '</div>' +
  '</div>';
}}

function countBadge(items) {{
  var g2 = items.filter(function(f) {{ return (f.severity||f.risk)==='green'; }}).length;
  var y2 = items.filter(function(f) {{ return (f.severity||f.risk)==='yellow'; }}).length;
  var r2 = items.filter(function(f) {{ return (f.severity||f.risk)==='red'; }}).length;
  var parts = [];
  if (r2) parts.push('<span class="badge badge-red">' + r2 + '</span>');
  if (y2) parts.push('<span class="badge badge-yellow">' + y2 + '</span>');
  if (g2) parts.push('<span class="badge badge-green">' + g2 + '</span>');
  return parts.join(' ');
}}

// ── Render network sections (tab 2) ──
var netGroups = groupByCategory(networkFindings);
var netHtml = '';
networkCats.forEach(function(cat) {{
  var items = netGroups[cat];
  if (!items) return;
  var title = categoryTitles[cat] || cat;
  var hasIssues = items.some(function(f) {{ return f.severity !== 'green'; }});
  netHtml += makeSection('net-' + cat, title, countBadge(items), items, hasIssues);
}});
document.getElementById('network-sections').innerHTML = netHtml;

// ── Render traffic sections (tab 3) ──
var trafficHtml = '';
trafficCats.forEach(function(cat) {{
  var items = netGroups[cat];
  if (!items) return;
  // Show each traffic finding as its own section
  items.forEach(function(f, i) {{
    var sev = f.severity;
    trafficHtml += makeSection('trf-' + i, f.title, countBadge([f]), [f], sev !== 'green');
  }});
}});
if (!trafficHtml) {{
  trafficHtml = '<div style="color:#64748b;font-size:14px;padding:20px 0">Ingen trafikanalys tillgänglig.</div>';
}}
document.getElementById('traffic-sections').innerHTML = trafficHtml;

// ── Render home network sections (tab 4) ──
var homeHtml = '';
homeCats.forEach(function(cat) {{
  var items = netGroups[cat];
  if (!items) return;
  items.forEach(function(f, i) {{
    var sev = f.severity;
    homeHtml += makeSection('home-' + i, f.title, countBadge([f]), [f], sev !== 'green');
  }});
}});
if (!homeHtml) {{
  homeHtml = '<div style="color:#64748b;font-size:14px;padding:20px 0">Hemnätverksanalys ej tillgänglig.</div>';
}}
document.getElementById('home-network-sections').innerHTML = homeHtml;

// ── Tab badges ──
function setBadge(tabIndex, count, cls) {{
  var slots = document.querySelectorAll('.tab-badge-slot');
  if (slots[tabIndex] && count > 0) {{
    slots[tabIndex].innerHTML = ' <span class="tab-badge ' + cls + '">' + count + '</span>';
  }}
}}
function updateTabBadges() {{
  var netFindings = networkFindings.filter(function(f) {{ return networkCats.indexOf(f.category) !== -1; }});
  var netR = netFindings.filter(function(f) {{ return f.severity === 'red'; }}).length;
  var netY = netFindings.filter(function(f) {{ return f.severity === 'yellow'; }}).length;
  if (netR) setBadge(1, netR, 'tab-badge-red');
  else if (netY) setBadge(1, netY, 'tab-badge-yellow');

  var trfFindings = networkFindings.filter(function(f) {{ return trafficCats.indexOf(f.category) !== -1; }});
  var trfR = trfFindings.filter(function(f) {{ return f.severity === 'red'; }}).length;
  var trfY = trfFindings.filter(function(f) {{ return f.severity === 'yellow'; }}).length;
  if (trfR) setBadge(2, trfR, 'tab-badge-red');
  else if (trfY) setBadge(2, trfY, 'tab-badge-yellow');

  // Home network tab badge (index 3)
  var homeFindings = networkFindings.filter(function(f) {{ return homeCats.indexOf(f.category) !== -1; }});
  var homeR = homeFindings.filter(function(f) {{ return f.severity === 'red'; }}).length;
  var homeY = homeFindings.filter(function(f) {{ return f.severity === 'yellow'; }}).length;
  if (homeR) setBadge(3, homeR, 'tab-badge-red');
  else if (homeY) setBadge(3, homeY, 'tab-badge-yellow');
}}
updateTabBadges();

// ── Section collapse/expand (event delegation without inline handlers) ──
document.addEventListener('click', function(e) {{
  var header = e.target;
  while (header && !header.classList.contains('section-header')) {{
    header = header.parentElement;
  }}
  if (!header) return;
  var sec = header.parentElement;
  if (sec && sec.classList.contains('section')) {{
    if (sec.className.indexOf('open') !== -1) {{
      sec.className = 'section';
    }} else {{
      sec.className = 'section open';
    }}
  }}
}});

// ── Browser fingerprint analysis (runs live in browser) ──
var browserFindings = [];
function addBF(category, title, value, risk, tip) {{
  browserFindings.push({{ category: category, title: title, value: value, risk: risk, tip: tip || '' }});
}}

{fp_js}

// ── After browser analysis: render everything ──
setTimeout(function() {{
  // Browser sections (tab 4)
  var bGroups = groupByCategory(browserFindings.map(function(f) {{
    return {{
      category: f.category, title: f.title, description: f.value,
      severity: f.risk, recommendation: f.tip
    }};
  }}));
  var bHtml = '';
  for (var cat in bGroups) {{
    var items = bGroups[cat];
    var hasIssues = items.some(function(f) {{ return f.severity !== 'green'; }});
    bHtml += makeSection('br-' + cat, '🔍 ' + cat, countBadge(items), items, hasIssues);
  }}
  document.getElementById('browser-sections').innerHTML = bHtml;

  // Fingerprint tab badge (index 4)
  var fpR = browserFindings.filter(function(f) {{ return f.risk === 'red'; }}).length;
  var fpY = browserFindings.filter(function(f) {{ return f.risk === 'yellow'; }}).length;
  if (fpR) setBadge(4, fpR, 'tab-badge-red');
  else if (fpY) setBadge(4, fpY, 'tab-badge-yellow');

  // ── Combined score (overview tab) ──
  var all = networkFindings.map(function(f) {{ return f.severity; }})
    .concat(browserFindings.map(function(f) {{ return f.risk; }}));
  var totalG = all.filter(function(s) {{ return s==='green'; }}).length;
  var totalY = all.filter(function(s) {{ return s==='yellow'; }}).length;
  var totalR = all.filter(function(s) {{ return s==='red'; }}).length;
  var total = all.length;
  var weights = {{ green: 0, yellow: 1, red: 3 }};
  var points = all.reduce(function(s, r) {{ return s + weights[r]; }}, 0);
  var rawScore = Math.round((points / (total * 3)) * 100);

  // Uniqueness bits from browser
  var uniqueBits = 0;
  browserFindings.forEach(function(f) {{
    if (f.title === 'Canvas Fingerprint' && f.risk !== 'green') uniqueBits += 12;
    else if (f.title === 'WebGL Renderer' && f.risk === 'red') uniqueBits += 8;
    else if (f.title === 'Detekterade typsnitt') uniqueBits += 4;
    else if (f.title === 'Skärm') uniqueBits += 4;
    else if (f.title === 'User Agent') uniqueBits += 6;
    else if (f.title === 'Språk') uniqueBits += 3;
    else if (f.title === 'Tidszon') uniqueBits += 3;
    else if (f.title === 'Audio API' && f.risk !== 'green') uniqueBits += 4;
    else if (f.title === 'CPU-kärnor') uniqueBits += 2;
    else if (f.title === 'WebRTC' && f.risk === 'red') uniqueBits += 10;
    else if (f.risk === 'red') uniqueBits += 3;
    else if (f.risk === 'yellow') uniqueBits += 1;
  }});

  var uniqueness, uniqueLabel, uniqueColor;
  if (uniqueBits >= 33) {{
    uniqueness = 'Mycket hög'; uniqueLabel = 'Din webbläsare har ett nästan unikt fingeravtryck.'; uniqueColor = '#ef4444';
  }} else if (uniqueBits >= 20) {{
    uniqueness = 'Hög'; uniqueLabel = 'Din webbläsare är identifierbar bland tusentals.'; uniqueColor = '#f59e0b';
  }} else if (uniqueBits >= 10) {{
    uniqueness = 'Medel'; uniqueLabel = 'Svårare att spåra individuellt.'; uniqueColor = '#f59e0b';
  }} else {{
    uniqueness = 'Låg'; uniqueLabel = 'Svårt att skilja dig från andra.'; uniqueColor = '#10b981';
  }}

  var gc;
  if (rawScore <= 30) gc = '#10b981';
  else if (rawScore <= 60) gc = '#f59e0b';
  else gc = '#ef4444';

  document.getElementById('score-area').innerHTML =
    '<div style="text-align:center;padding:32px 20px 24px;margin-bottom:20px;' +
      'border-radius:18px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06)">' +
      '<div style="position:relative;width:130px;height:130px;margin:0 auto 16px">' +
        '<svg viewBox="0 0 140 140" style="transform:rotate(-90deg)">' +
          '<circle cx="70" cy="70" r="60" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>' +
          '<circle cx="70" cy="70" r="60" fill="none" stroke="' + gc + '" stroke-width="10"' +
            ' stroke-dasharray="' + Math.round(rawScore * 3.77) + ' 377" stroke-linecap="round"/>' +
        '</svg>' +
        '<div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">' +
          '<div style="font-size:34px;font-weight:800;color:' + gc + '">' + rawScore + '</div>' +
          '<div style="font-size:11px;color:#64748b;text-transform:uppercase">av 100</div>' +
        '</div>' +
      '</div>' +
      '<div style="font-size:16px;font-weight:700;margin-bottom:4px">Sammanlagd riskpoäng</div>' +
      '<div style="font-size:13px;color:#94a3b8;max-width:420px;margin:0 auto">' +
        (rawScore <= 30 ? 'Bra! Låg exponering.' : rawScore <= 60 ? 'Förbättringsmöjligheter finns.' : 'Hög exponering.') +
      '</div>' +
    '</div>' +
    '<div class="score-grid">' +
      '<div class="score-box">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">' +
          '<span style="font-size:13px;font-weight:700">🧬 Spårbarhet</span>' +
          '<span style="font-size:13px;font-weight:700;color:' + uniqueColor + '">' + uniqueness + '</span>' +
        '</div>' +
        '<div style="font-size:12px;color:#94a3b8;margin-bottom:10px">' + uniqueLabel + '</div>' +
        '<div style="height:5px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden">' +
          '<div style="height:100%;width:' + Math.min(uniqueBits/40*100,100) + '%;background:' + uniqueColor + ';border-radius:3px"></div>' +
        '</div>' +
        '<div style="font-size:10px;color:#475569;margin-top:4px">' + uniqueBits + ' bitar</div>' +
      '</div>' +
      '<div class="score-box">' +
        '<div style="font-size:13px;font-weight:700;margin-bottom:10px">📊 Resultat</div>' +
        '<div style="display:flex;gap:14px;font-size:13px;color:#94a3b8">' +
          '<span>🟢 <strong style="color:#e2e8f0">' + totalG + '</strong></span>' +
          '<span>🟡 <strong style="color:#e2e8f0">' + totalY + '</strong></span>' +
          '<span>🔴 <strong style="color:#e2e8f0">' + totalR + '</strong></span>' +
        '</div>' +
        '<div style="font-size:11px;color:#475569;margin-top:6px">' + total + ' kontroller totalt</div>' +
      '</div>' +
    '</div>';

  // Collect all red findings with details
  var redDetails = [];
  networkFindings.forEach(function(f) {{
    if (f.severity === 'red') redDetails.push(esc(f.title) + ': ' + esc(f.description.split('\\n')[0]));
  }});
  browserFindings.forEach(function(f) {{
    if (f.risk === 'red') redDetails.push(esc(f.title) + ': ' + esc(f.value));
  }});

  // Verdict
  var vHtml;
  if (totalR > 0) {{
    var detailList = redDetails.map(function(d) {{
      return '<div style="font-size:12px;padding:3px 0">❌ ' + d + '</div>';
    }}).join('');
    vHtml = '<div style="margin-top:24px;padding:16px 20px;border-radius:12px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:#fca5a5;font-size:14px">' +
      '⚠️ <strong>' + totalR + ' risker</strong> hittades som bör åtgärdas.' +
      '<div style="margin-top:10px">' + detailList + '</div></div>';
  }} else if (totalY > 0) {{
    vHtml = '<div style="margin-top:24px;padding:16px 20px;border-radius:12px;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.18);color:#fcd34d;font-size:14px">' +
      '⚡ Inga akuta problem, men <strong>' + totalY + ' saker</strong> kan förbättras.</div>';
  }} else {{
    vHtml = '<div style="margin-top:24px;padding:16px 20px;border-radius:12px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);color:#6ee7b7;font-size:14px">' +
      '✓ Allt ser bra ut!</div>';
  }}
  document.getElementById('verdict-area').innerHTML = vHtml;

  // Add fingerprint findings to AI analysis card
  var fpSection = document.getElementById('ai-fp-section');
  if (fpSection) {{
    var fpItems = '';
    browserFindings.forEach(function(f) {{
      var icon = f.risk === 'green' ? '✅' : f.risk === 'yellow' ? '⚠️' : '❌';
      fpItems += '<div style="font-size:13px;color:#cbd5e1;padding:4px 0;line-height:1.5">' +
        icon + ' ' + esc(f.title) + ': ' + esc(f.value) + '</div>';
    }});
    fpSection.innerHTML = '<div style="font-size:14px;font-weight:700;margin-bottom:6px;color:#e2e8f0">🔍 Webbläsar-fingeravtryck</div>' + fpItems;
  }}
}}, 400);
</script>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"  🌐 HTML exporterad till: {filepath}")


def _get_fingerprint_js() -> str:
    """Return browser fingerprint analysis JS that calls addBF() for each finding."""
    return r"""
  // ── User Agent ──
  var ua = navigator.userAgent;
  addBF('Identitet', 'User Agent', ua, 'yellow',
    'User Agent avslöjar webbläsare, OS och version.');

  // ── Platform ──
  addBF('Identitet', 'Plattform', navigator.platform || 'Okänd', 'yellow',
    'Visar ditt operativsystem.');

  // ── Language ──
  var langs = navigator.languages ? navigator.languages.join(', ') : navigator.language;
  addBF('Identitet', 'Språk', langs, 'yellow',
    'Språkinställningar kan användas för att identifiera dig.');

  // ── Screen ──
  var screenInfo = screen.width+'×'+screen.height+' (tillgänglig: '+screen.availWidth+'×'+screen.availHeight+'), färgdjup: '+screen.colorDepth+'-bit, pixelratio: '+devicePixelRatio;
  addBF('Hårdvara', 'Skärm', screenInfo, 'yellow',
    'Unik kombination av skärmstorlek och pixelratio gör dig spårbar.');

  // ── Hardware concurrency ──
  if (navigator.hardwareConcurrency) {
    addBF('Hårdvara', 'CPU-kärnor', navigator.hardwareConcurrency.toString(), 'yellow');
  }

  // ── Device memory ──
  if (navigator.deviceMemory) {
    addBF('Hårdvara', 'RAM (ungefärligt)', navigator.deviceMemory + ' GB', 'yellow');
  }

  // ── Timezone ──
  var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  addBF('Plats', 'Tidszon', tz, 'yellow',
    'Tidszonen avslöjar ungefärligt var du befinner dig.');

  // ── Geolocation API ──
  var geoAvail = 'geolocation' in navigator ? 'Tillgänglig (kräver godkännande)' : 'Ej tillgänglig';
  addBF('Plats', 'Geolocation API', geoAvail,
    'geolocation' in navigator ? 'yellow' : 'green');

  // ── Cookies ──
  addBF('Spårning', 'Cookies', navigator.cookieEnabled ? 'Aktiverade' : 'Avaktiverade',
    navigator.cookieEnabled ? 'yellow' : 'green',
    navigator.cookieEnabled ? 'Cookies möjliggör spårning mellan besök.' : '');

  // ── Do Not Track ──
  var dnt = navigator.doNotTrack;
  var dntText = dnt === '1' ? 'Aktiverat' : dnt === '0' ? 'Avaktiverat' : 'Ej inställt';
  addBF('Spårning', 'Do Not Track', dntText,
    dnt === '1' ? 'green' : 'yellow',
    dnt !== '1' ? 'Aktivera Do Not Track i webbläsarens integritetsinställningar.' : '');

  // ── Local/Session storage ──
  var storageAvail = 'Nej';
  try { if (window.localStorage && window.sessionStorage) storageAvail = 'Ja (localStorage + sessionStorage)'; }
  catch(e) { storageAvail = 'Blockerat'; }
  addBF('Spårning', 'Webblagring', storageAvail,
    storageAvail.indexOf('Ja') === 0 ? 'yellow' : 'green',
    storageAvail.indexOf('Ja') === 0 ? 'Webblagring kan användas för att spåra dig utan cookies.' : '');

  // ── WebRTC ──
  var rtcAvail = (window.RTCPeerConnection || window.webkitRTCPeerConnection) ? 'Tillgänglig' : 'Ej tillgänglig';
  addBF('Integritet', 'WebRTC', rtcAvail,
    rtcAvail === 'Tillgänglig' ? 'red' : 'green',
    rtcAvail === 'Tillgänglig' ? 'WebRTC kan läcka din riktiga IP-adress även bakom VPN!' : '');

  // ── Canvas fingerprint ──
  var canvasHash = 'Ej tillgänglig';
  var canvasRisk = 'green';
  try {
    var cvs = document.createElement('canvas');
    cvs.width = 280; cvs.height = 40;
    var ctx = cvs.getContext('2d');
    ctx.fillStyle = '#0c0e14'; ctx.fillRect(0, 0, 280, 40);
    ctx.fillStyle = '#e2e8f0'; ctx.font = '14px Arial';
    ctx.fillText('Fingerprint Test åäö', 5, 25);
    ctx.fillStyle = 'rgba(16,185,129,0.5)';
    ctx.beginPath(); ctx.arc(240, 20, 15, 0, Math.PI * 2); ctx.fill();
    var dataURL = cvs.toDataURL();
    var hash = 0;
    for (var i = 0; i < dataURL.length; i++) {
      hash = ((hash << 5) - hash) + dataURL.charCodeAt(i);
      hash |= 0;
    }
    canvasHash = 'Hash: ' + Math.abs(hash).toString(16);
    canvasRisk = 'red';
  } catch(e) {
    canvasHash = 'Blockerat av webbläsaren';
  }
  addBF('Fingeravtryck', 'Canvas Fingerprint', canvasHash, canvasRisk,
    canvasRisk === 'red' ? 'Canvas-fingeravtryck är unikt för din dator. Överväg CanvasBlocker-tillägg.' : '');

  // ── WebGL ──
  var webglInfo = 'Ej tillgänglig';
  var webglRisk = 'green';
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    if (gl) {
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (ext) {
        webglInfo = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) + ' — ' + gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
        webglRisk = 'red';
      } else {
        webglInfo = 'Tillgänglig (renderer dold)';
        webglRisk = 'yellow';
      }
    }
  } catch(e) {}
  addBF('Fingeravtryck', 'WebGL Renderer', webglInfo, webglRisk,
    webglRisk === 'red' ? 'Avslöjar exakt grafikprocessor — unikt för din hårdvara.' : '');

  // ── Audio fingerprint ──
  var audioAvail = (window.AudioContext || window.webkitAudioContext) ? 'Tillgänglig' : 'Ej tillgänglig';
  addBF('Fingeravtryck', 'Audio API', audioAvail,
    audioAvail === 'Tillgänglig' ? 'yellow' : 'green',
    audioAvail === 'Tillgänglig' ? 'Kan användas för ljudbaserat fingeravtryck.' : '');

  // ── Fonts ──
  var testFonts = ['Arial','Courier New','Georgia','Helvetica','Monaco','Comic Sans MS','Impact','Trebuchet MS','Verdana','Palatino','Lucida Console'];
  var detectedFonts = [];
  var span = document.createElement('span');
  span.style.cssText = 'position:absolute;left:-9999px;font-size:72px';
  span.textContent = 'mmmmmmmmmmlli';
  document.body.appendChild(span);
  span.style.fontFamily = 'monospace';
  var defaultWidth = span.offsetWidth;
  testFonts.forEach(function(f) {
    span.style.fontFamily = '"'+f+'", monospace';
    if (span.offsetWidth !== defaultWidth) detectedFonts.push(f);
  });
  document.body.removeChild(span);
  addBF('Fingeravtryck', 'Detekterade typsnitt', detectedFonts.join(', ') || 'Inga extra', 'yellow',
    'Installerade typsnitt skapar ett unikt fingeravtryck.');

  // ── Plugins ──
  var plugins = Array.from(navigator.plugins || []).map(function(p){return p.name}).filter(Boolean);
  addBF('Fingeravtryck', 'Webbläsarplugins', plugins.length > 0 ? plugins.join(', ') : 'Inga',
    plugins.length > 2 ? 'yellow' : 'green');

  // ── Permissions API ──
  if (navigator.permissions) {
    var permNames = ['camera', 'microphone', 'notifications', 'geolocation'];
    var permResults = [];
    var permDone = 0;
    permNames.forEach(function(name) {
      navigator.permissions.query({name: name}).then(function(result) {
        permResults.push(name + ': ' + result.state);
        permDone++;
        if (permDone === permNames.length) {
          var granted = permResults.filter(function(r) { return r.indexOf('granted') !== -1; });
          var risk = granted.length >= 2 ? 'red' : granted.length === 1 ? 'yellow' : 'green';
          var tip = granted.length > 0 ? 'Granska beviljade behörigheter i webbläsarens inställningar.' : '';
          addBF('Behörigheter', 'Webbläsarbehörigheter', permResults.join(', '), risk, tip);
        }
      }).catch(function() {
        permDone++;
        if (permDone === permNames.length && permResults.length > 0) {
          addBF('Behörigheter', 'Webbläsarbehörigheter', permResults.join(', '), 'green', '');
        }
      });
    });
  }

  // ── Battery API ──
  if (navigator.getBattery) {
    try {
      navigator.getBattery().then(function(battery) {
        var level = Math.round(battery.level * 100) + '%';
        var charging = battery.charging ? 'Laddar' : 'Batteri';
        addBF('Hårdvara', 'Batteristatus', charging + ' (' + level + ')',
          'yellow', 'Battery API kan användas för fingerprinting.');
      }).catch(function() {});
    } catch(e) {}
  }

  // ── Network Information API ──
  if (navigator.connection) {
    var conn = navigator.connection;
    var connInfo = 'Typ: ' + (conn.effectiveType || 'okänd');
    if (conn.downlink) connInfo += ', Bandbredd: ~' + conn.downlink + ' Mbps';
    if (conn.rtt) connInfo += ', RTT: ' + conn.rtt + ' ms';
    addBF('Hårdvara', 'Nätverksinfo', connInfo, 'yellow',
      'Network Information API avslöjar din anslutningstyp.');
  }
"""


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
