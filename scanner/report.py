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
        "traffic": "Trafikanalys",
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
    """Export combined HTML report: network findings + live browser fingerprinting."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    node = platform.node()

    # Build network findings as JSON for the JS to consume
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

    # Read the fingerprint.html JS (everything between <script> tags)
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
    padding: 40px 20px;
  }}
  .wrap {{ max-width: 720px; margin: 0 auto; }}
  h1 {{ font-size: 24px; font-weight: 800; margin-bottom: 4px; }}
  .meta {{ color: #64748b; font-size: 13px; margin-bottom: 28px; }}

  /* Collapsible sections */
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
  .section-badge {{
    font-size: 11px; font-weight: 600; padding: 2px 10px;
    border-radius: 20px;
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
    max-height: 5000px; padding: 0 22px 18px;
  }}

  /* Cards inside sections */
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

  .summary {{
    display: flex; gap: 16px; margin-bottom: 24px; padding: 18px;
    border-radius: 14px; background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06); flex-wrap: wrap;
  }}
  .stat {{ font-size: 14px; color: #94a3b8; }}
  .stat strong {{ color: #e2e8f0; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ Säkerhetsrapport</h1>
  <div class="meta">{_escape_html(now)} &middot; {_escape_html(node)}</div>

  <div id="score-area"></div>
  <div id="network-sections"></div>
  <div id="browser-sections"></div>
  <div id="verdict-area"></div>
</div>

<script>
// ── Network findings from scanner ──
const networkFindings = {net_json};

// ── Helpers ──
function riskLevel(r) {{
  if (r === 'green') return {{ cls: 'risk-green', badge: 'badge-green', label: 'OK' }};
  if (r === 'yellow') return {{ cls: 'risk-yellow', badge: 'badge-yellow', label: 'Varning' }};
  return {{ cls: 'risk-red', badge: 'badge-red', label: 'Risk' }};
}}
function esc(s) {{ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}

const categoryTitles = {{
  firewall: '🔥 Brandvägg',
  wifi: '📶 WiFi-säkerhet',
  dns: '🌐 DNS-konfiguration',
  open_ports: '🚪 Öppna portar',
  exposed_services: '⚠️ Exponerade tjänster',
  active_connections: '🔗 Aktiva anslutningar',
  process: '⚙️ Processanalys',
  traffic: '📡 Trafikanalys',
}};

// Group network findings by category
function groupByCategory(items) {{
  const groups = {{}};
  items.forEach(f => {{
    const cat = f.category || f.cat;
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(f);
  }});
  return groups;
}}

function makeCard(f) {{
  const sev = f.severity || f.risk;
  const r = riskLevel(sev);
  const desc = (f.description || f.value || '').replace(/\\n/g, '<br>');
  const rec = f.recommendation || f.tip || '';
  const tipHtml = rec ? `<div class="card-tip">💡 ${{esc(rec)}}</div>` : '';
  return `<div class="card ${{r.cls}}">
    <div class="card-header">
      <span class="card-title">${{esc(f.title)}}</span>
      <span class="badge ${{r.badge}}">${{r.label}}</span>
    </div>
    <div class="card-value">${{desc}}</div>
    ${{tipHtml}}
  </div>`;
}}

function makeSection(id, title, badge, items, open) {{
  const cards = items.map(makeCard).join('');
  return `<div class="section ${{open ? 'open' : ''}}" id="${{id}}">
    <div class="section-header" onclick="this.parentElement.classList.toggle('open')">
      <div class="section-title">${{title}} ${{badge}}</div>
      <span class="section-arrow">▶</span>
    </div>
    <div class="section-body">${{cards}}</div>
  </div>`;
}}

function countBadge(items) {{
  const g = items.filter(f => (f.severity||f.risk)==='green').length;
  const y = items.filter(f => (f.severity||f.risk)==='yellow').length;
  const r = items.filter(f => (f.severity||f.risk)==='red').length;
  let parts = [];
  if (r) parts.push(`<span class="badge badge-red">${{r}}</span>`);
  if (y) parts.push(`<span class="badge badge-yellow">${{y}}</span>`);
  if (g) parts.push(`<span class="badge badge-green">${{g}}</span>`);
  return parts.join(' ');
}}

// ── Render network sections ──
const netGroups = groupByCategory(networkFindings);
let netHtml = '';
for (const [cat, items] of Object.entries(netGroups)) {{
  const title = categoryTitles[cat] || cat;
  const hasIssues = items.some(f => f.severity !== 'green');
  netHtml += makeSection('net-' + cat, title, countBadge(items), items, hasIssues);
}}
document.getElementById('network-sections').innerHTML = netHtml;

// ── Browser fingerprint analysis (runs live in browser) ──
const browserFindings = [];
function addBF(category, title, value, risk, tip) {{
  browserFindings.push({{ category, title, value, risk, tip: tip || '' }});
}}

{fp_js}

// ── After browser analysis: render everything ──
setTimeout(function() {{
  // Browser sections
  const bGroups = groupByCategory(browserFindings.map(f => ({{
    category: f.category, title: f.title, description: f.value,
    severity: f.risk, recommendation: f.tip
  }})));
  let bHtml = '';
  for (const [cat, items] of Object.entries(bGroups)) {{
    const hasIssues = items.some(f => f.severity !== 'green');
    bHtml += makeSection('br-' + cat, '🔍 ' + cat, countBadge(items), items, hasIssues);
  }}
  document.getElementById('browser-sections').innerHTML = bHtml;

  // ── Combined score ──
  const all = [
    ...networkFindings.map(f => f.severity),
    ...browserFindings.map(f => f.risk)
  ];
  const totalG = all.filter(s => s==='green').length;
  const totalY = all.filter(s => s==='yellow').length;
  const totalR = all.filter(s => s==='red').length;
  const total = all.length;
  const weights = {{ green: 0, yellow: 1, red: 3 }};
  const points = all.reduce((s, r) => s + weights[r], 0);
  const rawScore = Math.round((points / (total * 3)) * 100);

  // Uniqueness bits from browser
  let uniqueBits = 0;
  browserFindings.forEach(f => {{
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

  let uniqueness, uniqueLabel, uniqueColor;
  if (uniqueBits >= 33) {{
    uniqueness = 'Mycket hög'; uniqueLabel = 'Din webbläsare har ett nästan unikt fingeravtryck.'; uniqueColor = '#ef4444';
  }} else if (uniqueBits >= 20) {{
    uniqueness = 'Hög'; uniqueLabel = 'Din webbläsare är identifierbar bland tusentals.'; uniqueColor = '#f59e0b';
  }} else if (uniqueBits >= 10) {{
    uniqueness = 'Medel'; uniqueLabel = 'Svårare att spåra individuellt.'; uniqueColor = '#f59e0b';
  }} else {{
    uniqueness = 'Låg'; uniqueLabel = 'Svårt att skilja dig från andra.'; uniqueColor = '#10b981';
  }}

  let gc;
  if (rawScore <= 30) gc = '#10b981';
  else if (rawScore <= 60) gc = '#f59e0b';
  else gc = '#ef4444';

  document.getElementById('score-area').innerHTML = `
    <div style="text-align:center;padding:32px 20px 24px;margin-bottom:20px;
      border-radius:18px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06)">
      <div style="position:relative;width:130px;height:130px;margin:0 auto 16px">
        <svg viewBox="0 0 140 140" style="transform:rotate(-90deg)">
          <circle cx="70" cy="70" r="60" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
          <circle cx="70" cy="70" r="60" fill="none" stroke="${{gc}}" stroke-width="10"
            stroke-dasharray="${{Math.round(rawScore * 3.77)}} 377" stroke-linecap="round"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
          <div style="font-size:34px;font-weight:800;color:${{gc}}">${{rawScore}}</div>
          <div style="font-size:11px;color:#64748b;text-transform:uppercase">av 100</div>
        </div>
      </div>
      <div style="font-size:16px;font-weight:700;margin-bottom:4px">Sammanlagd riskpoäng</div>
      <div style="font-size:13px;color:#94a3b8;max-width:420px;margin:0 auto">
        ${{rawScore <= 30 ? 'Bra! Låg exponering.' : rawScore <= 60 ? 'Förbättringsmöjligheter finns.' : 'Hög exponering.'}}
      </div>
    </div>
    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">
      <div style="flex:1;min-width:200px;padding:16px 20px;border-radius:14px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06)">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span style="font-size:13px;font-weight:700">🧬 Spårbarhet</span>
          <span style="font-size:13px;font-weight:700;color:${{uniqueColor}}">${{uniqueness}}</span>
        </div>
        <div style="font-size:12px;color:#94a3b8;margin-bottom:10px">${{uniqueLabel}}</div>
        <div style="height:5px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${{Math.min(uniqueBits/40*100,100)}}%;background:${{uniqueColor}};border-radius:3px"></div>
        </div>
        <div style="font-size:10px;color:#475569;margin-top:4px">${{uniqueBits}} bitar</div>
      </div>
      <div style="flex:1;min-width:200px;padding:16px 20px;border-radius:14px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06)">
        <div style="font-size:13px;font-weight:700;margin-bottom:10px">📊 Resultat</div>
        <div style="display:flex;gap:14px;font-size:13px;color:#94a3b8">
          <span>🟢 <strong style="color:#e2e8f0">${{totalG}}</strong></span>
          <span>🟡 <strong style="color:#e2e8f0">${{totalY}}</strong></span>
          <span>🔴 <strong style="color:#e2e8f0">${{totalR}}</strong></span>
        </div>
        <div style="font-size:11px;color:#475569;margin-top:6px">${{total}} kontroller totalt</div>
      </div>
    </div>`;

  // Verdict
  let vHtml;
  if (totalR > 0) {{
    vHtml = `<div style="margin-top:24px;padding:16px 20px;border-radius:12px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);color:#fca5a5;font-size:14px">
      ⚠️ <strong>${{totalR}} risker</strong> hittades som bör åtgärdas.</div>`;
  }} else if (totalY > 0) {{
    vHtml = `<div style="margin-top:24px;padding:16px 20px;border-radius:12px;background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.18);color:#fcd34d;font-size:14px">
      ⚡ Inga akuta problem, men <strong>${{totalY}} saker</strong> kan förbättras.</div>`;
  }} else {{
    vHtml = `<div style="margin-top:24px;padding:16px 20px;border-radius:12px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);color:#6ee7b7;font-size:14px">
      ✓ Allt ser bra ut!</div>`;
  }}
  document.getElementById('verdict-area').innerHTML = vHtml;
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
"""


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
