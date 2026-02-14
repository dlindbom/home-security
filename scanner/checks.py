"""Security checks for macOS — firewall, WiFi, DNS, ports, connections, processes."""

import os
import plistlib
import re

from scanner.utils import (
    Finding,
    Severity,
    ConnectionInfo,
    run_command,
    parse_lsof_output,
    reverse_dns,
    is_private_ip,
)


# ── Brandvägg ────────────────────────────────────────────────────────────────

def check_firewall() -> list[Finding]:
    """Check macOS firewall status via socketfilterfw."""
    findings = []
    stdout, stderr, rc = run_command(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
    )

    if rc != 0:
        findings.append(Finding(
            category="firewall",
            title="Brandväggsstatus kunde inte läsas",
            severity=Severity.YELLOW,
            description=f"Kommandot misslyckades: {stderr.strip()}",
            recommendation="Kontrollera att du kör som admin.",
        ))
        return findings

    enabled = "enabled" in stdout.lower()
    findings.append(Finding(
        category="firewall",
        title="macOS-brandvägg",
        severity=Severity.GREEN if enabled else Severity.RED,
        description="Brandväggen är aktiverad." if enabled else "Brandväggen är AVSTÄNGD.",
        recommendation="" if enabled else "Aktivera: Systeminställningar → Nätverk → Brandvägg",
    ))

    # Stealth mode
    stdout2, _, rc2 = run_command(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"]
    )
    if rc2 == 0:
        stealth = "enabled" in stdout2.lower()
        findings.append(Finding(
            category="firewall",
            title="Stealth-läge",
            severity=Severity.GREEN if stealth else Severity.YELLOW,
            description="Datorn svarar inte på ping/portskanningar." if stealth
            else "Stealth-läge är av – datorn svarar på ping.",
            recommendation="" if stealth
            else "Aktivera stealth: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
        ))

    return findings


# ── WiFi ─────────────────────────────────────────────────────────────────────

def check_wifi() -> list[Finding]:
    """Check current WiFi connection security."""
    findings = []

    # Try the modern macOS command first, fall back to legacy
    stdout, stderr, rc = run_command(
        ["system_profiler", "SPAirPortDataType", "-detailLevel", "basic"]
    )
    if rc != 0:
        findings.append(Finding(
            category="wifi",
            title="WiFi-information kunde inte läsas",
            severity=Severity.YELLOW,
            description=stderr.strip(),
        ))
        return findings

    # Parse security type from system_profiler output
    security_type = None
    ssid = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if "Current Network Information:" in stripped:
            continue
        if ssid is None and stripped.endswith(":") and "Security" not in stripped:
            # Network name is the first key after "Current Network Information"
            candidate = stripped.rstrip(":")
            if candidate and not any(k in candidate for k in ["PHY Mode", "Channel", "BSSID"]):
                ssid = candidate
        if "Security:" in stripped or "Säkerhet:" in stripped:
            security_type = stripped.split(":", 1)[1].strip()

    if ssid:
        if security_type and "WPA3" in security_type:
            sev = Severity.GREEN
            desc = f"Nätverk \"{ssid}\" använder {security_type}."
            rec = ""
        elif security_type and "WPA2" in security_type:
            sev = Severity.GREEN
            desc = f"Nätverk \"{ssid}\" använder {security_type}."
            rec = "Överväg att uppgradera routern till WPA3 om möjligt."
        elif security_type and ("WPA" in security_type or "WEP" in security_type):
            sev = Severity.RED
            desc = f"Nätverk \"{ssid}\" använder {security_type} som är osäkert."
            rec = "Byt till WPA2/WPA3 i routerns inställningar."
        elif security_type and "None" in security_type:
            sev = Severity.RED
            desc = f"Nätverk \"{ssid}\" är ett ÖPPET nätverk utan kryptering!"
            rec = "Undvik öppna nätverk. Använd VPN om du måste."
        else:
            sev = Severity.YELLOW
            desc = f"Nätverk \"{ssid}\" – säkerhetstyp: {security_type or 'okänd'}."
            rec = "Kontrollera routerns krypteringsinställningar."

        findings.append(Finding(
            category="wifi",
            title="WiFi-kryptering",
            severity=sev,
            description=desc,
            recommendation=rec,
        ))
    else:
        findings.append(Finding(
            category="wifi",
            title="Inget WiFi-nätverk anslutet",
            severity=Severity.YELLOW,
            description="Kunde inte hitta ett aktivt WiFi-nätverk.",
        ))

    return findings


# ── DNS ──────────────────────────────────────────────────────────────────────

_KNOWN_SECURE_DNS = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google",
    "8.8.4.4": "Google",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
}


def check_dns() -> list[Finding]:
    """Check DNS resolver configuration."""
    findings = []
    stdout, _, rc = run_command(["scutil", "--dns"])
    if rc != 0:
        findings.append(Finding(
            category="dns",
            title="DNS-konfiguration kunde inte läsas",
            severity=Severity.YELLOW,
            description="scutil --dns misslyckades.",
        ))
        return findings

    # Extract nameserver IPs
    servers = []
    for line in stdout.splitlines():
        m = re.match(r'\s*nameserver\[\d+\]\s*:\s*(.+)', line)
        if m:
            servers.append(m.group(1).strip())

    unique_servers = list(dict.fromkeys(servers))  # preserve order, deduplicate

    if not unique_servers:
        findings.append(Finding(
            category="dns",
            title="Inga DNS-servrar konfigurerade",
            severity=Severity.RED,
            description="Ingen DNS-resolver hittades.",
            recommendation="Ställ in DNS manuellt, t.ex. 1.1.1.1 (Cloudflare) eller 9.9.9.9 (Quad9).",
        ))
        return findings

    known = []
    unknown = []
    for s in unique_servers:
        if s in _KNOWN_SECURE_DNS:
            known.append(f"{s} ({_KNOWN_SECURE_DNS[s]})")
        elif is_private_ip(s):
            unknown.append(f"{s} (router/lokalt)")
        else:
            unknown.append(s)

    if known and not unknown:
        findings.append(Finding(
            category="dns",
            title="DNS-servrar",
            severity=Severity.GREEN,
            description=f"Använder kända säkra DNS-resolvers: {', '.join(known)}",
        ))
    elif unknown:
        all_display = known + unknown
        sev = Severity.YELLOW if not known else Severity.GREEN
        findings.append(Finding(
            category="dns",
            title="DNS-servrar",
            severity=sev,
            description=f"DNS-resolvers: {', '.join(all_display)}",
            recommendation="Överväg att använda krypterad DNS som 1.1.1.1 eller 9.9.9.9."
            if sev == Severity.YELLOW else "",
        ))

    return findings


# ── Öppna portar & exponerade tjänster ───────────────────────────────────────

# Services that are generally risky to expose
_RISKY_PORTS = {
    22: ("SSH", Severity.YELLOW, "Se till att SSH kräver nyckelautentisering."),
    23: ("Telnet", Severity.RED, "Stäng av Telnet! Använd SSH istället."),
    80: ("HTTP", Severity.YELLOW, "Webbserver utan kryptering. Kör HTTPS."),
    445: ("SMB", Severity.YELLOW, "Fildelning – se till att den inte är öppen externt."),
    548: ("AFP", Severity.YELLOW, "Apple Filing Protocol – begränsa till lokalt nätverk."),
    3306: ("MySQL", Severity.RED, "Databasport exponerad. Begränsa till localhost."),
    5432: ("PostgreSQL", Severity.RED, "Databasport exponerad. Begränsa till localhost."),
    5900: ("VNC/Screen Sharing", Severity.RED, "Skärmdelning exponerad! Begränsa åtkomst."),
    6379: ("Redis", Severity.RED, "Redis utan auth är extremt riskabelt."),
    8080: ("HTTP-alt", Severity.YELLOW, "Alternativ webbserver. Kontrollera vad den kör."),
    27017: ("MongoDB", Severity.RED, "Databasport exponerad. Begränsa till localhost."),
}

# Processes that are normal and expected on macOS
_KNOWN_SAFE_PROCESSES = {
    # macOS system
    "rapportd", "sharingd", "mDNSResponder", "CommCenter", "identityservicesd",
    "apsd", "UserEventAgent", "launchd", "SystemUIServer", "WiFiAgent",
    "airportd", "configd", "networkd", "symptomsd", "cloudd",
    "trustd", "parsecd", "nsurlsessiond", "AMPDevicesDi",
    "ControlCe", "networkservi",
    # Common user apps
    "Safari", "firefox", "Google", "Chrome", "Brave",
    "Slack", "Discord", "Spotify", "Teams", "zoom.us",
    "OneDrive", "Dropbox", "iCloud",
    "Claude", "Cursor", "Code",
    "NordVPN", "Mullvad", "WireGuard",
    "Mail", "Outlook", "Thunderbird",
    "Comet",  # Electron apps (lsof truncates names)
}


def _is_known_process(name: str) -> bool:
    """Check if a process name matches a known safe process (case-insensitive prefix match)."""
    clean = name.replace("\\x20", "").strip().lower()
    return any(clean.startswith(safe.lower()) for safe in _KNOWN_SAFE_PROCESSES)


def check_open_ports() -> list[Finding]:
    """Identify listening ports and flag risky ones."""
    findings = []
    stdout, stderr, rc = run_command(["lsof", "-i", "-P", "-n"])
    if rc != 0:
        findings.append(Finding(
            category="open_ports",
            title="Portskanning misslyckades",
            severity=Severity.YELLOW,
            description=f"lsof kunde inte köras: {stderr.strip()}",
            recommendation="Testa: sudo lsof -i -P -n",
        ))
        return findings

    connections = parse_lsof_output(stdout)
    listeners = [c for c in connections if c.state == "LISTEN"]

    if not listeners:
        findings.append(Finding(
            category="open_ports",
            title="Inga lyssningsportar",
            severity=Severity.GREEN,
            description="Inga tjänster lyssnar på nätverket.",
        ))
        return findings

    # Group by port
    seen_ports: dict[int, list[ConnectionInfo]] = {}
    for c in listeners:
        if c.local_port is not None:
            seen_ports.setdefault(c.local_port, []).append(c)

    for port, conns in sorted(seen_ports.items()):
        process_names = ", ".join(sorted({c.command for c in conns}))
        addresses = sorted({c.local_address for c in conns})
        binds_all = any(a in ("*", "0.0.0.0", "::") for a in addresses)

        if port in _RISKY_PORTS:
            service_name, sev, rec = _RISKY_PORTS[port]
            if not binds_all:
                sev = Severity.YELLOW if sev == Severity.RED else sev
                rec = f"Bunden till {', '.join(addresses)} (ej externt). " + rec
            findings.append(Finding(
                category="open_ports",
                title=f"Port {port} ({service_name})",
                severity=sev,
                description=f"Process: {process_names}\nLyssnar på: {', '.join(addresses)}",
                recommendation=rec,
                raw_data={"port": port, "processes": process_names, "addresses": addresses},
            ))
        else:
            # Unknown port – flag if binding to all interfaces
            sev = Severity.YELLOW if binds_all else Severity.GREEN
            findings.append(Finding(
                category="open_ports",
                title=f"Port {port}",
                severity=sev,
                description=f"Process: {process_names}\nLyssnar på: {', '.join(addresses)}",
                recommendation="Kontrollera om tjänsten behöver vara tillgänglig externt."
                if binds_all else "",
                raw_data={"port": port, "processes": process_names, "addresses": addresses},
            ))

    return findings


# ── Aktiva anslutningar ──────────────────────────────────────────────────────

def check_active_connections() -> list[Finding]:
    """Analyze established outbound connections."""
    findings = []
    stdout, stderr, rc = run_command(["lsof", "-i", "-P", "-n"])
    if rc != 0:
        return findings

    connections = parse_lsof_output(stdout)
    established = [c for c in connections if c.state == "ESTABLISHED" and c.remote_address]

    if not established:
        findings.append(Finding(
            category="active_connections",
            title="Inga aktiva utgående anslutningar",
            severity=Severity.GREEN,
            description="Inga etablerade anslutningar hittades.",
        ))
        return findings

    # Analyze external connections
    external = [c for c in established if not is_private_ip(c.remote_address or "")]
    internal = [c for c in established if is_private_ip(c.remote_address or "")]

    findings.append(Finding(
        category="active_connections",
        title="Anslutningsöversikt",
        severity=Severity.GREEN,
        description=(
            f"Totalt {len(established)} etablerade anslutningar.\n"
            f"  Lokala/privata: {len(internal)}\n"
            f"  Externa:        {len(external)}"
        ),
    ))

    # Flag unusual external connections from unexpected processes
    for c in external:
        if _is_known_process(c.command):
            continue

        hostname = reverse_dns(c.remote_address) if c.remote_address else None
        remote_display = hostname or c.remote_address

        findings.append(Finding(
            category="active_connections",
            title=f"{c.command} → {remote_display}:{c.remote_port}",
            severity=Severity.YELLOW,
            description=(
                f"Process {c.command} (PID {c.pid}) har en extern anslutning.\n"
                f"Fjärradress: {c.remote_address}"
                + (f" ({hostname})" if hostname else "")
            ),
            recommendation="Kontrollera om denna anslutning är förväntad.",
            raw_data={
                "command": c.command, "pid": c.pid,
                "remote": c.remote_address, "hostname": hostname,
                "port": c.remote_port,
            },
        ))

    return findings


# ── Processanalys ────────────────────────────────────────────────────────────

def check_processes() -> list[Finding]:
    """Check for suspicious or unexpected processes with network access."""
    findings = []
    stdout, _, rc = run_command(["lsof", "-i", "-P", "-n"])
    if rc != 0:
        return findings

    connections = parse_lsof_output(stdout)

    # Count connections per process
    process_conns: dict[str, int] = {}
    for c in connections:
        process_conns[c.command] = process_conns.get(c.command, 0) + 1

    # Flag processes with unusually many connections
    for proc, count in sorted(process_conns.items(), key=lambda x: -x[1]):
        if count > 50 and not _is_known_process(proc):
            findings.append(Finding(
                category="process",
                title=f"{proc}: {count} nätverksanslutningar",
                severity=Severity.YELLOW,
                description=f"Processen {proc} har ovanligt många ({count}) anslutningar.",
                recommendation="Undersök varför denna process har så många anslutningar.",
                raw_data={"command": proc, "connection_count": count},
            ))

    # Check for processes running as root with network access
    root_network = {c.command for c in connections if c.user == "root"}
    non_system_root = {p for p in root_network if not _is_known_process(p)}
    if non_system_root:
        findings.append(Finding(
            category="process",
            title="Processer med nätverksåtkomst som root",
            severity=Severity.YELLOW,
            description=f"Följande processer kör som root med nätverksåtkomst:\n"
                        + "\n".join(f"  • {p}" for p in sorted(non_system_root)),
            recommendation="Kontrollera att dessa processer är förväntade.",
        ))

    if not findings:
        findings.append(Finding(
            category="process",
            title="Processanalys",
            severity=Severity.GREEN,
            description="Inga ovanliga processmönster upptäcktes.",
        ))

    return findings


# ── Kör alla kontroller ──────────────────────────────────────────────────────

def run_all_checks() -> list[Finding]:
    """Execute all security checks and return combined findings."""
    all_findings: list[Finding] = []
    all_findings.extend(check_firewall())
    all_findings.extend(check_wifi())
    all_findings.extend(check_dns())
    all_findings.extend(check_open_ports())
    all_findings.extend(check_active_connections())
    all_findings.extend(check_processes())
    return all_findings
