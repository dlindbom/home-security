"""Security checks for macOS — firewall, WiFi, DNS, ports, connections, processes, traffic."""

import datetime
import ipaddress
import json
import os
import plistlib
import re
from typing import Optional

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


# ── Trafikanalys – Modul C ───────────────────────────────────────────────────

# Known cloud provider CIDR prefixes for IP classification
_CLOUD_PROVIDERS: dict[str, list[str]] = {
    "Microsoft Azure": [
        "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14",
        "20.0.0.0/8",
        "40.64.0.0/10", "40.128.0.0/12",
        "52.96.0.0/12", "52.112.0.0/14", "52.120.0.0/14",
        "104.40.0.0/13", "104.208.0.0/13",
    ],
    "Amazon AWS": [
        "3.0.0.0/8", "18.0.0.0/8", "54.0.0.0/8",
        "35.160.0.0/11", "52.0.0.0/11",
        "99.77.0.0/16", "99.150.0.0/16",
    ],
    "Google Cloud": [
        "34.0.0.0/8", "35.190.0.0/15", "35.192.0.0/11",
        "142.250.0.0/15", "172.217.0.0/16",
        "216.58.0.0/16", "216.239.32.0/19",
    ],
    "Cloudflare": [
        "104.16.0.0/13", "104.24.0.0/14",
        "172.64.0.0/13", "173.245.48.0/20",
        "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "188.114.96.0/20",
    ],
    "Apple": [
        "17.0.0.0/8",
    ],
}

# Pre-compiled networks for fast lookup (built once at import time)
_CLOUD_NETWORKS: list = []
for _provider, _cidrs in _CLOUD_PROVIDERS.items():
    for _cidr in _cidrs:
        _CLOUD_NETWORKS.append((_provider, ipaddress.ip_network(_cidr, strict=False)))

_BASELINE_DIR = os.path.join(os.path.expanduser("~"), ".home-security")
_BASELINE_FILE = os.path.join(_BASELINE_DIR, "baseline.json")


def _classify_ip(ip_str: str) -> Optional[str]:
    """Return cloud provider name if the IP belongs to a known range, else None."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for provider, network in _CLOUD_NETWORKS:
        if addr in network:
            return provider
    return None


def _check_code_signatures(connections: list[ConnectionInfo]) -> list[Finding]:
    """Verify code signatures for processes with network connections."""
    findings: list[Finding] = []
    checked_pids: set[int] = set()

    for conn in connections:
        if conn.pid in checked_pids:
            continue
        checked_pids.add(conn.pid)

        # Skip known safe processes for speed
        if _is_known_process(conn.command):
            continue

        # Get executable path via ps
        stdout, _, rc = run_command(["ps", "-p", str(conn.pid), "-o", "comm="])
        if rc != 0 or not stdout.strip():
            continue

        exe_path = stdout.strip()

        # Skip if not an absolute path (some processes report just a name)
        if not exe_path.startswith("/"):
            continue

        # Run codesign verification
        cs_out, cs_err, cs_rc = run_command(
            ["/usr/bin/codesign", "-dvvv", exe_path], timeout=10
        )
        combined = cs_out + cs_err  # codesign writes to stderr

        if "not signed" in combined.lower() or "code object is not signed" in combined.lower():
            findings.append(Finding(
                category="traffic",
                title=f"Osignerad process: {conn.command}",
                severity=Severity.RED,
                description=(
                    f"Processen {conn.command} (PID {conn.pid}) har nätverksåtkomst "
                    f"men saknar kodsignatur.\nSökväg: {exe_path}"
                ),
                recommendation="Kontrollera om processen är legitim. Osignerad kod kan vara skadlig.",
                raw_data={"pid": conn.pid, "command": conn.command, "path": exe_path},
            ))
        elif "adhoc" in combined.lower():
            findings.append(Finding(
                category="traffic",
                title=f"Ad-hoc-signerad: {conn.command}",
                severity=Severity.YELLOW,
                description=(
                    f"Processen {conn.command} (PID {conn.pid}) är ad-hoc-signerad "
                    f"(ingen verifierad utvecklaridentitet).\nSökväg: {exe_path}"
                ),
                recommendation="Ad-hoc-signering saknar identitet. Verifiera att programmet är pålitligt.",
                raw_data={"pid": conn.pid, "command": conn.command, "path": exe_path},
            ))
        elif "invalid" in combined.lower() or "code is broken" in combined.lower():
            findings.append(Finding(
                category="traffic",
                title=f"Ogiltig signatur: {conn.command}",
                severity=Severity.RED,
                description=(
                    f"Processen {conn.command} (PID {conn.pid}) har en bruten/ogiltig signatur.\n"
                    f"Sökväg: {exe_path}"
                ),
                recommendation="Bruten kodsignatur kan tyda på manipulerad programvara.",
                raw_data={"pid": conn.pid, "command": conn.command, "path": exe_path},
            ))

    if not findings:
        findings.append(Finding(
            category="traffic",
            title="Kodsignaturer",
            severity=Severity.GREEN,
            description="Alla nätverksanslutna processer har giltiga kodsignaturer.",
        ))

    return findings


def _classify_connections(connections: list[ConnectionInfo]) -> list[Finding]:
    """Classify remote IPs against known cloud providers."""
    findings: list[Finding] = []
    external = [
        c for c in connections
        if c.state == "ESTABLISHED" and c.remote_address and not is_private_ip(c.remote_address)
    ]

    if not external:
        findings.append(Finding(
            category="traffic",
            title="IP-klassificering",
            severity=Severity.GREEN,
            description="Inga externa anslutningar att klassificera.",
        ))
        return findings

    provider_counts: dict[str, list[str]] = {}  # provider -> [process names]
    unclassified: list[ConnectionInfo] = []

    for conn in external:
        provider = _classify_ip(conn.remote_address)
        if provider:
            provider_counts.setdefault(provider, []).append(conn.command)
        else:
            unclassified.append(conn)

    if provider_counts:
        lines = []
        for provider, procs in sorted(provider_counts.items()):
            unique_procs = sorted(set(procs))
            lines.append(f"  {provider}: {len(procs)} ansl. ({', '.join(unique_procs)})")
        findings.append(Finding(
            category="traffic",
            title="IP-klassificering",
            severity=Severity.GREEN,
            description="Externa anslutningar per molnleverantör:\n" + "\n".join(lines),
            raw_data={"providers": {k: len(v) for k, v in provider_counts.items()}},
        ))

    if unclassified:
        # Flag unknown destinations from non-known processes
        for conn in unclassified:
            if _is_known_process(conn.command):
                continue
            hostname = reverse_dns(conn.remote_address) if conn.remote_address else None
            remote_display = hostname or conn.remote_address
            findings.append(Finding(
                category="traffic",
                title=f"Oklassificerad: {conn.command} → {remote_display}",
                severity=Severity.YELLOW,
                description=(
                    f"Process {conn.command} (PID {conn.pid}) ansluter till okänd destination.\n"
                    f"IP: {conn.remote_address}"
                    + (f" ({hostname})" if hostname else "")
                ),
                recommendation="Kontrollera om denna destination är förväntad.",
                raw_data={"command": conn.command, "remote": conn.remote_address, "hostname": hostname},
            ))

    if not findings:
        findings.append(Finding(
            category="traffic",
            title="IP-klassificering",
            severity=Severity.GREEN,
            description="Inga externa anslutningar att klassificera.",
        ))

    return findings


def _check_vpn_leak(connections: list[ConnectionInfo]) -> list[Finding]:
    """Detect VPN and check for traffic leaking outside the tunnel."""
    findings: list[Finding] = []

    # Check for utun interfaces via scutil --nwi
    stdout, _, rc = run_command(["scutil", "--nwi"])
    if rc != 0:
        return findings

    # Detect VPN: look for utun interfaces in the network info
    has_vpn = False
    vpn_interfaces: list[str] = []

    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("utun") and ":" in stripped:
            has_vpn = True
            iface = stripped.split()[0]
            if iface not in vpn_interfaces:
                vpn_interfaces.append(iface)

    if not has_vpn:
        findings.append(Finding(
            category="traffic",
            title="VPN-status",
            severity=Severity.YELLOW,
            description="Ingen VPN-tunnel (utun) hittades.",
            recommendation="Överväg att använda en VPN för ökad integritet.",
        ))
        return findings

    # VPN detected – check default route
    ns_out, _, ns_rc = run_command(["netstat", "-nr", "-f", "inet"])
    default_iface = None
    if ns_rc == 0:
        for line in ns_out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "default":
                default_iface = parts[-1]
                break

    vpn_is_default = default_iface and default_iface.startswith("utun")

    if vpn_is_default:
        findings.append(Finding(
            category="traffic",
            title="VPN-tunnel aktiv",
            severity=Severity.GREEN,
            description=(
                f"VPN-interfaces: {', '.join(vpn_interfaces)}\n"
                f"Standardrutt via: {default_iface}"
            ),
        ))
    else:
        findings.append(Finding(
            category="traffic",
            title="VPN-läcka: standardrutt",
            severity=Severity.RED,
            description=(
                f"VPN-tunnel hittad ({', '.join(vpn_interfaces)}) men standardrutten "
                f"går via {default_iface or 'okänt interface'} istället för tunneln."
            ),
            recommendation="Konfigurera VPN:en att tvinga all trafik genom tunneln (kill switch).",
            raw_data={"vpn_interfaces": vpn_interfaces, "default_iface": default_iface},
        ))

    return findings


def _check_baseline_diff(connections: list[ConnectionInfo]) -> list[Finding]:
    """Compare current state to previous baseline and save new snapshot."""
    findings: list[Finding] = []

    # Build current snapshot
    current_procs: dict[str, set[str]] = {}
    for conn in connections:
        if conn.state == "ESTABLISHED" and conn.remote_address:
            current_procs.setdefault(conn.command, set()).add(conn.remote_address)

    # Serializable form
    current_snapshot = {
        cmd: sorted(ips) for cmd, ips in current_procs.items()
    }

    # Load previous baseline if it exists
    prev_snapshot: dict[str, list[str]] = {}
    if os.path.exists(_BASELINE_FILE):
        try:
            with open(_BASELINE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                prev_snapshot = data.get("processes", {})
        except (json.JSONDecodeError, OSError):
            pass  # Corrupt file, treat as no baseline

    if prev_snapshot:
        # Compare: find new processes and new connections
        prev_cmds = set(prev_snapshot.keys())
        curr_cmds = set(current_snapshot.keys())
        new_procs = curr_cmds - prev_cmds

        if new_procs:
            proc_list = "\n".join(f"  • {p}" for p in sorted(new_procs))
            findings.append(Finding(
                category="traffic",
                title=f"{len(new_procs)} nya nätverksprocesser sedan förra skanningen",
                severity=Severity.YELLOW,
                description=f"Nya processer med nätverksanslutningar:\n{proc_list}",
                recommendation="Kontrollera om de nya processerna är förväntade.",
                raw_data={"new_processes": sorted(new_procs)},
            ))

        # Check for new remote IPs on existing processes
        new_connections: list[str] = []
        for cmd in curr_cmds & prev_cmds:
            prev_ips = set(prev_snapshot.get(cmd, []))
            curr_ips = set(current_snapshot.get(cmd, []))
            new_ips = curr_ips - prev_ips
            for ip in new_ips:
                if not is_private_ip(ip):
                    new_connections.append(f"{cmd} → {ip}")

        if new_connections:
            findings.append(Finding(
                category="traffic",
                title=f"{len(new_connections)} nya externa anslutningar",
                severity=Severity.YELLOW,
                description="Nya anslutningar sedan förra skanningen:\n"
                            + "\n".join(f"  • {c}" for c in new_connections[:20]),
                recommendation="Kontrollera att dessa anslutningar är förväntade.",
                raw_data={"new_connections": new_connections},
            ))

        if not findings:
            findings.append(Finding(
                category="traffic",
                title="Baslinje-jämförelse",
                severity=Severity.GREEN,
                description="Inga nya processer eller anslutningar sedan förra skanningen.",
            ))
    else:
        findings.append(Finding(
            category="traffic",
            title="Baslinje skapad",
            severity=Severity.GREEN,
            description="Första skanningen – en baslinje har sparats för framtida jämförelse.",
        ))

    # Save current snapshot as new baseline
    try:
        os.makedirs(_BASELINE_DIR, exist_ok=True)
        with open(_BASELINE_FILE, "w", encoding="utf-8") as fh:
            json.dump({
                "timestamp": datetime.datetime.now().isoformat(),
                "processes": current_snapshot,
            }, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass  # Can't write baseline; not critical

    return findings


def check_traffic() -> list[Finding]:
    """Modul C – Trafikanalys: kodsignaturer, IP-klassificering, VPN-läckor, baslinje."""
    findings: list[Finding] = []

    # Get connection data once (shared by sub-checks)
    stdout, stderr, rc = run_command(["lsof", "-i", "-P", "-n"])
    if rc != 0:
        findings.append(Finding(
            category="traffic",
            title="Trafikanalys misslyckades",
            severity=Severity.YELLOW,
            description=f"lsof kunde inte köras: {stderr.strip()}",
            recommendation="Testa: sudo lsof -i -P -n",
        ))
        return findings

    connections = parse_lsof_output(stdout)

    findings.extend(_check_code_signatures(connections))
    findings.extend(_classify_connections(connections))
    findings.extend(_check_vpn_leak(connections))
    findings.extend(_check_baseline_diff(connections))

    return findings


# ── Systemsäkerhet ────────────────────────────────────────────────────────────

def check_sip() -> list[Finding]:
    """Check System Integrity Protection status."""
    findings: list[Finding] = []
    stdout, stderr, rc = run_command(["csrutil", "status"])
    if rc != 0:
        findings.append(Finding(
            category="system",
            title="SIP-status",
            severity=Severity.YELLOW,
            description="Kunde inte kontrollera SIP-status.",
        ))
        return findings

    if "enabled" in stdout.lower():
        findings.append(Finding(
            category="system",
            title="System Integrity Protection",
            severity=Severity.GREEN,
            description="SIP är aktiverat.",
        ))
    else:
        findings.append(Finding(
            category="system",
            title="System Integrity Protection",
            severity=Severity.RED,
            description="SIP är avaktiverat – systemfiler saknar skydd.",
            recommendation="Starta om i Recovery Mode och kör: csrutil enable",
        ))
    return findings


def check_gatekeeper() -> list[Finding]:
    """Check Gatekeeper status."""
    findings: list[Finding] = []
    stdout, stderr, rc = run_command(["spctl", "--status"])
    # spctl returns exit code 0 if enabled, non-zero text varies
    combined = (stdout + stderr).lower()

    if "assessments enabled" in combined:
        findings.append(Finding(
            category="system",
            title="Gatekeeper",
            severity=Severity.GREEN,
            description="Gatekeeper är aktiverat – appar verifieras innan de körs.",
        ))
    else:
        findings.append(Finding(
            category="system",
            title="Gatekeeper",
            severity=Severity.RED,
            description="Gatekeeper är avaktiverat – appar från okända utvecklare kan köras.",
            recommendation="Aktivera: sudo spctl --master-enable",
        ))
    return findings


def check_filevault() -> list[Finding]:
    """Check FileVault disk encryption status."""
    findings: list[Finding] = []
    stdout, stderr, rc = run_command(["fdesetup", "status"])

    if rc != 0:
        findings.append(Finding(
            category="system",
            title="FileVault",
            severity=Severity.YELLOW,
            description="Kunde inte kontrollera FileVault-status.",
        ))
        return findings

    if "on" in stdout.lower():
        findings.append(Finding(
            category="system",
            title="FileVault diskkryptering",
            severity=Severity.GREEN,
            description="FileVault är aktiverat – disken är krypterad.",
        ))
    else:
        findings.append(Finding(
            category="system",
            title="FileVault diskkryptering",
            severity=Severity.RED,
            description="FileVault är avaktiverat – diskens data är okrypterad.",
            recommendation="Aktivera FileVault i Systeminställningar → Integritet och säkerhet.",
        ))
    return findings


def check_auto_updates() -> list[Finding]:
    """Check if automatic macOS software updates are enabled."""
    findings: list[Finding] = []

    # Check automatic check
    stdout, stderr, rc = run_command([
        "defaults", "read",
        "/Library/Preferences/com.apple.SoftwareUpdate",
        "AutomaticCheckEnabled",
    ])
    auto_check = stdout.strip() == "1" if rc == 0 else None

    # Check automatic download
    stdout2, stderr2, rc2 = run_command([
        "defaults", "read",
        "/Library/Preferences/com.apple.SoftwareUpdate",
        "AutomaticDownload",
    ])
    auto_download = stdout2.strip() == "1" if rc2 == 0 else None

    # Check automatic install for macOS updates
    stdout3, stderr3, rc3 = run_command([
        "defaults", "read",
        "/Library/Preferences/com.apple.SoftwareUpdate",
        "AutomaticallyInstallMacOSUpdates",
    ])
    auto_install = stdout3.strip() == "1" if rc3 == 0 else None

    parts = []
    if auto_check is True:
        parts.append("Automatisk sökning: på")
    elif auto_check is False:
        parts.append("Automatisk sökning: av")

    if auto_download is True:
        parts.append("Automatisk nedladdning: på")
    elif auto_download is False:
        parts.append("Automatisk nedladdning: av")

    if auto_install is True:
        parts.append("Automatisk installation: på")
    elif auto_install is False:
        parts.append("Automatisk installation: av")

    if not parts:
        findings.append(Finding(
            category="system",
            title="Automatiska uppdateringar",
            severity=Severity.YELLOW,
            description="Kunde inte läsa uppdateringsinställningar.",
        ))
        return findings

    all_on = auto_check is True and auto_download is True
    desc = "\n".join(parts)

    if all_on and auto_install is True:
        findings.append(Finding(
            category="system",
            title="Automatiska uppdateringar",
            severity=Severity.GREEN,
            description=desc,
        ))
    elif all_on:
        findings.append(Finding(
            category="system",
            title="Automatiska uppdateringar",
            severity=Severity.YELLOW,
            description=desc,
            recommendation="Aktivera automatisk installation av macOS-uppdateringar för bästa skydd.",
        ))
    else:
        findings.append(Finding(
            category="system",
            title="Automatiska uppdateringar",
            severity=Severity.YELLOW,
            description=desc,
            recommendation="Aktivera automatiska uppdateringar i Systeminställningar → Allmänt → Programuppdatering.",
        ))
    return findings


# ── ARP-tabell ────────────────────────────────────────────────────────────────

def check_arp_table() -> list[Finding]:
    """Analyze ARP table for duplicate MAC addresses (ARP spoofing indicator)."""
    findings: list[Finding] = []
    stdout, stderr, rc = run_command(["arp", "-a"])

    if rc != 0:
        findings.append(Finding(
            category="network_advanced",
            title="ARP-tabell",
            severity=Severity.YELLOW,
            description="Kunde inte läsa ARP-tabellen.",
        ))
        return findings

    # Parse ARP entries: hostname (ip) at mac on iface ...
    mac_to_ips: dict = {}
    entries = 0
    for line in stdout.splitlines():
        match = re.match(r".*?\(([^)]+)\)\s+at\s+([0-9a-f:]+)", line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower()
            if mac in ("ff:ff:ff:ff:ff:ff", "(incomplete)"):
                continue
            mac_to_ips.setdefault(mac, []).append(ip)
            entries += 1

    # Check for duplicate MACs (potential ARP spoofing)
    duplicates = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}

    if duplicates:
        dup_lines = []
        for mac, ips in duplicates.items():
            dup_lines.append(f"MAC {mac} → {', '.join(ips)}")
        findings.append(Finding(
            category="network_advanced",
            title="Duplicerade MAC-adresser",
            severity=Severity.RED,
            description="Samma MAC-adress svarar för flera IP:er – möjlig ARP-spoofing!\n"
                        + "\n".join(dup_lines),
            recommendation="Kontrollera att ingen obehörig enhet manipulerar nätverkstrafiken.",
        ))
    else:
        findings.append(Finding(
            category="network_advanced",
            title="ARP-tabell",
            severity=Severity.GREEN,
            description=f"{entries} enheter i ARP-tabellen, inga duplicerade MAC-adresser.",
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
    all_findings.extend(check_traffic())
    all_findings.extend(check_sip())
    all_findings.extend(check_gatekeeper())
    all_findings.extend(check_filevault())
    all_findings.extend(check_auto_updates())
    all_findings.extend(check_arp_table())
    return all_findings
