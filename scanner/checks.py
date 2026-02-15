"""Security checks for macOS — firewall, WiFi, DNS, ports, connections, processes, traffic, home network."""

import datetime
import ipaddress
import json
import os
import plistlib
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
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


# ── Hemnätverksanalys ────────────────────────────────────────────────────────

# OUI database – top ~100 vendors for home network device identification
_OUI_DB: dict[str, str] = {
    # Apple
    "00:1c:b3": "Apple", "00:1e:c2": "Apple", "00:25:00": "Apple",
    "00:26:bb": "Apple", "00:3e:e1": "Apple", "00:50:e4": "Apple",
    "00:cd:fe": "Apple", "18:ee:69": "Apple", "28:6a:ba": "Apple",
    "3c:22:fb": "Apple", "40:b3:95": "Apple", "48:d7:05": "Apple",
    "54:26:96": "Apple", "5c:f7:e6": "Apple", "60:03:08": "Apple",
    "64:70:02": "Apple", "68:5b:35": "Apple", "70:de:e2": "Apple",
    "7c:d1:c3": "Apple", "80:e6:50": "Apple", "88:66:a5": "Apple",
    "8c:85:90": "Apple", "98:01:a7": "Apple", "a4:83:e7": "Apple",
    "ac:bc:32": "Apple", "b0:34:95": "Apple", "b8:e8:56": "Apple",
    "c8:2a:14": "Apple", "d0:81:7a": "Apple", "dc:a9:04": "Apple",
    "e0:b5:5f": "Apple", "f0:18:98": "Apple", "f4:5c:89": "Apple",
    # Samsung
    "00:07:ab": "Samsung", "00:12:fb": "Samsung", "00:15:99": "Samsung",
    "00:16:32": "Samsung", "00:21:19": "Samsung", "08:d4:6a": "Samsung",
    "10:d5:42": "Samsung", "18:3a:2d": "Samsung", "34:23:ba": "Samsung",
    "50:01:bb": "Samsung", "78:47:1d": "Samsung", "84:25:db": "Samsung",
    "94:35:0a": "Samsung", "bc:72:b1": "Samsung", "c4:73:1e": "Samsung",
    "f0:25:b7": "Samsung",
    # Google
    "00:1a:11": "Google", "3c:5a:b4": "Google", "54:60:09": "Google",
    "94:eb:2c": "Google", "f4:f5:d8": "Google",
    # Netgear
    "00:09:5b": "Netgear", "00:14:6c": "Netgear", "00:1e:2a": "Netgear",
    "00:24:b2": "Netgear", "10:0c:6b": "Netgear", "20:0c:c8": "Netgear",
    "a4:2b:8c": "Netgear", "c4:04:15": "Netgear",
    # TP-Link
    "00:27:19": "TP-Link", "14:cc:20": "TP-Link", "50:c7:bf": "TP-Link",
    "60:32:b1": "TP-Link", "b0:4e:26": "TP-Link", "c0:25:e9": "TP-Link",
    "ec:08:6b": "TP-Link",
    # ASUS
    "00:0c:6e": "ASUS", "00:15:f2": "ASUS", "04:d4:c4": "ASUS",
    "1c:87:2c": "ASUS", "2c:fd:a1": "ASUS", "ac:22:05": "ASUS",
    # D-Link
    "00:05:5d": "D-Link", "00:11:95": "D-Link", "00:19:5b": "D-Link",
    "1c:7e:e5": "D-Link", "28:10:7b": "D-Link", "b8:a3:86": "D-Link",
    # Cisco
    "00:00:0c": "Cisco", "00:1a:2b": "Cisco",
    # Sonos
    "00:0e:58": "Sonos", "5c:aa:fd": "Sonos", "78:28:ca": "Sonos",
    "b8:e9:37": "Sonos",
    # Amazon (Echo, etc.)
    "00:71:47": "Amazon", "10:ce:a9": "Amazon", "14:91:82": "Amazon",
    "34:d2:70": "Amazon", "68:54:fd": "Amazon", "fc:65:de": "Amazon",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    # Intel
    "00:02:b3": "Intel", "00:13:e8": "Intel", "00:1b:21": "Intel",
    "3c:97:0e": "Intel", "68:05:ca": "Intel",
    # VMware
    "00:50:56": "VMware", "00:0c:29": "VMware",
    # Microsoft
    "00:15:5d": "Microsoft (Hyper-V)",
    # Espressif (IoT)
    "24:0a:c4": "Espressif (IoT)", "30:ae:a4": "Espressif (IoT)",
    "a4:cf:12": "Espressif (IoT)",
    # Philips Hue
    "00:17:88": "Philips Hue",
    # Ring
    "24:ec:99": "Ring",
    # Ubiquiti
    "04:18:d6": "Ubiquiti", "24:5a:4c": "Ubiquiti",
    "78:8a:20": "Ubiquiti", "f0:9f:c2": "Ubiquiti",
    # Linksys
    "00:04:5a": "Linksys", "00:0c:41": "Linksys", "20:aa:4b": "Linksys",
    # Brother (printers)
    "00:1b:a9": "Brother", "00:80:77": "Brother",
    # HP (printers)
    "00:01:e6": "HP", "00:0b:cd": "HP", "00:14:38": "HP",
    # Roku
    "b0:a7:37": "Roku", "dc:3a:5e": "Roku",
}


def _oui_lookup(mac: str) -> str:
    """Lookup vendor from first 3 octets of MAC address."""
    # Normalize MAC: ensure each octet is zero-padded (e.g., "a:b:cc" → "0a:0b:cc")
    parts = mac.lower().split(":")
    if len(parts) >= 3:
        normalized = ":".join(p.zfill(2) for p in parts[:3])
        return _OUI_DB.get(normalized, "Okänd")
    return "Okänd"


def _get_gateway_ip() -> Optional[str]:
    """Get LAN gateway IP. Uses networksetup for Wi-Fi to bypass VPN routing."""
    # Try networksetup first (gives LAN router even when VPN is active)
    stdout, _, rc = run_command(["networksetup", "-getinfo", "Wi-Fi"])
    if rc == 0:
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Router:"):
                router = stripped.split(":", 1)[1].strip()
                if router and router != "none":
                    return router
    # Fallback to route command
    stdout, _, rc = run_command(["route", "-n", "get", "default"])
    if rc != 0:
        return None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("gateway:"):
            return stripped.split(":", 1)[1].strip()
    return None


def _get_own_ip() -> Optional[str]:
    """Get own IP on the local network. Uses en0 first to bypass VPN."""
    # Try en0 (Wi-Fi) directly – works even when VPN is active
    stdout, _, rc = run_command(["ipconfig", "getifaddr", "en0"])
    if rc == 0 and stdout.strip():
        return stdout.strip()
    # Fallback: parse route for interface
    stdout, _, rc = run_command(["route", "-n", "get", "default"])
    if rc != 0:
        return None
    interface = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
            break
    if not interface:
        return None
    stdout2, _, rc2 = run_command(["ipconfig", "getifaddr", interface])
    if rc2 != 0:
        return None
    return stdout2.strip() or None


def _get_local_subnet() -> Optional[str]:
    """Get the /24 subnet prefix (e.g., '192.168.1') from own IP."""
    own_ip = _get_own_ip()
    if not own_ip:
        return None
    parts = own_ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return None


def _parse_ping_stats(output: str) -> Optional[dict]:
    """Parse ping output for min/avg/max/stddev and packet loss."""
    if not output:
        return None

    stats: dict = {}

    # Packet loss: "X packets transmitted, Y packets received, Z% packet loss"
    loss_match = re.search(r"([\d.]+)% packet loss", output)
    if loss_match:
        stats["loss"] = float(loss_match.group(1))
    else:
        stats["loss"] = 0.0

    # Round-trip: "min/avg/max/stddev = 1.234/5.678/9.012/3.456 ms"
    rtt_match = re.search(
        r"min/avg/max/stddev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output
    )
    if rtt_match:
        stats["min"] = float(rtt_match.group(1))
        stats["avg"] = float(rtt_match.group(2))
        stats["max"] = float(rtt_match.group(3))
        stats["stddev"] = float(rtt_match.group(4))
        return stats

    return None


# Ports to scan on home network devices
_HOME_SCAN_PORTS = [22, 23, 53, 80, 443, 445, 548, 554, 631, 5000, 5353, 8080, 8443, 8009, 9100, 32400]

# Risky ports on home network devices
_HOME_RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    23: ("Telnet", Severity.RED, "Telnet är okrypterat. Stäng av och använd SSH istället."),
    445: ("SMB", Severity.YELLOW, "SMB-fildelning exponerad. Kontrollera åtkomst."),
    554: ("RTSP", Severity.YELLOW, "RTSP (kameraprotokoll) öppet. Kontrollera kamerasäkerhet."),
    9100: ("Skrivare (RAW)", Severity.YELLOW, "Skrivarport öppen. Begränsa till nödvändig åtkomst."),
}


def check_network_devices() -> list[Finding]:
    """Discover devices on the local /24 subnet via ping sweep + ARP."""
    findings: list[Finding] = []

    subnet = _get_local_subnet()
    gateway = _get_gateway_ip()
    own_ip = _get_own_ip()

    if not subnet:
        findings.append(Finding(
            category="home_network",
            title="Enhetssökning misslyckades",
            severity=Severity.YELLOW,
            description="Kunde inte bestämma lokalt subnät.",
            recommendation="Kontrollera att du är ansluten till ett nätverk.",
        ))
        return findings

    # Ping sweep: concurrent pings to all 254 addresses
    def _ping_ip(ip: str) -> bool:
        _, _, rc = run_command(["ping", "-c", "1", "-W", "1", ip], timeout=5)
        return rc == 0

    responsive_ips: list[str] = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {}
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            futures[executor.submit(_ping_ip, ip)] = ip
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    responsive_ips.append(ip)
            except Exception:
                pass

    # Parse ARP table to get MAC addresses for discovered devices
    arp_out, _, arp_rc = run_command(["arp", "-a"])
    ip_to_mac: dict[str, str] = {}
    if arp_rc == 0:
        for line in arp_out.splitlines():
            match = re.match(r".*?\(([^)]+)\)\s+at\s+([0-9a-f:]+)", line, re.IGNORECASE)
            if match:
                ip_to_mac[match.group(1)] = match.group(2).lower()

    # Build device table
    devices: list[dict[str, str]] = []
    for ip in sorted(responsive_ips, key=lambda x: list(map(int, x.split(".")))):
        mac = ip_to_mac.get(ip, "okänd")
        vendor = _oui_lookup(mac) if mac != "okänd" else "Okänd"
        label = ""
        if ip == gateway:
            label = " (router)"
        elif ip == own_ip:
            label = " (denna dator)"
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "label": label,
        })

    # Format device table as description text
    device_lines = []
    for d in devices:
        device_lines.append(
            f"  {d['ip']:16s} {d['mac']:18s} {d['vendor']}{d['label']}"
        )
    table_header = f"  {'IP':16s} {'MAC':18s} Tillverkare"
    table_str = table_header + "\n" + "\n".join(device_lines)

    findings.append(Finding(
        category="home_network",
        title=f"{len(devices)} enheter hittades på nätverket",
        severity=Severity.GREEN,
        description=f"Subnät: {subnet}.0/24\n\n{table_str}",
        raw_data={"devices": devices, "subnet": subnet},
    ))

    return findings


def check_device_ports() -> list[Finding]:
    """Scan common ports on discovered home network devices."""
    findings: list[Finding] = []

    gateway = _get_gateway_ip()
    own_ip = _get_own_ip()

    # Get devices from ARP table
    arp_out, _, arp_rc = run_command(["arp", "-a"])
    if arp_rc != 0:
        findings.append(Finding(
            category="home_network",
            title="Portskanning misslyckades",
            severity=Severity.YELLOW,
            description="Kunde inte läsa ARP-tabellen för att hitta enheter.",
        ))
        return findings

    device_ips: list[str] = []
    for line in arp_out.splitlines():
        match = re.match(r".*?\(([^)]+)\)\s+at\s+([0-9a-f:]+)", line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2)
            if mac.lower() not in ("ff:ff:ff:ff:ff:ff", "(incomplete)"):
                if ip != own_ip:
                    device_ips.append(ip)

    if not device_ips:
        findings.append(Finding(
            category="home_network",
            title="Inga enheter att skanna",
            severity=Severity.GREEN,
            description="Inga andra enheter hittades i ARP-tabellen.",
        ))
        return findings

    # Scan ports using socket.connect_ex
    def _check_port(ip: str, port: int) -> Optional[tuple]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return (ip, port)
        except (OSError, socket.error):
            pass
        return None

    open_ports: dict[str, list[int]] = {}  # ip -> [open ports]
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {}
        for ip in device_ips:
            for port in _HOME_SCAN_PORTS:
                futures[executor.submit(_check_port, ip, port)] = (ip, port)
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    ip, port = result
                    open_ports.setdefault(ip, []).append(port)
            except Exception:
                pass

    # Analyze results
    risky_found: list[str] = []
    worst_severity = Severity.GREEN

    for ip, ports in sorted(open_ports.items()):
        is_router = (ip == gateway)
        for port in sorted(ports):
            if port in _HOME_RISKY_PORTS:
                service, sev, desc = _HOME_RISKY_PORTS[port]
                risky_found.append(f"{ip}: port {port} ({service}) – {desc}")
                if sev == Severity.RED:
                    worst_severity = Severity.RED
                elif worst_severity != Severity.RED:
                    worst_severity = sev
            elif port in (80, 8080) and not is_router:
                risky_found.append(
                    f"{ip}: port {port} (HTTP) – Webbserver på enhet som inte är routern."
                )
                if worst_severity == Severity.GREEN:
                    worst_severity = Severity.YELLOW

    if risky_found:
        findings.append(Finding(
            category="home_network",
            title=f"{len(risky_found)} riskabla portar hittades",
            severity=worst_severity,
            description="\n".join(f"  • {r}" for r in risky_found),
            recommendation="Stäng portar som inte behövs och kontrollera enhetssäkerheten.",
            raw_data={"open_ports": {ip: ports for ip, ports in open_ports.items()}},
        ))
    else:
        port_summary_lines = []
        for ip, ports in sorted(open_ports.items()):
            port_summary_lines.append(f"  {ip}: {', '.join(str(p) for p in sorted(ports))}")
        desc = "Inga riskabla portar hittades på nätverkets enheter."
        if port_summary_lines:
            desc += "\n\nÖppna portar:\n" + "\n".join(port_summary_lines)
        findings.append(Finding(
            category="home_network",
            title="Portskanning av hemnätverket",
            severity=Severity.GREEN,
            description=desc,
            raw_data={"open_ports": {ip: ports for ip, ports in open_ports.items()}},
        ))

    return findings


def check_dns_hijacking() -> list[Finding]:
    """Check for DNS hijacking by querying non-existent domain and comparing resolvers."""
    findings: list[Finding] = []

    gateway = _get_gateway_ip()
    if not gateway:
        findings.append(Finding(
            category="home_network",
            title="DNS-kapningstest",
            severity=Severity.YELLOW,
            description="Kunde inte bestämma gateway-IP för DNS-test.",
        ))
        return findings

    # Test 1: Query non-existent domain via router's DNS
    nxdomain_out, _, nxdomain_rc = run_command(
        ["dig", f"@{gateway}", "thisdomaindoesnotexist12345.com", "+short"],
        timeout=10,
    )
    nxdomain_response = nxdomain_out.strip()

    if nxdomain_response and re.match(r"\d+\.\d+\.\d+\.\d+", nxdomain_response):
        findings.append(Finding(
            category="home_network",
            title="DNS-kapning detekterad!",
            severity=Severity.RED,
            description=(
                f"Routerns DNS ({gateway}) returnerade IP {nxdomain_response} "
                f"för en icke-existerande domän.\n"
                f"Detta tyder på DNS-omdirigering (hijacking)."
            ),
            recommendation=(
                "Kontrollera routerns DNS-inställningar. "
                "Byt till en säkrare DNS som 1.1.1.1 eller 9.9.9.9."
            ),
            raw_data={"gateway": gateway, "nxdomain_ip": nxdomain_response},
        ))
    else:
        findings.append(Finding(
            category="home_network",
            title="Ingen DNS-kapning",
            severity=Severity.GREEN,
            description=f"Routerns DNS ({gateway}) returnerade korrekt NXDOMAIN för okänd domän.",
        ))

    # Test 2: Cross-resolver comparison
    router_out, _, router_rc = run_command(
        ["dig", f"@{gateway}", "google.com", "+short"], timeout=10,
    )
    cf_out, _, cf_rc = run_command(
        ["dig", "@1.1.1.1", "google.com", "+short"], timeout=10,
    )

    if router_rc == 0 and cf_rc == 0:
        router_ips = set(router_out.strip().splitlines())
        cf_ips = set(cf_out.strip().splitlines())
        # Filter to only IP addresses (dig +short can return CNAME lines too)
        router_ips = {ip for ip in router_ips if re.match(r"\d+\.\d+\.\d+\.\d+", ip)}
        cf_ips = {ip for ip in cf_ips if re.match(r"\d+\.\d+\.\d+\.\d+", ip)}

        if router_ips and cf_ips and not router_ips.intersection(cf_ips):
            findings.append(Finding(
                category="home_network",
                title="DNS-svar skiljer sig mellan resolvers",
                severity=Severity.YELLOW,
                description=(
                    f"Router ({gateway}): {', '.join(sorted(router_ips))}\n"
                    f"Cloudflare (1.1.1.1): {', '.join(sorted(cf_ips))}\n"
                    f"Olika IP-svar kan tyda på DNS-manipulation."
                ),
                recommendation="Överväg att använda en betrodd DNS-resolver direkt.",
                raw_data={
                    "router_ips": sorted(router_ips),
                    "cloudflare_ips": sorted(cf_ips),
                },
            ))

    return findings


def check_network_quality() -> list[Finding]:
    """Check network quality: latency to gateway and internet, packet loss."""
    findings: list[Finding] = []

    gateway = _get_gateway_ip()
    if not gateway:
        findings.append(Finding(
            category="home_network",
            title="Nätverkskvalitet",
            severity=Severity.YELLOW,
            description="Kunde inte bestämma gateway för kvalitetstest.",
        ))
        return findings

    # Test 1: Gateway latency
    gw_out, _, gw_rc = run_command(
        ["ping", "-c", "10", "-i", "0.2", gateway], timeout=15,
    )
    gw_stats = _parse_ping_stats(gw_out)

    # Test 2: Internet latency
    inet_out, _, inet_rc = run_command(
        ["ping", "-c", "5", "8.8.8.8"], timeout=15,
    )
    inet_stats = _parse_ping_stats(inet_out)

    # Evaluate gateway quality
    if gw_stats:
        avg = gw_stats["avg"]
        loss = gw_stats["loss"]
        if avg < 10 and loss == 0.0:
            sev = Severity.GREEN
            desc = f"Gateway ({gateway}): {avg:.1f} ms genomsnitt, {loss:.0f}% förlust."
        elif avg < 50 and loss < 5:
            sev = Severity.YELLOW
            desc = f"Gateway ({gateway}): {avg:.1f} ms genomsnitt, {loss:.0f}% förlust. Något förhöjd latens."
        else:
            sev = Severity.RED
            desc = f"Gateway ({gateway}): {avg:.1f} ms genomsnitt, {loss:.0f}% förlust. Hög latens eller paketförlust!"

        desc += f"\n  Min/Avg/Max/Stddev: {gw_stats['min']:.1f}/{avg:.1f}/{gw_stats['max']:.1f}/{gw_stats['stddev']:.1f} ms"

        if inet_stats:
            desc += f"\n  Internet (8.8.8.8): {inet_stats['avg']:.1f} ms genomsnitt, {inet_stats['loss']:.0f}% förlust."

        findings.append(Finding(
            category="home_network",
            title="Nätverkskvalitet",
            severity=sev,
            description=desc,
            recommendation="Kontrollera router och kabelanslutningar." if sev != Severity.GREEN else "",
            raw_data={"gateway_stats": gw_stats, "internet_stats": inet_stats},
        ))
    else:
        findings.append(Finding(
            category="home_network",
            title="Nätverkskvalitet",
            severity=Severity.YELLOW,
            description="Kunde inte mäta latens till gateway.",
        ))

    return findings


def check_router_security() -> list[Finding]:
    """Analyze router security: open ports and vendor identification."""
    findings: list[Finding] = []

    gateway = _get_gateway_ip()
    if not gateway:
        findings.append(Finding(
            category="home_network",
            title="Routeranalys",
            severity=Severity.YELLOW,
            description="Kunde inte bestämma gateway-IP.",
        ))
        return findings

    # Get router MAC for vendor ID
    arp_out, _, arp_rc = run_command(["arp", "-a"])
    router_mac = None
    if arp_rc == 0:
        for line in arp_out.splitlines():
            match = re.match(r".*?\(([^)]+)\)\s+at\s+([0-9a-f:]+)", line, re.IGNORECASE)
            if match and match.group(1) == gateway:
                router_mac = match.group(2).lower()
                break

    router_vendor = _oui_lookup(router_mac) if router_mac else "Okänd"

    # Port scan router
    router_ports = [22, 23, 80, 443, 8080, 8443]
    open_router_ports: list[int] = []

    def _check_router_port(port: int) -> Optional[int]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((gateway, port))
            sock.close()
            if result == 0:
                return port
        except (OSError, socket.error):
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_check_router_port, p): p for p in router_ports}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    open_router_ports.append(result)
            except Exception:
                pass

    open_router_ports.sort()

    # Analyze
    issues: list[str] = []
    worst_severity = Severity.GREEN

    if 23 in open_router_ports:
        issues.append("Telnet (port 23) är öppet – extremt osäkert för fjärradministration!")
        worst_severity = Severity.RED

    if 80 in open_router_ports and 443 not in open_router_ports:
        issues.append("HTTP (port 80) utan HTTPS – administrationsgränssnittet saknar kryptering.")
        if worst_severity == Severity.GREEN:
            worst_severity = Severity.YELLOW

    if 8080 in open_router_ports:
        issues.append("Alternativ webbserver (port 8080) är öppen.")
        if worst_severity == Severity.GREEN:
            worst_severity = Severity.YELLOW

    port_list = ", ".join(str(p) for p in open_router_ports) if open_router_ports else "inga"
    desc = (
        f"Router: {gateway}\n"
        f"Tillverkare: {router_vendor}"
        + (f" ({router_mac})" if router_mac else "") + "\n"
        f"Öppna portar: {port_list}"
    )
    if issues:
        desc += "\n\nProblem:\n" + "\n".join(f"  • {issue}" for issue in issues)

    findings.append(Finding(
        category="home_network",
        title="Routersäkerhet",
        severity=worst_severity,
        description=desc,
        recommendation="Stäng onödiga portar och aktivera HTTPS för routerns adminpanel."
        if worst_severity != Severity.GREEN else "",
        raw_data={
            "gateway": gateway,
            "vendor": router_vendor,
            "mac": router_mac,
            "open_ports": open_router_ports,
        },
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
    # Hemnätverksanalys
    all_findings.extend(check_network_devices())
    all_findings.extend(check_device_ports())
    all_findings.extend(check_dns_hijacking())
    all_findings.extend(check_network_quality())
    all_findings.extend(check_router_security())
    return all_findings
