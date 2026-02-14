"""Shared utilities: command execution, lsof parsing, data models."""

import subprocess
import socket
import re
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from functools import lru_cache


class Severity(Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


@dataclass
class Finding:
    """A single security finding with traffic light severity."""
    category: str
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    raw_data: dict = field(default_factory=dict)


@dataclass
class ConnectionInfo:
    """Parsed network connection from lsof output."""
    command: str
    pid: int
    user: str
    protocol: str          # TCP / UDP
    local_address: str
    local_port: Optional[int]
    remote_address: Optional[str] = None
    remote_port: Optional[int] = None
    state: Optional[str] = None


def run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Execute a system command safely. Returns (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"Kommando hittades inte: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return "", f"Kommando tog för lång tid (>{timeout}s): {' '.join(cmd)}", -2
    except PermissionError:
        return "", f"Behörighet saknas: {cmd[0]}", -3
    except Exception as e:
        return "", f"Oväntat fel: {e}", -4


def parse_lsof_output(output: str) -> list[ConnectionInfo]:
    """
    Parse output from `lsof -i -P -n`.

    NAME field formats:
      *:7000 (LISTEN)
      127.0.0.1:8080 (LISTEN)
      [::1]:42050 (LISTEN)
      192.168.1.69:51540->192.168.1.57:49585 (ESTABLISHED)
      *:*
    """
    connections = []
    lines = output.strip().splitlines()
    if not lines:
        return connections

    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue

        command = parts[0]
        try:
            pid = int(parts[1])
        except ValueError:
            continue

        user = parts[2]

        # Find protocol (TCP/UDP) – usually at index 7 or in the TYPE/NODE columns
        protocol = None
        name_start = None
        for i, p in enumerate(parts):
            if p in ("TCP", "UDP"):
                protocol = p
                name_start = i + 1
                break

        if protocol is None or name_start is None or name_start >= len(parts):
            continue

        # Everything after the protocol is the NAME field (may contain spaces for state)
        name_field = " ".join(parts[name_start:])

        # Extract state from parentheses at the end
        state = None
        state_match = re.search(r'\((\w+)\)\s*$', name_field)
        if state_match:
            state = state_match.group(1)
            name_field = name_field[:state_match.start()].strip()

        # Split on -> for remote connections
        local_part = name_field
        remote_part = None
        if "->" in name_field:
            local_part, remote_part = name_field.split("->", 1)

        local_address, local_port = _parse_address(local_part.strip())
        remote_address, remote_port = (None, None)
        if remote_part:
            remote_address, remote_port = _parse_address(remote_part.strip())

        connections.append(ConnectionInfo(
            command=command,
            pid=pid,
            user=user,
            protocol=protocol,
            local_address=local_address,
            local_port=local_port,
            remote_address=remote_address,
            remote_port=remote_port,
            state=state,
        ))

    return connections


def _parse_address(addr_str: str) -> tuple[str, Optional[int]]:
    """Parse 'host:port' or '[ipv6]:port' or '*:*'."""
    if addr_str == "*:*":
        return "*", None

    # IPv6 in brackets: [::1]:42050
    ipv6_match = re.match(r'\[([^\]]+)\]:(\d+)', addr_str)
    if ipv6_match:
        return ipv6_match.group(1), int(ipv6_match.group(2))

    # Regular host:port – split on last colon
    idx = addr_str.rfind(":")
    if idx == -1:
        return addr_str, None

    host = addr_str[:idx]
    port_str = addr_str[idx + 1:]
    try:
        port = int(port_str)
    except ValueError:
        port = None

    return host, port


# DNS cache for reverse lookups
_dns_cache: dict[str, Optional[str]] = {}


def reverse_dns(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup with caching."""
    if ip in _dns_cache:
        return _dns_cache[ip]

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        _dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        _dns_cache[ip] = None
        return None


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    if ip in ("*", "localhost"):
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
