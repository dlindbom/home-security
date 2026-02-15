"""Tests for scanner.checks — mocked system commands."""

import json
import unittest
from unittest.mock import patch, mock_open, MagicMock

from scanner.checks import (
    check_firewall,
    check_dns,
    check_open_ports,
    check_active_connections,
    check_processes,
    check_traffic,
    check_sip,
    check_gatekeeper,
    check_filevault,
    check_auto_updates,
    check_arp_table,
    check_network_devices,
    check_device_ports,
    check_dns_hijacking,
    check_network_quality,
    check_router_security,
    run_all_checks,
    _classify_ip,
    _check_code_signatures,
    _classify_connections,
    _check_vpn_leak,
    _check_baseline_diff,
    _oui_lookup,
    _get_gateway_ip,
    _get_own_ip,
    _get_local_subnet,
    _parse_ping_stats,
)
from scanner.utils import Severity, ConnectionInfo


class TestCheckFirewall(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_firewall_enabled(self, mock_cmd):
        mock_cmd.side_effect = [
            ("Firewall is enabled. (State = 1)", "", 0),
            ("Stealth mode enabled", "", 0),
        ]
        findings = check_firewall()
        self.assertTrue(any(f.severity == Severity.GREEN and "brandvägg" in f.title.lower() for f in findings))

    @patch("scanner.checks.run_command")
    def test_firewall_disabled(self, mock_cmd):
        mock_cmd.side_effect = [
            ("Firewall is disabled. (State = 0)", "", 0),
            ("Stealth mode disabled", "", 0),
        ]
        findings = check_firewall()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))

    @patch("scanner.checks.run_command")
    def test_firewall_command_fails(self, mock_cmd):
        mock_cmd.return_value = ("", "Permission denied", 1)
        findings = check_firewall()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.YELLOW)


class TestCheckDns(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_secure_dns(self, mock_cmd):
        mock_cmd.return_value = (
            "resolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 1.0.0.1\n",
            "", 0,
        )
        findings = check_dns()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))

    @patch("scanner.checks.run_command")
    def test_router_dns(self, mock_cmd):
        mock_cmd.return_value = (
            "resolver #1\n  nameserver[0] : 192.168.1.1\n",
            "", 0,
        )
        findings = check_dns()
        self.assertTrue(any("192.168.1.1" in f.description for f in findings))

    @patch("scanner.checks.run_command")
    def test_no_dns(self, mock_cmd):
        mock_cmd.return_value = ("resolver #1\n", "", 0)
        findings = check_dns()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))


class TestCheckOpenPorts(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_no_listeners(self, mock_cmd):
        mock_cmd.return_value = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n",
            "", 0,
        )
        findings = check_open_ports()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))

    @patch("scanner.checks.run_command")
    def test_risky_port(self, mock_cmd):
        mock_cmd.return_value = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "mongod  999 daniel 4u IPv4 0x1 0t0 TCP *:27017 (LISTEN)\n",
            "", 0,
        )
        findings = check_open_ports()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))


class TestCheckActiveConnections(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_no_connections(self, mock_cmd):
        mock_cmd.return_value = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n",
            "", 0,
        )
        findings = check_active_connections()
        self.assertTrue(any("Inga aktiva" in f.title for f in findings))


class TestCheckProcesses(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_normal_state(self, mock_cmd):
        mock_cmd.return_value = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "Safari  111 daniel 4u IPv4 0x1 0t0 TCP 10.0.0.5:55000->93.184.216.34:443 (ESTABLISHED)\n",
            "", 0,
        )
        findings = check_processes()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))


# ── Trafikanalys (Modul C) ──────────────────────────────────────────────────


class TestClassifyIp(unittest.TestCase):
    """Tests for _classify_ip — pure function, no mocking needed."""

    def test_apple_ip(self):
        self.assertEqual(_classify_ip("17.253.144.10"), "Apple")

    def test_aws_ip(self):
        self.assertEqual(_classify_ip("54.231.0.1"), "Amazon AWS")

    def test_cloudflare_ip(self):
        self.assertEqual(_classify_ip("104.18.1.1"), "Cloudflare")

    def test_google_ip(self):
        self.assertEqual(_classify_ip("142.250.74.14"), "Google Cloud")

    def test_azure_ip(self):
        self.assertEqual(_classify_ip("40.101.124.226"), "Microsoft Azure")

    def test_unknown_ip(self):
        self.assertIsNone(_classify_ip("93.184.216.34"))

    def test_private_ip_not_classified(self):
        self.assertIsNone(_classify_ip("192.168.1.1"))

    def test_invalid_ip(self):
        self.assertIsNone(_classify_ip("not-an-ip"))


class TestCheckCodeSignatures(unittest.TestCase):
    """Tests for _check_code_signatures."""

    @patch("scanner.checks.run_command")
    def test_unsigned_process_is_red(self, mock_cmd):
        conns = [ConnectionInfo(
            command="badproc", pid=999, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        mock_cmd.side_effect = [
            ("/usr/local/bin/badproc\n", "", 0),                  # ps
            ("", "/usr/local/bin/badproc: code object is not signed at all\n", 3),  # codesign
        ]
        findings = _check_code_signatures(conns)
        self.assertTrue(any(f.severity == Severity.RED and "Osignerad" in f.title for f in findings))

    @patch("scanner.checks.run_command")
    def test_adhoc_process_is_yellow(self, mock_cmd):
        conns = [ConnectionInfo(
            command="myapp", pid=500, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        mock_cmd.side_effect = [
            ("/usr/local/bin/myapp\n", "", 0),                   # ps
            ("", "CodeDirectory flags=0x20002(adhoc,linker-signed)\n", 0),  # codesign
        ]
        findings = _check_code_signatures(conns)
        self.assertTrue(any(f.severity == Severity.YELLOW and "Ad-hoc" in f.title for f in findings))

    @patch("scanner.checks.run_command")
    def test_valid_signature_is_green(self, mock_cmd):
        conns = [ConnectionInfo(
            command="myapp", pid=500, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        mock_cmd.side_effect = [
            ("/usr/local/bin/myapp\n", "", 0),                     # ps
            ("", "Executable=/usr/local/bin/myapp\nAuthority=Developer ID Application: Foo\nvalid on disk\n", 0),  # codesign
        ]
        findings = _check_code_signatures(conns)
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))

    @patch("scanner.checks.run_command")
    def test_known_process_skipped(self, mock_cmd):
        """Known safe processes should not be checked."""
        conns = [ConnectionInfo(
            command="Safari", pid=100, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        # run_command should never be called for Safari
        findings = _check_code_signatures(conns)
        mock_cmd.assert_not_called()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))

    @patch("scanner.checks.run_command")
    def test_process_path_not_found_skipped(self, mock_cmd):
        """Process without absolute path should be skipped."""
        conns = [ConnectionInfo(
            command="myapp", pid=500, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        mock_cmd.return_value = ("myapp\n", "", 0)  # ps returns just name, not path
        findings = _check_code_signatures(conns)
        # Should get green (skipped = no bad findings)
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))


class TestClassifyConnections(unittest.TestCase):
    """Tests for _classify_connections."""

    def test_known_provider_is_green(self):
        conns = [ConnectionInfo(
            command="Safari", pid=100, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="17.253.144.10", remote_port=443, state="ESTABLISHED",
        )]
        with patch("scanner.checks.reverse_dns", return_value=None):
            findings = _classify_connections(conns)
        self.assertTrue(any(f.severity == Severity.GREEN and "Apple" in f.description for f in findings))

    def test_unknown_from_unknown_process_is_yellow(self):
        conns = [ConnectionInfo(
            command="badproc", pid=999, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        with patch("scanner.checks.reverse_dns", return_value="example.com"):
            findings = _classify_connections(conns)
        self.assertTrue(any(f.severity == Severity.YELLOW and "Oklassificerad" in f.title for f in findings))

    def test_no_external_connections(self):
        conns = [ConnectionInfo(
            command="Safari", pid=100, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="192.168.1.1", remote_port=80, state="ESTABLISHED",
        )]
        findings = _classify_connections(conns)
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))


class TestCheckVpnLeak(unittest.TestCase):
    """Tests for _check_vpn_leak."""

    @patch("scanner.checks.run_command")
    def test_no_vpn_is_yellow(self, mock_cmd):
        mock_cmd.return_value = (
            "Network information\n  en0 : flags 0x5 (IPv4)\n",
            "", 0,
        )
        findings = _check_vpn_leak([])
        self.assertTrue(any(
            f.severity == Severity.YELLOW and "Ingen VPN" in f.description
            for f in findings
        ))

    @patch("scanner.checks.run_command")
    def test_vpn_active_no_leak_is_green(self, mock_cmd):
        mock_cmd.side_effect = [
            # scutil --nwi
            ("Network information\n  utun4 : flags 0x5 (IPv4)\n  en0 : flags 0x5\n", "", 0),
            # netstat -nr -f inet
            (
                "Routing tables\n"
                "Internet:\n"
                "Destination        Gateway            Flags   Netif\n"
                "default            100.64.0.1         UGSc    utun4\n",
                "", 0,
            ),
        ]
        findings = _check_vpn_leak([])
        self.assertTrue(any(
            f.severity == Severity.GREEN and "VPN-tunnel aktiv" in f.title
            for f in findings
        ))

    @patch("scanner.checks.run_command")
    def test_vpn_leak_is_red(self, mock_cmd):
        mock_cmd.side_effect = [
            # scutil --nwi – utun present
            ("Network information\n  utun4 : flags 0x5 (IPv4)\n", "", 0),
            # netstat – default goes through en0, not utun
            (
                "Routing tables\n"
                "Internet:\n"
                "Destination        Gateway            Flags   Netif\n"
                "default            192.168.1.1        UGSc    en0\n",
                "", 0,
            ),
        ]
        findings = _check_vpn_leak([])
        self.assertTrue(any(
            f.severity == Severity.RED and "läcka" in f.title.lower()
            for f in findings
        ))

    @patch("scanner.checks.run_command")
    def test_scutil_fails_returns_empty(self, mock_cmd):
        mock_cmd.return_value = ("", "error", 1)
        findings = _check_vpn_leak([])
        self.assertEqual(findings, [])


class TestCheckBaselineDiff(unittest.TestCase):
    """Tests for _check_baseline_diff."""

    @patch("scanner.checks.os.makedirs")
    @patch("builtins.open", mock_open())
    @patch("scanner.checks.os.path.exists", return_value=False)
    def test_first_run_creates_baseline(self, *_):
        conns = [ConnectionInfo(
            command="Safari", pid=100, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="17.253.144.10", remote_port=443, state="ESTABLISHED",
        )]
        findings = _check_baseline_diff(conns)
        self.assertTrue(any(
            "Baslinje skapad" in f.title for f in findings
        ))

    @patch("scanner.checks.os.makedirs")
    @patch("scanner.checks.os.path.exists", return_value=True)
    def test_no_changes_is_green(self, mock_exists, mock_makedirs):
        conns = [ConnectionInfo(
            command="Safari", pid=100, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="17.253.144.10", remote_port=443, state="ESTABLISHED",
        )]
        baseline_data = json.dumps({
            "timestamp": "2026-02-14T12:00:00",
            "processes": {"Safari": ["17.253.144.10"]},
        })
        with patch("builtins.open", mock_open(read_data=baseline_data)):
            findings = _check_baseline_diff(conns)
        self.assertTrue(any(
            f.severity == Severity.GREEN and "Inga nya" in f.description
            for f in findings
        ))

    @patch("scanner.checks.os.makedirs")
    @patch("scanner.checks.os.path.exists", return_value=True)
    def test_new_process_detected(self, mock_exists, mock_makedirs):
        conns = [
            ConnectionInfo(
                command="Safari", pid=100, user="daniel",
                protocol="TCP", local_address="10.0.0.5", local_port=55000,
                remote_address="17.253.144.10", remote_port=443, state="ESTABLISHED",
            ),
            ConnectionInfo(
                command="newproc", pid=999, user="daniel",
                protocol="TCP", local_address="10.0.0.5", local_port=55001,
                remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
            ),
        ]
        baseline_data = json.dumps({
            "timestamp": "2026-02-14T12:00:00",
            "processes": {"Safari": ["17.253.144.10"]},
        })
        with patch("builtins.open", mock_open(read_data=baseline_data)):
            findings = _check_baseline_diff(conns)
        self.assertTrue(any(
            f.severity == Severity.YELLOW and "nya nätverksprocesser" in f.title
            for f in findings
        ))

    @patch("scanner.checks.os.makedirs")
    @patch("scanner.checks.os.path.exists", return_value=True)
    def test_new_connection_detected(self, mock_exists, mock_makedirs):
        conns = [ConnectionInfo(
            command="Safari", pid=100, user="daniel",
            protocol="TCP", local_address="10.0.0.5", local_port=55000,
            remote_address="93.184.216.34", remote_port=443, state="ESTABLISHED",
        )]
        baseline_data = json.dumps({
            "timestamp": "2026-02-14T12:00:00",
            "processes": {"Safari": ["17.253.144.10"]},
        })
        with patch("builtins.open", mock_open(read_data=baseline_data)):
            findings = _check_baseline_diff(conns)
        self.assertTrue(any(
            f.severity == Severity.YELLOW and "nya externa" in f.title
            for f in findings
        ))


class TestCheckTraffic(unittest.TestCase):
    """Integration tests for check_traffic()."""

    @patch("scanner.checks.run_command")
    def test_lsof_failure(self, mock_cmd):
        mock_cmd.return_value = ("", "Permission denied", 1)
        findings = check_traffic()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.YELLOW)
        self.assertEqual(findings[0].category, "traffic")

    @patch("scanner.checks.os.makedirs")
    @patch("builtins.open", mock_open())
    @patch("scanner.checks.os.path.exists", return_value=False)
    @patch("scanner.checks.run_command")
    def test_empty_lsof_all_green(self, mock_cmd, *_):
        """With only a header line, all sub-checks should produce green findings."""
        mock_cmd.side_effect = [
            ("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n", "", 0),  # lsof (main)
            # scutil --nwi for VPN check
            ("Network information\n  utun4 : flags 0x5\n", "", 0),
            # netstat for VPN check
            ("Destination Gateway Flags Netif\ndefault 100.64.0.1 UGSc utun4\n", "", 0),
        ]
        findings = check_traffic()
        self.assertTrue(all(f.category == "traffic" for f in findings))
        # Should have at least: codesig green, classify green, vpn green, baseline green
        self.assertGreaterEqual(len(findings), 3)


# ── SIP ───────────────────────────────────────────────────────────────────────

class TestCheckSip(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_sip_enabled(self, mock_cmd):
        mock_cmd.return_value = ("System Integrity Protection status: enabled.", "", 0)
        findings = check_sip()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.GREEN)

    @patch("scanner.checks.run_command")
    def test_sip_disabled(self, mock_cmd):
        mock_cmd.return_value = ("System Integrity Protection status: disabled.", "", 0)
        findings = check_sip()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.RED)

    @patch("scanner.checks.run_command")
    def test_sip_command_fails(self, mock_cmd):
        mock_cmd.return_value = ("", "error", 1)
        findings = check_sip()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.YELLOW)


# ── Gatekeeper ────────────────────────────────────────────────────────────────

class TestCheckGatekeeper(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_gatekeeper_enabled(self, mock_cmd):
        mock_cmd.return_value = ("assessments enabled", "", 0)
        findings = check_gatekeeper()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.GREEN)

    @patch("scanner.checks.run_command")
    def test_gatekeeper_disabled(self, mock_cmd):
        mock_cmd.return_value = ("assessments disabled", "", 0)
        findings = check_gatekeeper()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.RED)


# ── FileVault ─────────────────────────────────────────────────────────────────

class TestCheckFilevault(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_filevault_on(self, mock_cmd):
        mock_cmd.return_value = ("FileVault is On.", "", 0)
        findings = check_filevault()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.GREEN)

    @patch("scanner.checks.run_command")
    def test_filevault_off(self, mock_cmd):
        mock_cmd.return_value = ("FileVault is Off.", "", 0)
        findings = check_filevault()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.RED)

    @patch("scanner.checks.run_command")
    def test_filevault_command_fails(self, mock_cmd):
        mock_cmd.return_value = ("", "error", 1)
        findings = check_filevault()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.YELLOW)


# ── Auto Updates ──────────────────────────────────────────────────────────────

class TestCheckAutoUpdates(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_all_enabled(self, mock_cmd):
        def side_effect(cmd):
            if "AutomaticCheckEnabled" in cmd:
                return ("1", "", 0)
            if "AutomaticDownload" in cmd:
                return ("1", "", 0)
            if "AutomaticallyInstallMacOSUpdates" in cmd:
                return ("1", "", 0)
            return ("", "", 1)
        mock_cmd.side_effect = side_effect
        findings = check_auto_updates()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.GREEN)

    @patch("scanner.checks.run_command")
    def test_check_disabled(self, mock_cmd):
        def side_effect(cmd):
            if "AutomaticCheckEnabled" in cmd:
                return ("0", "", 0)
            if "AutomaticDownload" in cmd:
                return ("0", "", 0)
            if "AutomaticallyInstallMacOSUpdates" in cmd:
                return ("0", "", 0)
            return ("", "", 1)
        mock_cmd.side_effect = side_effect
        findings = check_auto_updates()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.YELLOW)


# ── ARP Table ─────────────────────────────────────────────────────────────────

class TestCheckArpTable(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_no_duplicates(self, mock_cmd):
        mock_cmd.return_value = (
            "router (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0\n"
            "device (192.168.1.2) at aa:bb:cc:dd:ee:02 on en0\n",
            "", 0
        )
        findings = check_arp_table()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.GREEN)
        self.assertIn("2 enheter", findings[0].description)

    @patch("scanner.checks.run_command")
    def test_duplicate_mac_is_red(self, mock_cmd):
        mock_cmd.return_value = (
            "router (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0\n"
            "fake (192.168.1.99) at aa:bb:cc:dd:ee:01 on en0\n",
            "", 0
        )
        findings = check_arp_table()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.RED)
        self.assertIn("ARP-spoofing", findings[0].description)

    @patch("scanner.checks.run_command")
    def test_arp_command_fails(self, mock_cmd):
        mock_cmd.return_value = ("", "error", 1)
        findings = check_arp_table()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.YELLOW)


# ── Hemnätverksanalys ────────────────────────────────────────────────────────


class TestOuiLookup(unittest.TestCase):
    def test_known_apple_mac(self):
        self.assertEqual(_oui_lookup("ac:bc:32:aa:bb:cc"), "Apple")

    def test_known_netgear_mac(self):
        self.assertEqual(_oui_lookup("10:0c:6b:aa:bb:cc"), "Netgear")

    def test_unknown_mac(self):
        self.assertEqual(_oui_lookup("00:00:00:aa:bb:cc"), "Okänd")

    def test_case_insensitive(self):
        self.assertEqual(_oui_lookup("AC:BC:32:AA:BB:CC"), "Apple")


class TestNetworkHelpers(unittest.TestCase):
    @patch("scanner.checks.run_command")
    def test_get_gateway_ip_via_networksetup(self, mock_cmd):
        mock_cmd.return_value = (
            "DHCP Configuration\n"
            "IP address: 192.168.1.68\n"
            "Subnet mask: 255.255.255.0\n"
            "Router: 192.168.1.1\n",
            "", 0,
        )
        self.assertEqual(_get_gateway_ip(), "192.168.1.1")

    @patch("scanner.checks.run_command")
    def test_get_gateway_ip_fallback_route(self, mock_cmd):
        mock_cmd.side_effect = [
            ("", "error", 1),  # networksetup fails
            (
                "   route to: default\n"
                "    gateway: 10.5.0.2\n"
                "  interface: utun4\n",
                "", 0,
            ),  # route works
        ]
        self.assertEqual(_get_gateway_ip(), "10.5.0.2")

    @patch("scanner.checks.run_command")
    def test_get_gateway_ip_fails(self, mock_cmd):
        mock_cmd.side_effect = [
            ("", "error", 1),  # networksetup fails
            ("", "error", 1),  # route fails
        ]
        self.assertIsNone(_get_gateway_ip())

    @patch("scanner.checks.run_command")
    def test_get_own_ip_via_en0(self, mock_cmd):
        mock_cmd.return_value = ("192.168.1.50\n", "", 0)
        self.assertEqual(_get_own_ip(), "192.168.1.50")

    @patch("scanner.checks.run_command")
    def test_get_own_ip_fallback_route(self, mock_cmd):
        mock_cmd.side_effect = [
            ("", "", 1),  # en0 fails
            ("   route to: default\n  interface: en1\n", "", 0),  # route
            ("192.168.1.50\n", "", 0),  # ipconfig getifaddr en1
        ]
        self.assertEqual(_get_own_ip(), "192.168.1.50")

    @patch("scanner.checks.run_command")
    def test_get_local_subnet(self, mock_cmd):
        mock_cmd.return_value = ("192.168.1.50\n", "", 0)
        self.assertEqual(_get_local_subnet(), "192.168.1")


class TestParsePingStats(unittest.TestCase):
    def test_normal_output(self):
        output = (
            "PING 192.168.1.1 (192.168.1.1): 56 data bytes\n"
            "64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=2.123 ms\n"
            "--- 192.168.1.1 ping statistics ---\n"
            "10 packets transmitted, 10 packets received, 0.0% packet loss\n"
            "round-trip min/avg/max/stddev = 1.234/2.345/5.678/1.234 ms\n"
        )
        stats = _parse_ping_stats(output)
        self.assertIsNotNone(stats)
        self.assertAlmostEqual(stats["avg"], 2.345)
        self.assertAlmostEqual(stats["loss"], 0.0)

    def test_with_packet_loss(self):
        output = (
            "--- ping statistics ---\n"
            "5 packets transmitted, 4 packets received, 20.0% packet loss\n"
            "round-trip min/avg/max/stddev = 1.0/5.0/10.0/3.0 ms\n"
        )
        stats = _parse_ping_stats(output)
        self.assertIsNotNone(stats)
        self.assertAlmostEqual(stats["loss"], 20.0)

    def test_empty_output(self):
        self.assertIsNone(_parse_ping_stats(""))


class TestCheckNetworkDevices(unittest.TestCase):
    @patch("scanner.checks._get_own_ip", return_value="192.168.1.50")
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks._get_local_subnet", return_value="192.168.1")
    @patch("scanner.checks.run_command")
    def test_discovers_devices(self, mock_cmd, *_):
        def side_effect(cmd, timeout=30):
            if cmd[0] == "ping":
                ip = cmd[-1]
                if ip in ("192.168.1.1", "192.168.1.50"):
                    return ("64 bytes", "", 0)
                return ("", "timeout", 1)
            if cmd[0] == "arp":
                return (
                    "router (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0\n"
                    "mypc (192.168.1.50) at aa:bb:cc:dd:ee:02 on en0\n",
                    "", 0,
                )
            return ("", "", 1)
        mock_cmd.side_effect = side_effect
        findings = check_network_devices()
        self.assertTrue(any("enheter hittades" in f.title for f in findings))
        self.assertEqual(findings[0].category, "home_network")

    @patch("scanner.checks._get_own_ip", return_value=None)
    @patch("scanner.checks._get_gateway_ip", return_value=None)
    @patch("scanner.checks._get_local_subnet", return_value=None)
    def test_no_subnet_is_yellow(self, *_):
        findings = check_network_devices()
        self.assertEqual(findings[0].severity, Severity.YELLOW)


class TestCheckDevicePorts(unittest.TestCase):
    @patch("scanner.checks.socket.socket")
    @patch("scanner.checks._get_own_ip", return_value="192.168.1.50")
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_telnet_is_red(self, mock_cmd, mock_gw, mock_own, mock_socket):
        mock_cmd.return_value = (
            "router (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0\n",
            "", 0,
        )
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        def connect_ex_side(addr):
            ip, port = addr
            if ip == "192.168.1.1" and port == 23:
                return 0  # open
            return 1  # closed
        mock_sock_instance.connect_ex = connect_ex_side
        findings = check_device_ports()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))

    @patch("scanner.checks._get_own_ip", return_value="192.168.1.50")
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_arp_fails_is_yellow(self, mock_cmd, *_):
        mock_cmd.return_value = ("", "error", 1)
        findings = check_device_ports()
        self.assertEqual(findings[0].severity, Severity.YELLOW)

    @patch("scanner.checks.socket.socket")
    @patch("scanner.checks._get_own_ip", return_value="192.168.1.50")
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_no_risky_ports_is_green(self, mock_cmd, mock_gw, mock_own, mock_socket):
        mock_cmd.return_value = (
            "router (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0\n",
            "", 0,
        )
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        # Only port 443 open (not risky)
        def connect_ex_side(addr):
            ip, port = addr
            if ip == "192.168.1.1" and port == 443:
                return 0
            return 1
        mock_sock_instance.connect_ex = connect_ex_side
        findings = check_device_ports()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))


class TestCheckDnsHijacking(unittest.TestCase):
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_nxdomain_is_green(self, mock_cmd, _):
        mock_cmd.side_effect = [
            ("\n", "", 0),  # dig nxdomain - empty response
            ("142.250.74.14\n", "", 0),  # dig router google.com
            ("142.250.74.14\n", "", 0),  # dig cloudflare google.com
        ]
        findings = check_dns_hijacking()
        self.assertTrue(any(
            f.severity == Severity.GREEN and "Ingen DNS-kapning" in f.title
            for f in findings
        ))

    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_hijack_detected_is_red(self, mock_cmd, _):
        mock_cmd.side_effect = [
            ("93.184.216.34\n", "", 0),  # dig nxdomain returns an IP!
            ("142.250.74.14\n", "", 0),  # dig router
            ("142.250.74.14\n", "", 0),  # dig cloudflare
        ]
        findings = check_dns_hijacking()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))

    @patch("scanner.checks._get_gateway_ip", return_value=None)
    def test_no_gateway_is_yellow(self, _):
        findings = check_dns_hijacking()
        self.assertEqual(findings[0].severity, Severity.YELLOW)


class TestCheckNetworkQuality(unittest.TestCase):
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_good_quality_is_green(self, mock_cmd, _):
        mock_cmd.side_effect = [
            (
                "10 packets transmitted, 10 packets received, 0.0% packet loss\n"
                "round-trip min/avg/max/stddev = 1.0/3.5/8.0/2.0 ms\n",
                "", 0,
            ),
            (
                "5 packets transmitted, 5 packets received, 0.0% packet loss\n"
                "round-trip min/avg/max/stddev = 10.0/15.0/20.0/3.0 ms\n",
                "", 0,
            ),
        ]
        findings = check_network_quality()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))

    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_high_latency_is_red(self, mock_cmd, _):
        mock_cmd.side_effect = [
            (
                "10 packets transmitted, 5 packets received, 50.0% packet loss\n"
                "round-trip min/avg/max/stddev = 100.0/200.0/500.0/100.0 ms\n",
                "", 0,
            ),
            ("", "timeout", 1),
        ]
        findings = check_network_quality()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))

    @patch("scanner.checks._get_gateway_ip", return_value=None)
    def test_no_gateway_is_yellow(self, _):
        findings = check_network_quality()
        self.assertEqual(findings[0].severity, Severity.YELLOW)


class TestCheckRouterSecurity(unittest.TestCase):
    @patch("scanner.checks.socket.socket")
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_telnet_on_router_is_red(self, mock_cmd, mock_gw, mock_socket):
        mock_cmd.return_value = (
            "router (192.168.1.1) at c4:04:15:aa:bb:cc on en0\n",
            "", 0,
        )
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        def connect_ex_side(addr):
            ip, port = addr
            if port == 23:
                return 0
            return 1
        mock_sock.connect_ex = connect_ex_side
        findings = check_router_security()
        self.assertTrue(any(f.severity == Severity.RED for f in findings))
        self.assertIn("Netgear", findings[0].description)

    @patch("scanner.checks._get_gateway_ip", return_value=None)
    def test_no_gateway_is_yellow(self, _):
        findings = check_router_security()
        self.assertEqual(findings[0].severity, Severity.YELLOW)

    @patch("scanner.checks.socket.socket")
    @patch("scanner.checks._get_gateway_ip", return_value="192.168.1.1")
    @patch("scanner.checks.run_command")
    def test_secure_router_is_green(self, mock_cmd, mock_gw, mock_socket):
        mock_cmd.return_value = (
            "router (192.168.1.1) at c4:04:15:aa:bb:cc on en0\n",
            "", 0,
        )
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        # Only 443 open (HTTPS only = good)
        def connect_ex_side(addr):
            ip, port = addr
            if port == 443:
                return 0
            return 1
        mock_sock.connect_ex = connect_ex_side
        findings = check_router_security()
        self.assertTrue(any(f.severity == Severity.GREEN for f in findings))


class TestRunAllChecks(unittest.TestCase):
    @patch("scanner.checks.check_firewall", return_value=[])
    @patch("scanner.checks.check_wifi", return_value=[])
    @patch("scanner.checks.check_dns", return_value=[])
    @patch("scanner.checks.check_open_ports", return_value=[])
    @patch("scanner.checks.check_active_connections", return_value=[])
    @patch("scanner.checks.check_processes", return_value=[])
    @patch("scanner.checks.check_traffic", return_value=[])
    @patch("scanner.checks.check_sip", return_value=[])
    @patch("scanner.checks.check_gatekeeper", return_value=[])
    @patch("scanner.checks.check_filevault", return_value=[])
    @patch("scanner.checks.check_auto_updates", return_value=[])
    @patch("scanner.checks.check_arp_table", return_value=[])
    @patch("scanner.checks.check_network_devices", return_value=[])
    @patch("scanner.checks.check_device_ports", return_value=[])
    @patch("scanner.checks.check_dns_hijacking", return_value=[])
    @patch("scanner.checks.check_network_quality", return_value=[])
    @patch("scanner.checks.check_router_security", return_value=[])
    def test_returns_combined(self, *mocks):
        findings = run_all_checks()
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
