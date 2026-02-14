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
    run_all_checks,
    _classify_ip,
    _check_code_signatures,
    _classify_connections,
    _check_vpn_leak,
    _check_baseline_diff,
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


class TestRunAllChecks(unittest.TestCase):
    @patch("scanner.checks.check_firewall", return_value=[])
    @patch("scanner.checks.check_wifi", return_value=[])
    @patch("scanner.checks.check_dns", return_value=[])
    @patch("scanner.checks.check_open_ports", return_value=[])
    @patch("scanner.checks.check_active_connections", return_value=[])
    @patch("scanner.checks.check_processes", return_value=[])
    @patch("scanner.checks.check_traffic", return_value=[])
    def test_returns_combined(self, *mocks):
        findings = run_all_checks()
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
