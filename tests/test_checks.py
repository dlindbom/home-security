"""Tests for scanner.checks — mocked system commands."""

import unittest
from unittest.mock import patch

from scanner.checks import (
    check_firewall,
    check_dns,
    check_open_ports,
    check_active_connections,
    check_processes,
    run_all_checks,
)
from scanner.utils import Severity


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


class TestRunAllChecks(unittest.TestCase):
    @patch("scanner.checks.check_firewall", return_value=[])
    @patch("scanner.checks.check_wifi", return_value=[])
    @patch("scanner.checks.check_dns", return_value=[])
    @patch("scanner.checks.check_open_ports", return_value=[])
    @patch("scanner.checks.check_active_connections", return_value=[])
    @patch("scanner.checks.check_processes", return_value=[])
    def test_returns_combined(self, *mocks):
        findings = run_all_checks()
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
