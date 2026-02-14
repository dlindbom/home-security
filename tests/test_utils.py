"""Tests for scanner.utils — parsing, data models, helpers."""

import unittest
from scanner.utils import (
    Finding, Severity, ConnectionInfo,
    parse_lsof_output, is_private_ip, _parse_address,
)


class TestParseLsofOutput(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(parse_lsof_output(""), [])

    def test_header_only(self):
        self.assertEqual(parse_lsof_output("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"), [])

    def test_listen_entry(self):
        output = (
            "COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "python3  123 daniel 4u   IPv4 0x1234 0t0      TCP  *:8080 (LISTEN)\n"
        )
        conns = parse_lsof_output(output)
        self.assertEqual(len(conns), 1)
        c = conns[0]
        self.assertEqual(c.command, "python3")
        self.assertEqual(c.pid, 123)
        self.assertEqual(c.protocol, "TCP")
        self.assertEqual(c.local_address, "*")
        self.assertEqual(c.local_port, 8080)
        self.assertEqual(c.state, "LISTEN")
        self.assertIsNone(c.remote_address)

    def test_established_entry(self):
        output = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "Safari  456 daniel 5u IPv4 0xabc 0t0 TCP 192.168.1.10:51540->93.184.216.34:443 (ESTABLISHED)\n"
        )
        conns = parse_lsof_output(output)
        self.assertEqual(len(conns), 1)
        c = conns[0]
        self.assertEqual(c.command, "Safari")
        self.assertEqual(c.local_address, "192.168.1.10")
        self.assertEqual(c.local_port, 51540)
        self.assertEqual(c.remote_address, "93.184.216.34")
        self.assertEqual(c.remote_port, 443)
        self.assertEqual(c.state, "ESTABLISHED")

    def test_ipv6_listen(self):
        output = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "node    789 daniel 6u IPv6 0xdef 0t0 TCP [::1]:3000 (LISTEN)\n"
        )
        conns = parse_lsof_output(output)
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].local_address, "::1")
        self.assertEqual(conns[0].local_port, 3000)

    def test_udp_no_state(self):
        output = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "mDNSRes 100 root  7u IPv4 0xaaa 0t0 UDP *:5353\n"
        )
        conns = parse_lsof_output(output)
        self.assertEqual(len(conns), 1)
        c = conns[0]
        self.assertEqual(c.protocol, "UDP")
        self.assertEqual(c.local_port, 5353)
        self.assertIsNone(c.state)


class TestParseAddress(unittest.TestCase):
    def test_wildcard(self):
        self.assertEqual(_parse_address("*:*"), ("*", None))

    def test_ipv4_port(self):
        self.assertEqual(_parse_address("127.0.0.1:8080"), ("127.0.0.1", 8080))

    def test_ipv6_port(self):
        self.assertEqual(_parse_address("[::1]:3000"), ("::1", 3000))

    def test_wildcard_port(self):
        self.assertEqual(_parse_address("*:5353"), ("*", 5353))


class TestIsPrivateIp(unittest.TestCase):
    def test_private(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("*"))
        self.assertTrue(is_private_ip("localhost"))

    def test_public(self):
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("93.184.216.34"))


class TestFindingModel(unittest.TestCase):
    def test_creation(self):
        f = Finding(
            category="test",
            title="Test finding",
            severity=Severity.GREEN,
            description="All good",
        )
        self.assertEqual(f.category, "test")
        self.assertEqual(f.severity, Severity.GREEN)
        self.assertEqual(f.raw_data, {})


if __name__ == "__main__":
    unittest.main()
