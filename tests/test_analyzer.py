"""
test_analyzer.py
-----------------
Basic sanity tests for the detectors, run against the sample PCAP files.

These aren't exhaustive - they're here to prove each detector fires on
the traffic pattern it's meant to catch, and stays quiet on normal
traffic. Run with:

    python -m pytest tests/
or simply:
    python tests/test_analyzer.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import rdpcap

from netanalyzer import detectors
from netanalyzer.blocklist import load_blocklist
from netanalyzer.report import Finding, build_report, sanitize_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "sample_pcaps")
BLOCKLIST = os.path.join(ROOT, "data", "sample_blocklist.txt")


def categories(findings):
    return {f.category for f in findings}


class TestDetectors(unittest.TestCase):

    def test_normal_traffic_has_no_findings(self):
        packets = rdpcap(os.path.join(SAMPLES, "normal_traffic.pcap"))
        findings = []
        findings += detectors.detect_port_scans(packets)
        findings += detectors.detect_suspicious_protocols(packets)
        findings += detectors.detect_unusual_volume(packets)
        findings += detectors.detect_cleartext_credentials(packets)
        self.assertEqual(findings, [], "Clean baseline traffic should not trigger any findings")

    def test_port_scan_detected(self):
        packets = rdpcap(os.path.join(SAMPLES, "port_scan.pcap"))
        findings = detectors.detect_port_scans(packets)
        cats = categories(findings)
        self.assertIn("Port Scan (Vertical)", cats)
        self.assertIn("Port Scan (Horizontal / Network Sweep)", cats)

    def test_malicious_ip_detected(self):
        packets = rdpcap(os.path.join(SAMPLES, "malicious_ip_traffic.pcap"))
        blocklist = load_blocklist(BLOCKLIST)
        findings = detectors.detect_malicious_ips(packets, blocklist)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(all(f.severity == "CRITICAL" for f in findings))

    def test_cleartext_credentials_detected(self):
        packets = rdpcap(os.path.join(SAMPLES, "cleartext_credentials.pcap"))
        findings = detectors.detect_cleartext_credentials(packets)
        self.assertTrue(len(findings) >= 4)  # HTTP form, HTTP basic, FTP user, FTP pass
        # Make sure passwords are masked, never shown in full.
        for f in findings:
            if "password" in f.details:
                self.assertIn("*", f.details["password"])

    def test_suspicious_protocols_detected(self):
        packets = rdpcap(os.path.join(SAMPLES, "mixed_suspicious.pcap"))
        findings = detectors.detect_suspicious_protocols(packets)
        names = {f.details["protocol"] for f in findings}
        self.assertIn("Telnet", names)

    def test_mixed_file_triggers_all_categories(self):
        packets = rdpcap(os.path.join(SAMPLES, "mixed_suspicious.pcap"))
        blocklist = load_blocklist(BLOCKLIST)

        findings = []
        findings += detectors.detect_port_scans(packets)
        findings += detectors.detect_suspicious_protocols(packets)
        findings += detectors.detect_malicious_ips(packets, blocklist)
        findings += detectors.detect_unusual_volume(packets)
        findings += detectors.detect_cleartext_credentials(packets)

        cats = categories(findings)
        self.assertTrue(any("Port Scan" in c for c in cats))
        self.assertIn("Suspicious Protocol", cats)
        self.assertIn("Malicious IP Range", cats)
        self.assertIn("Unusual Packet Rate", cats)
        self.assertIn("Cleartext Credentials", cats)


class TestReportSafety(unittest.TestCase):

    def test_mask_reveals_nothing_about_the_secret(self):
        # Fixed-length mask: no first character, no true length.
        self.assertEqual(detectors._mask_secret(b"hunter2"), "********")
        self.assertEqual(detectors._mask_secret(b"a"), "********")
        self.assertEqual(
            detectors._mask_secret(b"hunter2"),
            detectors._mask_secret(b"correct horse battery staple"),
        )

    def test_sanitize_strips_terminal_escapes(self):
        self.assertEqual(sanitize_text("\x1b[2J\x1b[31mroot\x1b[0m"), "root")
        self.assertEqual(sanitize_text("line1\r\nline2"), "line1 line2")

    def test_payload_content_cannot_inject_into_report(self):
        # A username decoded from a packet payload is attacker-controlled;
        # escape codes and newlines must not survive into the report text.
        evil = Finding(
            severity="CRITICAL",
            category="Cleartext Credentials",
            message="HTTP Basic Authentication credentials sent unencrypted.",
            details={"username": "bob\x1b[2J\r\n  [INFO] forged line"},
        )
        report = build_report("fake.pcap", 1, [evil])
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\n  [INFO] forged line", report)


if __name__ == "__main__":
    unittest.main()
