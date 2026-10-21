"""
report.py
---------
Defines the `Finding` data structure (one suspicious thing we noticed)
and helper functions to turn a list of Findings into a readable,
severity-ranked text report.

Keeping this in its own file means the detection logic (detectors.py)
doesn't need to know anything about how results get *printed* - it just
creates Finding objects and hands them off.
"""

import re
from dataclasses import dataclass, field
from collections import Counter
from datetime import datetime

# Some finding fields (usernames pulled out of packet payloads, for
# example) are attacker-controlled bytes. Before they go into a report
# that gets printed to a terminal, strip ANSI escape sequences and other
# control characters - otherwise a crafted packet could inject escape
# codes that rewrite or hide report lines on the analyst's screen - and
# collapse newlines so one value can't masquerade as several lines.
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_text(value) -> str:
    """Make a possibly attacker-controlled value safe to print."""
    text = _ANSI_CSI.sub("", str(value))
    return _CONTROL_CHARS.sub(" ", text).strip()

# We rank severities from worst to least-bad. Lower number = more severe.
# This lets us sort findings so the scariest stuff appears first in the report.
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class Finding:
    """
    Represents a single suspicious observation made while analyzing a PCAP.

    severity:    one of CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:    short label for the *type* of detection, e.g. "Port Scan"
    message:     a one-line, human-readable description of what was found
    details:     optional dict of extra evidence (IPs, ports, counts, etc.)
    """
    severity: str
    category: str
    message: str
    details: dict = field(default_factory=dict)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


def sort_findings(findings):
    """Sort findings so CRITICAL comes first, then HIGH, MEDIUM, LOW, INFO."""
    return sorted(findings, key=lambda f: f.severity_rank())


def _format_details(details: dict) -> str:
    """Turn a details dict into an indented "key: value" block of text."""
    if not details:
        return ""
    lines = []
    for key, value in details.items():
        lines.append(f"      - {key}: {sanitize_text(value)}")
    return "\n".join(lines)


def build_report(pcap_path, packet_count, findings, generated_at=None) -> str:
    """
    Build the full text report as a single string.

    pcap_path:    path to the PCAP file that was analyzed
    packet_count: total number of packets read from the file
    findings:     list of Finding objects produced by the detectors
    """
    generated_at = generated_at or datetime.now()
    findings = sort_findings(findings)
    severity_counts = Counter(f.severity for f in findings)

    lines = []
    lines.append("=" * 70)
    lines.append("  NETWORK TRAFFIC ANALYZER - SUMMARY REPORT")
    lines.append("=" * 70)
    lines.append(f"  File analyzed   : {pcap_path}")
    lines.append(f"  Generated at    : {generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Packets read    : {packet_count}")
    lines.append(f"  Total findings  : {len(findings)}")
    lines.append("")
    lines.append("  Findings by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity_counts.get(sev):
            lines.append(f"      {sev:<9}: {severity_counts[sev]}")
    lines.append("=" * 70)
    lines.append("")

    if not findings:
        lines.append("No suspicious activity detected. Traffic looks normal.")
        lines.append("")
        return "\n".join(lines)

    current_severity = None
    for finding in findings:
        if finding.severity != current_severity:
            current_severity = finding.severity
            lines.append(f"--- {current_severity} " + "-" * (66 - len(current_severity)))
        lines.append(f"  [{finding.severity}] {finding.category}: {sanitize_text(finding.message)}")
        detail_text = _format_details(finding.details)
        if detail_text:
            lines.append(detail_text)
        lines.append("")

    return "\n".join(lines)
