"""
detectors.py
------------
The actual "detective work" lives here. Each function takes the list of
packets read from a PCAP file (plus some configurable thresholds) and
returns a list of Finding objects describing anything suspicious it saw.

Every function is independent - they don't depend on each other, and
analyzer.py simply calls each one in turn and combines the results.
This makes it easy to add a new detector later: write a function that
returns a list of Findings, then call it from analyzer.py.

Scapy basics used throughout this file:
  - packet.haslayer(IP)   -> True if the packet has an IP header
  - packet[IP].src/.dst   -> source/destination IP address (strings)
  - packet.haslayer(TCP)  -> True if it's a TCP packet
  - packet[TCP].sport/.dport -> source/destination TCP port (ints)
  - packet[Raw].load      -> the raw application-layer bytes (HTTP, FTP, etc.)
"""

import re
import base64
from collections import defaultdict

from scapy.all import IP, TCP, UDP, Raw

from .report import Finding
from .blocklist import find_matching_network


# ---------------------------------------------------------------------------
# 1. PORT SCAN DETECTION
# ---------------------------------------------------------------------------
# A port scan is when one machine sends traffic to a large number of
# *different* ports (and/or hosts) in a short time, usually to discover
# which services are running and might be attackable.
#
# We look for two patterns:
#   - "Vertical" scan: one source IP hits MANY ports on a SINGLE destination
#     (e.g. `nmap -p 1-1000 target`).
#   - "Horizontal" scan: one source IP hits the SAME port on MANY different
#     destinations (e.g. sweeping a subnet for open SSH).
# ---------------------------------------------------------------------------

def detect_port_scans(packets, vertical_threshold=15, horizontal_threshold=10):
    """
    vertical_threshold:   number of distinct ports on one host that counts
                           as a scan.
    horizontal_threshold: number of distinct hosts hit on the same port
                           that counts as a sweep.
    """
    findings = []

    # src_ip -> dst_ip -> set of ports contacted (for vertical scans)
    ports_per_src_dst = defaultdict(lambda: defaultdict(set))
    # src_ip -> dst_port -> set of destination IPs contacted (for horizontal scans)
    hosts_per_src_port = defaultdict(lambda: defaultdict(set))

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src = pkt[IP].src
        dst = pkt[IP].dst

        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
        if dport is None:
            continue

        ports_per_src_dst[src][dst].add(dport)
        hosts_per_src_port[src][dport].add(dst)

    # Vertical scans: many ports, one target
    for src, dst_map in ports_per_src_dst.items():
        for dst, ports in dst_map.items():
            if len(ports) >= vertical_threshold:
                findings.append(Finding(
                    severity="HIGH",
                    category="Port Scan (Vertical)",
                    message=f"{src} contacted {len(ports)} distinct ports on {dst} - "
                            f"looks like port scanning / service discovery.",
                    details={
                        "source_ip": src,
                        "target_ip": dst,
                        "distinct_ports": len(ports),
                        "sample_ports": sorted(ports)[:20],
                    },
                ))

    # Horizontal scans: same port, many targets (a network sweep)
    for src, port_map in hosts_per_src_port.items():
        for port, hosts in port_map.items():
            if len(hosts) >= horizontal_threshold:
                findings.append(Finding(
                    severity="HIGH",
                    category="Port Scan (Horizontal / Network Sweep)",
                    message=f"{src} probed port {port} on {len(hosts)} different hosts - "
                            f"looks like a network sweep.",
                    details={
                        "source_ip": src,
                        "port": port,
                        "distinct_hosts": len(hosts),
                        "sample_hosts": sorted(hosts)[:20],
                    },
                ))

    return findings


# ---------------------------------------------------------------------------
# 2. SUSPICIOUS / INSECURE PROTOCOL DETECTION
# ---------------------------------------------------------------------------
# Some protocols transmit everything - including passwords - in plain text,
# or are rarely used legitimately on a modern network. Seeing them at all
# is worth flagging, even if no other red flags are present.
# ---------------------------------------------------------------------------

# port -> (protocol name, severity, why it matters)
INSECURE_PORTS = {
    23:  ("Telnet", "HIGH", "Remote login with no encryption - credentials and session are sent in clear text."),
    21:  ("FTP (control)", "MEDIUM", "File transfer login/commands are sent in clear text."),
    69:  ("TFTP", "MEDIUM", "Trivial FTP has no authentication and no encryption."),
    512: ("rexec", "HIGH", "Legacy remote execution protocol, unauthenticated/clear text."),
    513: ("rlogin", "HIGH", "Legacy remote login protocol, clear text credentials."),
    514: ("rsh", "HIGH", "Legacy remote shell protocol, no encryption."),
    161: ("SNMP", "MEDIUM", "Often uses default/clear-text community strings ('public'/'private')."),
    162: ("SNMP-trap", "MEDIUM", "Often uses default/clear-text community strings."),
    110: ("POP3", "LOW", "Clear-text email retrieval unless wrapped in TLS (POP3S uses port 995)."),
    143: ("IMAP", "LOW", "Clear-text email access unless wrapped in TLS (IMAPS uses port 993)."),
    4444: ("Suspicious port 4444", "HIGH", "Commonly used as a default listener port by exploit/post-exploitation tools (e.g. Metasploit)."),
}


def detect_suspicious_protocols(packets):
    findings = []
    # (src, dst, port) -> packet count, so we report one finding per
    # conversation instead of one finding per packet.
    seen = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src, dst = pkt[IP].src, pkt[IP].dst

        for layer, get_port in ((TCP, lambda p: p[TCP].dport), (UDP, lambda p: p[UDP].dport)):
            if pkt.haslayer(layer):
                port = get_port(pkt)
                if port in INSECURE_PORTS:
                    seen[(src, dst, port)] += 1

    for (src, dst, port), count in seen.items():
        name, severity, reason = INSECURE_PORTS[port]
        findings.append(Finding(
            severity=severity,
            category="Suspicious Protocol",
            message=f"{name} traffic seen from {src} to {dst}:{port} ({count} packets).",
            details={
                "source_ip": src,
                "destination_ip": dst,
                "port": port,
                "protocol": name,
                "packet_count": count,
                "why_it_matters": reason,
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 3. CONNECTIONS TO KNOWN-MALICIOUS IP RANGES
# ---------------------------------------------------------------------------

def detect_malicious_ips(packets, blocklist_networks):
    findings = []
    seen_pairs = defaultdict(int)
    matched_network_for_pair = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src, dst = pkt[IP].src, pkt[IP].dst

        for ip in (src, dst):
            network = find_matching_network(ip, blocklist_networks)
            if network:
                key = (src, dst, ip, network)
                seen_pairs[key] += 1
                matched_network_for_pair[key] = network

    for (src, dst, flagged_ip, network), count in seen_pairs.items():
        findings.append(Finding(
            severity="CRITICAL",
            category="Malicious IP Range",
            message=f"Traffic between {src} and {dst} involves {flagged_ip}, "
                    f"which falls inside blocklisted range {network} ({count} packets).",
            details={
                "source_ip": src,
                "destination_ip": dst,
                "flagged_ip": flagged_ip,
                "matched_range": network,
                "packet_count": count,
            },
        ))

    return findings


# ---------------------------------------------------------------------------
# 4. UNUSUAL TRAFFIC VOLUME
# ---------------------------------------------------------------------------
# Flags conversations that move an unusually large amount of data, or send
# packets at an unusually high rate (a possible sign of data exfiltration,
# a flood/DoS attempt, or a misbehaving host).
# ---------------------------------------------------------------------------

def detect_unusual_volume(packets, byte_threshold=500_000, pps_threshold=200):
    findings = []

    # (src, dst) -> running totals
    bytes_per_pair = defaultdict(int)
    packets_per_pair = defaultdict(int)
    first_ts = {}
    last_ts = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        key = (src, dst)

        size = len(pkt)
        bytes_per_pair[key] += size
        packets_per_pair[key] += 1

        ts = float(pkt.time)
        if key not in first_ts:
            first_ts[key] = ts
        last_ts[key] = ts

    # A handful of packets sent close together isn't a meaningful "rate" -
    # require enough packets that a packets/sec figure is actually telling
    # us something, instead of being an artifact of two packets 1ms apart.
    min_packets_for_rate = 20

    for key, total_bytes in bytes_per_pair.items():
        src, dst = key
        total_packets = packets_per_pair[key]
        duration = last_ts[key] - first_ts[key]
        pps = total_packets / duration if duration > 0 else 0

        if total_bytes >= byte_threshold:
            severity = "HIGH" if total_bytes >= byte_threshold * 5 else "MEDIUM"
            findings.append(Finding(
                severity=severity,
                category="Unusual Traffic Volume",
                message=f"{src} -> {dst} transferred {total_bytes:,} bytes "
                        f"({total_packets} packets) - higher than the {byte_threshold:,} byte baseline.",
                details={
                    "source_ip": src,
                    "destination_ip": dst,
                    "total_bytes": total_bytes,
                    "total_packets": total_packets,
                },
            ))

        if total_packets >= min_packets_for_rate and pps >= pps_threshold:
            findings.append(Finding(
                severity="HIGH",
                category="Unusual Packet Rate",
                message=f"{src} -> {dst} sent {total_packets} packets in {duration:.2f}s "
                        f"(~{pps:.0f} packets/sec) - possible flood/DoS behavior.",
                details={
                    "source_ip": src,
                    "destination_ip": dst,
                    "packets_per_second": round(pps, 1),
                    "duration_seconds": round(duration, 3),
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# 5. CLEARTEXT CREDENTIALS IN HTTP / FTP TRAFFIC
# ---------------------------------------------------------------------------
# Looks inside the raw payload of packets for tell-tale signs of credentials
# being sent without encryption: HTTP Basic Auth headers, HTML login form
# fields (username=...&password=...), and FTP USER/PASS commands.
#
# Security note: we deliberately MASK passwords in the report output
# (showing only the first character + length) so that running this tool
# doesn't itself create a new place where plaintext passwords are stored.
# ---------------------------------------------------------------------------

_RE_HTTP_AUTH_BASIC = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
_RE_FORM_PASSWORD = re.compile(rb"(?:pass(?:word|wd)?)=([^&\s\r\n]+)", re.IGNORECASE)
_RE_FORM_USERNAME = re.compile(rb"(?:user(?:name)?|login|email)=([^&\s\r\n]+)", re.IGNORECASE)
_RE_FTP_USER = re.compile(rb"^USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_RE_FTP_PASS = re.compile(rb"^PASS\s+(\S+)", re.IGNORECASE | re.MULTILINE)


def _mask_secret(secret_bytes):
    """Confirm a secret was captured without leaking anything about it.
    The mask is a fixed length on purpose: even 'first character + true
    length' meaningfully narrows the search space for someone trying to
    recover the password from a shared report."""
    return "********" if secret_bytes else "(empty)"


def detect_cleartext_credentials(packets):
    findings = []

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        src, dst = pkt[IP].src, pkt[IP].dst
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        payload = bytes(pkt[Raw].load)

        # --- HTTP Basic Auth header ---
        match = _RE_HTTP_AUTH_BASIC.search(payload)
        if match:
            try:
                decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
                user, _, password = decoded.partition(":")
            except Exception:
                user, password = "?", "?"
            findings.append(Finding(
                severity="CRITICAL",
                category="Cleartext Credentials",
                message=f"HTTP Basic Authentication credentials sent unencrypted from {src} to {dst}:{dport}.",
                details={
                    "source_ip": src,
                    "destination_ip": dst,
                    "username": user,
                    "password": _mask_secret(password.encode()),
                    "protocol": "HTTP Basic Auth",
                },
            ))

        # --- HTML login form fields (username=...&password=...) ---
        pw_match = _RE_FORM_PASSWORD.search(payload)
        if pw_match:
            user_match = _RE_FORM_USERNAME.search(payload)
            user = user_match.group(1).decode("utf-8", errors="replace") if user_match else "(unknown)"
            findings.append(Finding(
                severity="CRITICAL",
                category="Cleartext Credentials",
                message=f"HTTP form submission with a password field sent unencrypted from {src} to {dst}:{dport}.",
                details={
                    "source_ip": src,
                    "destination_ip": dst,
                    "username": user,
                    "password": _mask_secret(pw_match.group(1)),
                    "protocol": "HTTP form POST",
                },
            ))

        # --- FTP USER / PASS commands (FTP control channel, port 21) ---
        if dport == 21 or sport == 21:
            user_match = _RE_FTP_USER.search(payload)
            if user_match:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Cleartext Credentials",
                    message=f"FTP USER command sent unencrypted from {src} to {dst}.",
                    details={
                        "source_ip": src,
                        "destination_ip": dst,
                        "username": user_match.group(1).decode("utf-8", errors="replace"),
                        "protocol": "FTP",
                    },
                ))
            pass_match = _RE_FTP_PASS.search(payload)
            if pass_match:
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Cleartext Credentials",
                    message=f"FTP PASS command sent unencrypted from {src} to {dst}.",
                    details={
                        "source_ip": src,
                        "destination_ip": dst,
                        "password": _mask_secret(pass_match.group(1)),
                        "protocol": "FTP",
                    },
                ))

    return findings
