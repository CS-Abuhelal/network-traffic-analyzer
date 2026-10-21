#!/usr/bin/env python3
"""
generate_samples.py
--------------------
Builds the sample PCAP files used to test and demo the Network Traffic
Analyzer. Every "suspicious" detail in these files is synthetic - no real
hosts, malware, or credentials are involved.

IP address scheme used throughout these samples:
    192.168.1.0/24   - the "internal network" (normal hosts + attackers)
    10.50.0.0/24      - a stand-in for ordinary external/internet hosts
                        (NOT on the sample blocklist - used for clean,
                        non-malicious traffic)
    192.0.2.0/24,
    198.51.100.0/24,
    203.0.113.0/24    - RFC 5737 "documentation" ranges, reserved by the
                        IETF specifically for examples like this one and
                        never routable on the real internet. These are
                        the ranges listed in data/sample_blocklist.txt,
                        so traffic to/from them is what trips the
                        "malicious IP range" detector.

Run this script from anywhere; it writes .pcap files into this same
sample_pcaps/ directory:

    python sample_pcaps/generate_samples.py
"""

import os
import base64

from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR, wrpcap

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def pkt(src, dst, sport, dport, payload=b"", flags="S", proto="tcp", time=None):
    """Small helper that builds one Ethernet/IP/TCP-or-UDP packet."""
    ip_layer = IP(src=src, dst=dst)
    if proto == "tcp":
        transport = TCP(sport=sport, dport=dport, flags=flags)
    else:
        transport = UDP(sport=sport, dport=dport)
    p = Ether(src=MAC_A, dst=MAC_B) / ip_layer / transport
    if payload:
        p = p / Raw(load=payload)
    if time is not None:
        p.time = time
    return p


def save(name, packets):
    path = os.path.join(OUT_DIR, name)
    wrpcap(path, packets)
    print(f"Wrote {len(packets)} packets to {path}")


# ---------------------------------------------------------------------------
def build_normal_traffic():
    """A clean baseline capture: should produce zero (or near-zero) findings."""
    packets = []
    t = 1_700_000_000.0

    # DNS lookup against the local resolver.
    dns_q = Ether(src=MAC_A, dst=MAC_B) / IP(src="192.168.1.10", dst="192.168.1.1") / \
        UDP(sport=53111, dport=53) / DNS(rd=1, qd=DNSQR(qname="intranet.local"))
    dns_q.time = t; t += 0.01
    dns_r = Ether(src=MAC_B, dst=MAC_A) / IP(src="192.168.1.1", dst="192.168.1.10") / \
        UDP(sport=53, dport=53111) / DNS(qr=1, qd=DNSQR(qname="intranet.local"),
                                          an=DNSRR(rrname="intranet.local", rdata="10.50.0.20"))
    dns_r.time = t; t += 0.05
    packets += [dns_q, dns_r]

    # A normal HTTP GET for a non-sensitive page (no credentials involved).
    http_get = pkt("192.168.1.10", "10.50.0.20", 51000, 80,
                    payload=b"GET /index.html HTTP/1.1\r\nHost: www.intranet.local\r\n\r\n",
                    flags="PA", time=t)
    t += 0.02
    http_resp = pkt("10.50.0.20", "192.168.1.10", 80, 51000,
                     payload=b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello world!",
                     flags="PA", time=t)
    t += 0.02
    packets += [http_get, http_resp]

    # A normal HTTPS-looking handshake (encrypted application data, no
    # readable contents - just a few bytes of random "ciphertext").
    syn = pkt("192.168.1.10", "10.50.0.10", 51500, 443, flags="S", time=t); t += 0.01
    synack = pkt("10.50.0.10", "192.168.1.10", 443, 51500, flags="SA", time=t); t += 0.01
    ack = pkt("192.168.1.10", "10.50.0.10", 51500, 443, flags="A", time=t); t += 0.01
    data = pkt("192.168.1.10", "10.50.0.10", 51500, 443, payload=os.urandom(64), flags="PA", time=t); t += 0.01
    packets += [syn, synack, ack, data]

    return packets


# ---------------------------------------------------------------------------
def build_port_scan():
    """Vertical scan (many ports, one host) + horizontal scan (one port, many hosts)."""
    packets = []
    t = 1_700_000_100.0

    attacker, victim = "192.168.1.50", "192.168.1.20"
    for port in range(20, 60):  # 40 distinct ports
        packets.append(pkt(attacker, victim, sport=40000 + port, dport=port, flags="S", time=t))
        t += 0.005

    sweeper = "192.168.1.51"
    for host_id in range(1, 16):  # 15 distinct hosts, same port (22)
        target = f"192.168.1.{host_id}"
        packets.append(pkt(sweeper, target, sport=41000 + host_id, dport=22, flags="S", time=t))
        t += 0.005

    return packets


# ---------------------------------------------------------------------------
def build_malicious_ip_traffic():
    """Internal host talking to an address inside the sample blocklist range,
    on a port (4444) commonly associated with exploit/post-exploitation tools."""
    packets = []
    t = 1_700_000_200.0

    internal = "192.168.1.10"
    flagged_ip = "203.0.113.50"  # inside data/sample_blocklist.txt

    syn = pkt(internal, flagged_ip, 52000, 4444, flags="S", time=t); t += 0.02
    synack = pkt(flagged_ip, internal, 4444, 52000, flags="SA", time=t); t += 0.02
    ack = pkt(internal, flagged_ip, 52000, 4444, flags="A", time=t); t += 0.02
    data = pkt(internal, flagged_ip, 52000, 4444, payload=b"session-check-in\n", flags="PA", time=t); t += 0.02
    packets += [syn, synack, ack, data]

    return packets


# ---------------------------------------------------------------------------
def build_cleartext_credentials():
    """HTTP form login, HTTP Basic Auth, and FTP USER/PASS - all unencrypted."""
    packets = []
    t = 1_700_000_300.0

    body = b"username=admin&password=SuperSecret123"
    http_post = pkt("192.168.1.15", "10.50.0.30", 53000, 80,
                     payload=(b"POST /login HTTP/1.1\r\nHost: portal.local\r\n"
                              b"Content-Type: application/x-www-form-urlencoded\r\n"
                              b"Content-Length: %d\r\n\r\n" % len(body)) + body,
                     flags="PA", time=t)
    t += 0.05
    packets.append(http_post)

    creds_b64 = base64.b64encode(b"alice:Password1!").decode()
    http_basic = pkt("192.168.1.16", "10.50.0.30", 53050, 80,
                      payload=(b"GET /admin HTTP/1.1\r\nHost: portal.local\r\n"
                               b"Authorization: Basic %s\r\n\r\n" % creds_b64.encode()),
                      flags="PA", time=t)
    t += 0.05
    packets.append(http_basic)

    ftp_user = pkt("192.168.1.15", "192.168.1.5", 53100, 21, payload=b"USER alice\r\n", flags="PA", time=t)
    t += 0.02
    ftp_pass = pkt("192.168.1.15", "192.168.1.5", 53100, 21, payload=b"PASS Password1!\r\n", flags="PA", time=t)
    t += 0.02
    packets += [ftp_user, ftp_pass]

    return packets


# ---------------------------------------------------------------------------
def build_mixed_suspicious():
    """One capture that trips all five detection categories at once - good
    for demoing the full report output."""
    packets = []
    t = 1_700_000_400.0

    # A smaller port scan.
    attacker, victim = "192.168.1.60", "192.168.1.21"
    for port in range(1, 20):  # 19 distinct ports
        packets.append(pkt(attacker, victim, sport=42000 + port, dport=port, flags="S", time=t))
        t += 0.005

    # Telnet (insecure protocol).
    packets.append(pkt("192.168.1.17", "192.168.1.6", 53200, 23, payload=b"login: root\r\n", flags="PA", time=t))
    t += 0.02

    # Traffic to a blocklisted range.
    flagged_ip = "203.0.113.99"
    packets.append(pkt("192.168.1.10", flagged_ip, 52500, 4444, flags="S", time=t)); t += 0.02
    packets.append(pkt(flagged_ip, "192.168.1.10", 4444, 52500, flags="SA", time=t)); t += 0.02

    # Cleartext HTTP credentials.
    body = b"user=svc_backup&pass=Winter2024!"
    packets.append(pkt("192.168.1.18", "10.50.0.40", 53300, 80,
                        payload=b"POST /auth HTTP/1.1\r\nHost: legacy.local\r\n\r\n" + body,
                        flags="PA", time=t))
    t += 0.02

    # A burst of packets in a very short time window - simulates a flood /
    # unusually high packet rate (~500 packets/sec).
    flood_src, flood_dst = "192.168.1.70", "192.168.1.22"
    burst_start = t
    for i in range(300):
        packets.append(pkt(flood_src, flood_dst, sport=44000, dport=80,
                            payload=b"X" * 200, flags="PA",
                            time=burst_start + i * 0.002))

    return packets


def main():
    save("normal_traffic.pcap", build_normal_traffic())
    save("port_scan.pcap", build_port_scan())
    save("malicious_ip_traffic.pcap", build_malicious_ip_traffic())
    save("cleartext_credentials.pcap", build_cleartext_credentials())
    save("mixed_suspicious.pcap", build_mixed_suspicious())


if __name__ == "__main__":
    main()
