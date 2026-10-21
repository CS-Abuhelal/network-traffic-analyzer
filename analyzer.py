#!/usr/bin/env python3
"""
analyzer.py
-----------
Command-line entry point for the Network Traffic Analyzer.

Usage:
    python analyzer.py sample_pcaps/mixed_suspicious.pcap
    python analyzer.py capture.pcap --output report.txt
    python analyzer.py capture.pcap --blocklist data/sample_blocklist.txt

What it does, step by step:
    1. Stream packets out of the given PCAP file using Scapy (one pass
       per detector, so huge captures never need to fit in memory).
    2. Run each detector function from netanalyzer/detectors.py against
       those packets. Every detector returns a list of "Finding" objects.
    3. Combine all the findings and build a human-readable report,
       sorted from most to least severe.
    4. Print the report to the screen (and optionally save it to a file).
"""

import argparse
import os
import sys

from scapy.all import PcapReader

from netanalyzer import detectors
from netanalyzer.blocklist import load_blocklist
from netanalyzer.report import build_report


def iter_packets(path):
    """Yield packets from a capture file one at a time.

    rdpcap() would load the entire capture into memory at once, which
    means a multi-gigabyte (or deliberately oversized) PCAP could
    exhaust RAM and take the analysis box down with it. Streaming keeps
    memory flat no matter how big the file is. Each detector gets its
    own fresh pass over the file - re-reading it a few times is a fair
    price for keeping every detector simple and independent."""
    with PcapReader(path) as reader:
        yield from reader


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and report suspicious network activity.",
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the .pcap / .pcapng file to analyze",
    )
    parser.add_argument(
        "--blocklist",
        default=os.path.join(os.path.dirname(__file__), "data", "sample_blocklist.txt"),
        help="Path to a text file of known-malicious CIDR ranges "
             "(default: data/sample_blocklist.txt, sample data only - see README)",
    )
    parser.add_argument(
        "--output",
        help="Optional path to also save the report as a text file",
    )

    # Detection thresholds. Sensible defaults are provided, but every
    # network is different, so these are all tweakable from the CLI.
    parser.add_argument("--port-scan-threshold", type=int, default=15,
                         help="Distinct ports on one host that counts as a port scan (default: 15)")
    parser.add_argument("--sweep-threshold", type=int, default=10,
                         help="Distinct hosts hit on the same port that counts as a network sweep (default: 10)")
    parser.add_argument("--byte-threshold", type=int, default=500_000,
                         help="Bytes between one src/dst pair that counts as unusual volume (default: 500000)")
    parser.add_argument("--pps-threshold", type=int, default=200,
                         help="Packets per second that counts as an unusual rate / possible flood (default: 200)")

    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.isfile(args.pcap_file):
        print(f"Error: file not found: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading packets from {args.pcap_file} ...")
    packet_count = sum(1 for _ in iter_packets(args.pcap_file))
    print(f"Found {packet_count} packets. Running detectors...")

    findings = []

    findings += detectors.detect_port_scans(
        iter_packets(args.pcap_file),
        vertical_threshold=args.port_scan_threshold,
        horizontal_threshold=args.sweep_threshold,
    )

    findings += detectors.detect_suspicious_protocols(iter_packets(args.pcap_file))

    if os.path.isfile(args.blocklist):
        blocklist_networks = load_blocklist(args.blocklist)
        findings += detectors.detect_malicious_ips(iter_packets(args.pcap_file), blocklist_networks)
    else:
        print(f"Warning: blocklist file not found ({args.blocklist}), "
              f"skipping malicious IP range detection.", file=sys.stderr)

    findings += detectors.detect_unusual_volume(
        iter_packets(args.pcap_file),
        byte_threshold=args.byte_threshold,
        pps_threshold=args.pps_threshold,
    )

    findings += detectors.detect_cleartext_credentials(iter_packets(args.pcap_file))

    report_text = build_report(args.pcap_file, packet_count, findings)
    print()
    print(report_text)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
