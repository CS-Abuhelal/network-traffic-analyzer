# Network Traffic Analyzer

Reads a PCAP file and tells you what's wrong with it.

I built this while teaching myself network forensics. Point it at a
capture from Wireshark or `tcpdump` and it flags the stuff a SOC analyst
would want a second look at: port scans, legacy protocols, blocklisted
IPs, strange traffic volumes, and credentials sent in the clear. The code
is commented to explain *why* each check works, not just what it does —
writing those comments was half the point of the project.

## What it detects

| Detection | What it looks for |
|---|---|
| **Port scans** | One source IP hitting many distinct ports on a single host ("vertical" scan), or the same port across many hosts ("horizontal" scan / network sweep) |
| **Suspicious protocols** | Insecure, legacy, or commonly-abused services - Telnet, FTP, TFTP, rlogin/rsh/rexec, SNMP, POP3/IMAP, and port 4444 (a common exploit-tool default) |
| **Malicious IP ranges** | Traffic to/from IPs inside a configurable blocklist of CIDR ranges |
| **Unusual traffic volume** | Conversations that move an unusually large number of bytes, or send packets at an unusually high rate (possible exfiltration or flood/DoS) |
| **Cleartext credentials** | HTTP Basic Authentication headers, HTML login form submissions (`username=...&password=...`), and FTP `USER`/`PASS` commands sent without encryption |

Every finding is tagged with a **severity**: `CRITICAL`, `HIGH`, `MEDIUM`,
`LOW`, or `INFO`, and the final report is sorted worst-first.

## Installation

Requires Python 3.8+.

```bash
git clone https://github.com/CS-Abuhelal/network-traffic-analyzer.git
cd network-traffic-analyzer
pip install -r requirements.txt
```

The only dependency is [Scapy](https://scapy.net/), which is used to read
and parse PCAP files. You do **not** need Npcap/WinPcap or admin
privileges to *analyze* existing capture files - those are only required
for *live* packet capture, which this tool doesn't do.

## Quick start

Five sample PCAP files are included in `sample_pcaps/` so you can try the
tool immediately without needing your own capture:

```bash
python analyzer.py sample_pcaps/mixed_suspicious.pcap
```

This prints a full report to the terminal. To also save it to a file:

```bash
python analyzer.py sample_pcaps/mixed_suspicious.pcap --output report.txt
```

To analyze your own capture:

```bash
python analyzer.py path/to/your_capture.pcap
```

### Sample output

```
======================================================================
  NETWORK TRAFFIC ANALYZER - SUMMARY REPORT
======================================================================
  File analyzed   : sample_pcaps/mixed_suspicious.pcap
  Generated at    : 2026-06-18 13:55:08
  Packets read    : 323
  Total findings  : 7

  Findings by severity:
      CRITICAL : 3
      HIGH     : 4
======================================================================

--- CRITICAL ----------------------------------------------------------
  [CRITICAL] Malicious IP Range: Traffic between 192.168.1.10 and 203.0.113.99
  involves 203.0.113.99, which falls inside blocklisted range 203.0.113.0/24.

  [CRITICAL] Cleartext Credentials: HTTP form submission with a password field
  sent unencrypted from 192.168.1.18 to 10.50.0.40:80.
      - username: svc_backup
      - password: W**********

--- HIGH --------------------------------------------------------------
  [HIGH] Port Scan (Vertical): 192.168.1.60 contacted 19 distinct ports on
  192.168.1.21 - looks like port scanning / service discovery.

  [HIGH] Suspicious Protocol: Telnet traffic seen from 192.168.1.17 to
  192.168.1.6:23 - remote login with no encryption.

  [HIGH] Unusual Packet Rate: 192.168.1.70 -> 192.168.1.22 sent 300 packets
  in 0.60s (~502 packets/sec) - possible flood/DoS behavior.
```

Detected passwords are **masked** in the report — first character, then
stars. The tool's job is to tell you *that* credentials leaked and
*where*. It shouldn't become a second place plaintext passwords get
written down.

## Sample PCAP files

| File | Demonstrates |
|---|---|
| `sample_pcaps/normal_traffic.pcap` | A clean baseline - DNS, HTTP, and HTTPS-looking traffic with nothing suspicious. Produces **zero** findings, by design. |
| `sample_pcaps/port_scan.pcap` | A vertical scan (40 ports on one host) and a horizontal sweep (port 22 across 15 hosts) |
| `sample_pcaps/malicious_ip_traffic.pcap` | A host talking to an IP inside the sample blocklist, on a port commonly used by exploit frameworks |
| `sample_pcaps/cleartext_credentials.pcap` | An HTTP login form, an HTTP Basic Auth header, and an FTP login - all unencrypted |
| `sample_pcaps/mixed_suspicious.pcap` | A combination of all five detection categories in one capture, for a full demo report |

These were generated synthetically with `sample_pcaps/generate_samples.py`
(using Scapy to build packets directly) - no real hosts, traffic, or
credentials are involved. Regenerate them anytime with:

```bash
python sample_pcaps/generate_samples.py
```

## About the malicious IP blocklist

`data/sample_blocklist.txt` is **sample data for demo and testing only**.
It uses the IP ranges reserved by [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)
specifically for documentation and examples (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`). These addresses aren't routable on
the real internet and aren't tied to any actual attacker - they just give
the tool something realistic to detect without making false claims about
real-world IPs.

For real use, point `--blocklist` at an actual threat-intel feed, e.g.:

- [Spamhaus DROP / EDROP](https://www.spamhaus.org/drop/)
- [AbuseIPDB](https://www.abuseipdb.com/) blacklist export
- [AlienVault OTX](https://otx.alienvault.com/) pulses
- Your own firewall/SIEM block list

The file format is simple - one CIDR range per line, `#` for comments:

```
198.51.100.0/24   # known botnet C2 range
203.0.113.50/32   # single malicious host
```

## Tuning detection thresholds

Every threshold has a sensible default but can be overridden from the
command line, since "normal" traffic volume looks very different on a
home network vs. a busy server:

```bash
python analyzer.py capture.pcap \
  --port-scan-threshold 20 \
  --sweep-threshold 15 \
  --byte-threshold 1000000 \
  --pps-threshold 300 \
  --blocklist my_blocklist.txt
```

| Flag | Default | Meaning |
|---|---|---|
| `--port-scan-threshold` | 15 | Distinct ports on one host that counts as a vertical port scan |
| `--sweep-threshold` | 10 | Distinct hosts hit on the same port that counts as a network sweep |
| `--byte-threshold` | 500,000 | Bytes between one source/destination pair that counts as unusual volume |
| `--pps-threshold` | 200 | Packets per second that counts as an unusual rate (possible flood) |
| `--blocklist` | `data/sample_blocklist.txt` | Path to a CIDR blocklist file |
| `--output` | *(none)* | Also save the report to this file |

## Project structure

```
network-traffic-analyzer/
├── analyzer.py                  # CLI entry point
├── netanalyzer/
│   ├── detectors.py             # The 5 detection functions
│   ├── report.py                # Finding data class + report formatting
│   └── blocklist.py             # CIDR blocklist loading/matching
├── data/
│   └── sample_blocklist.txt     # Demo blocklist (RFC 5737 ranges)
├── sample_pcaps/
│   ├── generate_samples.py      # Builds the sample PCAP files
│   └── *.pcap                   # The sample captures themselves
├── tests/
│   └── test_analyzer.py         # Unit tests for each detector
└── requirements.txt
```

## Running the tests

```bash
python tests/test_analyzer.py -v
# or, if you have pytest installed:
python -m pytest tests/ -v
```

## How the detectors actually work

- **Port scans** (`detect_port_scans`): builds a dictionary of
  `source IP -> destination IP -> set of ports contacted`. If the set
  size crosses the threshold, it's a vertical scan. A second dictionary
  tracks `source IP -> port -> set of destination IPs` for horizontal
  sweeps.
- **Suspicious protocols** (`detect_suspicious_protocols`): a simple
  lookup table maps well-known insecure ports (Telnet, FTP, TFTP, SNMP,
  etc.) to a severity and an explanation.
- **Malicious IPs** (`detect_malicious_ips`): uses Python's built-in
  `ipaddress` module to check whether the source or destination IP of
  each packet falls inside any CIDR range from the blocklist file.
- **Unusual volume** (`detect_unusual_volume`): sums total bytes and
  packet counts per source/destination pair, and divides by the time
  between the first and last packet to estimate packets-per-second.
- **Cleartext credentials** (`detect_cleartext_credentials`): uses
  regular expressions to scan raw TCP payloads for `Authorization: Basic`
  headers (decoded from Base64), HTML form fields named `password`/`user`/
  etc., and FTP `USER`/`PASS` commands.

## Limitations

This is an educational project, not a production IDS:

- All detection is **offline**, on a static PCAP file - there's no live
  capture or real-time alerting.
- Thresholds are simple counts/rates, not statistical baselining - a
  sufficiently slow scan can stay under the radar.
- The credential and protocol detectors only look at unencrypted
  traffic; anything inside TLS/SSH is (correctly) invisible to a
  payload-based check like this.
- The included blocklist is sample data, not a live threat feed (see
  above).

## License

MIT
