"""
blocklist.py
------------
Loads a list of "known bad" IP ranges (CIDR blocks) from a text file and
provides a simple way to check whether a given IP address falls inside
one of those ranges.

In a real SOC environment, this list would come from a live threat-intel
feed (Spamhaus DROP, AbuseIPDB, AlienVault OTX, your own incident
history, etc.) and would be refreshed regularly. For this project we
ship a small sample file (data/sample_blocklist.txt) using IP ranges
that are officially reserved for documentation/examples (RFC 5737), so
the demo never makes claims about real, currently-malicious IPs.
"""

import ipaddress


def load_blocklist(path):
    """
    Read a text file of CIDR ranges (one per line, '#' starts a comment)
    and return a list of ipaddress network objects.
    """
    networks = []
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                # Skip malformed lines instead of crashing the whole tool.
                continue
    return networks


def find_matching_network(ip_str, networks):
    """
    Return the CIDR network (as a string) that contains ip_str, or None
    if the IP isn't in any of the given networks.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    for network in networks:
        if ip in network:
            return str(network)
    return None
