#!/usr/bin/env python3
"""
pcap_analyzer.py - Lightweight PCAP file analyzer using only the Python standard library.

Parses pcap files at the byte level using the struct module to extract:
  - Source and destination IP addresses (IPv4)
  - Source and destination ports (TCP/UDP)
  - Protocol identification (TCP, UDP, ICMP)
  - Packet sizes and timestamps

Generates traffic statistics and flags suspicious patterns including:
  - Port scans (single source contacting many destination ports)
  - Beaconing (connections at regular intervals)
  - DNS tunneling indicators (queries with unusually long names)
  - Connections to unusual or high-risk ports

NOTE: This script is built for educational purposes and portfolio demonstration.
For production packet analysis, use scapy, pyshark, or dpkt which handle
malformed packets, fragmentation, encapsulation, and many more protocols.

Usage:
    python3 pcap_analyzer.py --pcap capture.pcap
    python3 pcap_analyzer.py --pcap capture.pcap --json report.json --top 20
"""

import struct
import socket
import argparse
import collections
import json
import datetime
import os
import sys
import math

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pcap magic numbers (native byte order variations)
PCAP_MAGIC_LE = 0xA1B2C3D4  # Little-endian microsecond resolution
PCAP_MAGIC_BE = 0xD4C3B2A1  # Big-endian microsecond resolution
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # Little-endian nanosecond resolution
PCAP_MAGIC_NS_BE = 0x4D3CB2A1  # Big-endian nanosecond resolution

# Ethernet
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# IP protocols
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

PROTO_NAMES = {
    PROTO_ICMP: "ICMP",
    PROTO_TCP: "TCP",
    PROTO_UDP: "UDP",
}

# Suspicious port lists
KNOWN_BAD_PORTS = {
    4444,   # Metasploit default
    5555,   # Common RAT / Android debug
    1337,   # Common backdoor convention
    31337,  # Back Orifice / leet backdoor
    8888,   # Alternate HTTP, sometimes C2
    9999,   # Common RAT
    12345,  # NetBus
    65535,  # Sometimes used by malware to avoid detection
}

COMMON_SERVICE_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 500, 514,
    515, 587, 636, 993, 995, 1433, 1434, 1521, 1723, 3306, 3389,
    5060, 5432, 5900, 5985, 5986, 8080, 8443,
}

# Thresholds for suspicious pattern detection
PORT_SCAN_THRESHOLD = 15          # Unique dest ports from single source
BEACONING_TOLERANCE = 0.15        # 15% jitter tolerance for interval detection
BEACONING_MIN_CONNECTIONS = 5     # Minimum connections to check for beaconing
DNS_NAME_LENGTH_THRESHOLD = 50    # Characters in DNS query name
DNS_LABEL_LENGTH_THRESHOLD = 30   # Characters in a single DNS label


# ---------------------------------------------------------------------------
# Pcap parsing
# ---------------------------------------------------------------------------

class PcapReader:
    """Reads and parses a pcap file at the byte level."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.endian = "<"  # Default little-endian
        self.link_type = 1  # Default Ethernet
        self.packets = []

    def read(self):
        """Read the entire pcap file and return parsed packet metadata."""
        with open(self.filepath, "rb") as f:
            self._read_global_header(f)
            self._read_packets(f)
        return self.packets

    def _read_global_header(self, f):
        """Parse the 24-byte pcap global header."""
        raw = f.read(24)
        if len(raw) < 24:
            raise ValueError("File too small to contain a valid pcap header.")

        magic = struct.unpack("<I", raw[0:4])[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self.endian = "<"
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            self.endian = ">"
        else:
            raise ValueError(
                f"Not a valid pcap file (magic: 0x{magic:08X}). "
                "Pcapng format is not supported by this lightweight parser."
            )

        # Unpack: magic, version_major, version_minor, thiszone, sigfigs,
        #         snaplen, link_type
        header = struct.unpack(self.endian + "IHHiIII", raw)
        self.link_type = header[6]

        if self.link_type != 1:
            print(
                f"[!] Warning: Link type {self.link_type} detected. "
                "This parser is optimized for Ethernet (type 1). "
                "Results may be incomplete.",
                file=sys.stderr,
            )

    def _read_packets(self, f):
        """Read all packet records from the pcap file."""
        pkt_header_fmt = self.endian + "IIII"  # ts_sec, ts_usec, incl_len, orig_len
        pkt_header_size = struct.calcsize(pkt_header_fmt)

        while True:
            raw_header = f.read(pkt_header_size)
            if len(raw_header) < pkt_header_size:
                break  # End of file

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                pkt_header_fmt, raw_header
            )

            raw_data = f.read(incl_len)
            if len(raw_data) < incl_len:
                break  # Truncated file

            pkt_info = self._parse_packet(raw_data, ts_sec, ts_usec, orig_len)
            if pkt_info:
                self.packets.append(pkt_info)

    def _parse_packet(self, data, ts_sec, ts_usec, orig_len):
        """Parse Ethernet -> IP -> TCP/UDP headers from raw packet bytes."""
        result = {
            "timestamp": ts_sec + ts_usec / 1_000_000,
            "orig_len": orig_len,
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "protocol_name": "OTHER",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "dns_query": None,
        }

        # -- Ethernet header (14 bytes) --
        if len(data) < 14:
            return None

        eth_header = struct.unpack("!6s6sH", data[0:14])
        ethertype = eth_header[2]
        offset = 14

        # Handle 802.1Q VLAN tag
        if ethertype == ETHERTYPE_VLAN:
            if len(data) < 18:
                return None
            ethertype = struct.unpack("!H", data[16:18])[0]
            offset = 18

        if ethertype != ETHERTYPE_IPV4:
            return result  # We only parse IPv4 in this lightweight tool

        # -- IPv4 header (20 bytes minimum) --
        if len(data) < offset + 20:
            return None

        ip_header = data[offset : offset + 20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4  # Header length in bytes

        if version != 4:
            return result

        total_length = iph[2]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        result["src_ip"] = src_ip
        result["dst_ip"] = dst_ip
        result["protocol"] = protocol
        result["protocol_name"] = PROTO_NAMES.get(protocol, f"PROTO_{protocol}")

        transport_offset = offset + ihl

        # -- TCP header (20 bytes minimum) --
        if protocol == PROTO_TCP:
            if len(data) < transport_offset + 20:
                return result

            tcp_header = data[transport_offset : transport_offset + 20]
            tcph = struct.unpack("!HHIIBBHHH", tcp_header)
            result["src_port"] = tcph[0]
            result["dst_port"] = tcph[1]

            # TCP flags are in the 6th byte (offset 13 of TCP header)
            flag_byte = tcph[5]
            result["tcp_flags"] = {
                "FIN": bool(flag_byte & 0x01),
                "SYN": bool(flag_byte & 0x02),
                "RST": bool(flag_byte & 0x04),
                "PSH": bool(flag_byte & 0x08),
                "ACK": bool(flag_byte & 0x10),
                "URG": bool(flag_byte & 0x20),
            }

        # -- UDP header (8 bytes) --
        elif protocol == PROTO_UDP:
            if len(data) < transport_offset + 8:
                return result

            udp_header = data[transport_offset : transport_offset + 8]
            udph = struct.unpack("!HHHH", udp_header)
            result["src_port"] = udph[0]
            result["dst_port"] = udph[1]

            # Attempt lightweight DNS parsing if port 53
            if udph[0] == 53 or udph[1] == 53:
                dns_offset = transport_offset + 8
                result["dns_query"] = self._parse_dns_query(data, dns_offset)

        return result

    def _parse_dns_query(self, data, offset):
        """Attempt to extract the query name from a DNS packet."""
        # DNS header is 12 bytes: ID, flags, qdcount, ancount, nscount, arcount
        if len(data) < offset + 12:
            return None

        dns_header = struct.unpack("!HHHHHH", data[offset : offset + 12])
        qd_count = dns_header[2]
        if qd_count == 0:
            return None

        # Parse the question section (first query only)
        pos = offset + 12
        labels = []
        while pos < len(data):
            label_len = data[pos]
            if label_len == 0:
                break
            if label_len >= 0xC0:
                # Compressed label -- skip for this lightweight parser
                break
            pos += 1
            if pos + label_len > len(data):
                break
            try:
                labels.append(data[pos : pos + label_len].decode("ascii", errors="replace"))
            except Exception:
                break
            pos += label_len

        return ".".join(labels) if labels else None


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

class TrafficAnalyzer:
    """Analyzes parsed packet metadata and produces statistics and alerts."""

    def __init__(self, packets, top_n=10):
        self.packets = packets
        self.top_n = top_n
        self.alerts = []

    def analyze(self):
        """Run all analysis passes and return a structured report."""
        report = {
            "summary": self._summary(),
            "protocol_breakdown": self._protocol_breakdown(),
            "top_source_ips": self._top_sources(),
            "top_destination_ips": self._top_destinations(),
            "top_destination_ports": self._top_dest_ports(),
            "alerts": [],
        }

        # Run detection routines
        self._detect_port_scans()
        self._detect_beaconing()
        self._detect_dns_tunneling()
        self._detect_unusual_ports()

        report["alerts"] = self.alerts
        return report

    # -- Statistics --

    def _summary(self):
        """High-level traffic summary."""
        if not self.packets:
            return {"total_packets": 0}

        timestamps = [p["timestamp"] for p in self.packets]
        total_bytes = sum(p["orig_len"] for p in self.packets)

        start = min(timestamps)
        end = max(timestamps)
        duration = end - start if end > start else 0

        unique_src = len(set(p["src_ip"] for p in self.packets if p["src_ip"]))
        unique_dst = len(set(p["dst_ip"] for p in self.packets if p["dst_ip"]))

        return {
            "total_packets": len(self.packets),
            "total_bytes": total_bytes,
            "capture_start": datetime.datetime.fromtimestamp(start, tz=datetime.timezone.utc).isoformat(),
            "capture_end": datetime.datetime.fromtimestamp(end, tz=datetime.timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "unique_source_ips": unique_src,
            "unique_destination_ips": unique_dst,
        }

    def _protocol_breakdown(self):
        """Count packets by protocol."""
        counter = collections.Counter(p["protocol_name"] for p in self.packets)
        total = len(self.packets)
        return {
            proto: {"count": count, "percent": round(count / total * 100, 1)}
            for proto, count in counter.most_common()
        }

    def _top_sources(self):
        """Top source IPs by packet count."""
        counter = collections.Counter(
            p["src_ip"] for p in self.packets if p["src_ip"]
        )
        byte_counter = collections.Counter()
        for p in self.packets:
            if p["src_ip"]:
                byte_counter[p["src_ip"]] += p["orig_len"]

        return [
            {"ip": ip, "packets": count, "bytes": byte_counter[ip]}
            for ip, count in counter.most_common(self.top_n)
        ]

    def _top_destinations(self):
        """Top destination IPs by packet count."""
        counter = collections.Counter(
            p["dst_ip"] for p in self.packets if p["dst_ip"]
        )
        byte_counter = collections.Counter()
        for p in self.packets:
            if p["dst_ip"]:
                byte_counter[p["dst_ip"]] += p["orig_len"]

        return [
            {"ip": ip, "packets": count, "bytes": byte_counter[ip]}
            for ip, count in counter.most_common(self.top_n)
        ]

    def _top_dest_ports(self):
        """Top destination ports."""
        counter = collections.Counter(
            (p["protocol_name"], p["dst_port"])
            for p in self.packets
            if p["dst_port"] is not None
        )
        return [
            {"protocol": proto, "port": port, "count": count}
            for (proto, port), count in counter.most_common(self.top_n)
        ]

    # -- Detection routines --

    def _detect_port_scans(self):
        """Detect potential port scans: one source hitting many destination ports."""
        src_to_dst_ports = collections.defaultdict(set)
        src_to_dst_ips = collections.defaultdict(set)

        for p in self.packets:
            if p["src_ip"] and p["dst_port"] is not None:
                src_to_dst_ports[p["src_ip"]].add(p["dst_port"])
                src_to_dst_ips[p["src_ip"]].add(p["dst_ip"])

        for src_ip, ports in src_to_dst_ports.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                # Check for SYN-only packets (SYN scan signature)
                syn_only = sum(
                    1 for p in self.packets
                    if p["src_ip"] == src_ip
                    and p["tcp_flags"]
                    and p["tcp_flags"]["SYN"]
                    and not p["tcp_flags"]["ACK"]
                )
                total_from_src = sum(
                    1 for p in self.packets if p["src_ip"] == src_ip
                )
                scan_type = "SYN scan" if syn_only > total_from_src * 0.7 else "connect scan"
                targets = src_to_dst_ips[src_ip]

                self.alerts.append({
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "unique_ports_contacted": len(ports),
                    "target_hosts": len(targets),
                    "scan_type": scan_type,
                    "description": (
                        f"Host {src_ip} contacted {len(ports)} unique destination "
                        f"ports across {len(targets)} host(s). "
                        f"Likely {scan_type} activity."
                    ),
                    "mitre_attack": "T1046 - Network Service Discovery",
                })

    def _detect_beaconing(self):
        """Detect beaconing: regular-interval connections from a source to a destination."""
        # Group connections by (src_ip, dst_ip) pair
        flow_times = collections.defaultdict(list)
        for p in self.packets:
            if p["src_ip"] and p["dst_ip"] and p["protocol"] == PROTO_TCP:
                # Only look at SYN packets (new connections) or all if no flag info
                if p["tcp_flags"] and p["tcp_flags"]["SYN"] and not p["tcp_flags"]["ACK"]:
                    flow_times[(p["src_ip"], p["dst_ip"])].append(p["timestamp"])

        for (src, dst), times in flow_times.items():
            if len(times) < BEACONING_MIN_CONNECTIONS:
                continue

            times.sort()
            intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]

            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 1:
                continue  # Sub-second intervals are likely normal traffic

            # Check if intervals are consistent (low jitter)
            within_tolerance = sum(
                1 for iv in intervals
                if abs(iv - mean_interval) <= mean_interval * BEACONING_TOLERANCE
            )
            consistency = within_tolerance / len(intervals)

            if consistency >= 0.75:
                self.alerts.append({
                    "type": "BEACONING",
                    "severity": "HIGH",
                    "source_ip": src,
                    "destination_ip": dst,
                    "connections": len(times),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "consistency_percent": round(consistency * 100, 1),
                    "description": (
                        f"Host {src} connects to {dst} at regular intervals "
                        f"(~{mean_interval:.0f}s, {consistency * 100:.0f}% consistent "
                        f"over {len(times)} connections). "
                        "Possible C2 beaconing."
                    ),
                    "mitre_attack": "T1071 - Application Layer Protocol",
                })

    def _detect_dns_tunneling(self):
        """Detect possible DNS tunneling via unusually long query names."""
        dns_packets = [p for p in self.packets if p["dns_query"]]

        for p in dns_packets:
            query = p["dns_query"]
            total_len = len(query)
            labels = query.split(".")
            max_label = max((len(l) for l in labels), default=0)

            # Calculate entropy of the longest subdomain label
            subdomain = labels[0] if labels else ""
            entropy = self._shannon_entropy(subdomain)

            reasons = []
            if total_len > DNS_NAME_LENGTH_THRESHOLD:
                reasons.append(f"query length {total_len} chars")
            if max_label > DNS_LABEL_LENGTH_THRESHOLD:
                reasons.append(f"label length {max_label} chars")
            if entropy > 3.5 and len(subdomain) > 15:
                reasons.append(f"high entropy subdomain ({entropy:.2f})")

            if reasons:
                self.alerts.append({
                    "type": "DNS_TUNNELING_INDICATOR",
                    "severity": "MEDIUM",
                    "source_ip": p["src_ip"],
                    "destination_ip": p["dst_ip"],
                    "query": query,
                    "reasons": reasons,
                    "description": (
                        f"Suspicious DNS query from {p['src_ip']}: {query} "
                        f"({', '.join(reasons)}). Possible DNS tunneling."
                    ),
                    "mitre_attack": "T1071.004 - DNS",
                })

    def _detect_unusual_ports(self):
        """Flag connections to ports commonly associated with malicious tools."""
        seen = set()
        for p in self.packets:
            if p["dst_port"] in KNOWN_BAD_PORTS:
                key = (p["src_ip"], p["dst_ip"], p["dst_port"])
                if key not in seen:
                    seen.add(key)
                    self.alerts.append({
                        "type": "UNUSUAL_PORT",
                        "severity": "MEDIUM",
                        "source_ip": p["src_ip"],
                        "destination_ip": p["dst_ip"],
                        "port": p["dst_port"],
                        "protocol": p["protocol_name"],
                        "description": (
                            f"Connection from {p['src_ip']} to {p['dst_ip']}:"
                            f"{p['dst_port']} ({p['protocol_name']}). "
                            f"Port {p['dst_port']} is commonly associated with "
                            "malicious tools or backdoors."
                        ),
                        "mitre_attack": "T1571 - Non-Standard Port",
                    })

    @staticmethod
    def _shannon_entropy(text):
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = collections.Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def print_report(report):
    """Print a human-readable report to stdout."""
    s = report["summary"]
    print("=" * 72)
    print("  PCAP TRAFFIC ANALYSIS REPORT")
    print("=" * 72)

    print(f"\n  Total packets:        {s.get('total_packets', 0)}")
    print(f"  Total bytes:          {s.get('total_bytes', 0):,}")
    print(f"  Capture start:        {s.get('capture_start', 'N/A')}")
    print(f"  Capture end:          {s.get('capture_end', 'N/A')}")
    print(f"  Duration:             {s.get('duration_seconds', 0)} seconds")
    print(f"  Unique source IPs:    {s.get('unique_source_ips', 0)}")
    print(f"  Unique dest IPs:      {s.get('unique_destination_ips', 0)}")

    # Protocol breakdown
    print("\n" + "-" * 40)
    print("  PROTOCOL BREAKDOWN")
    print("-" * 40)
    for proto, info in report["protocol_breakdown"].items():
        bar = "#" * int(info["percent"] / 2)
        print(f"  {proto:<10} {info['count']:>8} pkts  ({info['percent']:>5.1f}%)  {bar}")

    # Top sources
    print("\n" + "-" * 40)
    print("  TOP SOURCE IPs (by packet count)")
    print("-" * 40)
    for entry in report["top_source_ips"]:
        print(f"  {entry['ip']:<18} {entry['packets']:>8} pkts  {entry['bytes']:>12,} bytes")

    # Top destinations
    print("\n" + "-" * 40)
    print("  TOP DESTINATION IPs (by packet count)")
    print("-" * 40)
    for entry in report["top_destination_ips"]:
        print(f"  {entry['ip']:<18} {entry['packets']:>8} pkts  {entry['bytes']:>12,} bytes")

    # Top ports
    print("\n" + "-" * 40)
    print("  TOP DESTINATION PORTS")
    print("-" * 40)
    for entry in report["top_destination_ports"]:
        print(f"  {entry['protocol']}/{entry['port']:<6}  {entry['count']:>8} pkts")

    # Alerts
    print("\n" + "=" * 72)
    print(f"  ALERTS ({len(report['alerts'])} findings)")
    print("=" * 72)

    if not report["alerts"]:
        print("  No suspicious patterns detected.")
    else:
        for i, alert in enumerate(report["alerts"], 1):
            severity_marker = {
                "HIGH": "[!!!]",
                "MEDIUM": "[!! ]",
                "LOW": "[!  ]",
                "INFO": "[i  ]",
            }.get(alert["severity"], "[?  ]")

            print(f"\n  {severity_marker} Alert #{i}: {alert['type']}")
            print(f"         Severity:    {alert['severity']}")
            print(f"         Description: {alert['description']}")
            print(f"         MITRE ATT&CK: {alert['mitre_attack']}")

    print("\n" + "=" * 72)


# ---------------------------------------------------------------------------
# Demo / sample data generation
# ---------------------------------------------------------------------------

def generate_demo_pcap(filepath):
    """Generate a small demo pcap file with synthetic traffic for testing.

    Creates packets that will trigger various detection routines:
    - Normal web traffic
    - A port scan from a single source
    - Beaconing-like periodic connections
    - A connection to a suspicious port
    """
    import random

    packets_raw = []

    def build_packet(ts_sec, ts_usec, src_ip, dst_ip, proto, src_port, dst_port,
                     tcp_flags=0x02, payload_size=0):
        """Build a raw Ethernet/IPv4/TCP|UDP packet."""
        # Ethernet header: dst_mac(6) + src_mac(6) + ethertype(2)
        eth = struct.pack("!6s6sH",
                          b"\x00\x11\x22\x33\x44\x55",
                          b"\x66\x77\x88\x99\xaa\xbb",
                          ETHERTYPE_IPV4)

        # IPv4 header (20 bytes, no options)
        src_packed = socket.inet_aton(src_ip)
        dst_packed = socket.inet_aton(dst_ip)
        if proto == PROTO_TCP:
            transport_len = 20 + payload_size
        else:
            transport_len = 8 + payload_size

        total_len = 20 + transport_len
        ip = struct.pack("!BBHHHBBH4s4s",
                         0x45,           # Version=4, IHL=5
                         0x00,           # DSCP/ECN
                         total_len,      # Total length
                         random.randint(1, 65535),  # Identification
                         0x4000,         # Flags=DF, Fragment offset=0
                         64,             # TTL
                         proto,          # Protocol
                         0x0000,         # Checksum (skip for demo)
                         src_packed,
                         dst_packed)

        if proto == PROTO_TCP:
            transport = struct.pack("!HHIIBBHHH",
                                    src_port,      # Source port
                                    dst_port,      # Dest port
                                    random.randint(0, 2**32 - 1),  # Seq
                                    0,             # Ack
                                    0x50,          # Data offset = 5 words
                                    tcp_flags,     # Flags
                                    65535,         # Window
                                    0x0000,        # Checksum
                                    0x0000)        # Urgent pointer
        else:
            transport = struct.pack("!HHHH",
                                    src_port,
                                    dst_port,
                                    8 + payload_size,  # Length
                                    0x0000)            # Checksum

        payload = b"\x00" * payload_size
        full_packet = eth + ip + transport + payload
        orig_len = len(full_packet)

        pkt_record = struct.pack("<IIII", ts_sec, ts_usec, orig_len, orig_len)
        return pkt_record + full_packet

    base_time = 1700000000  # Fixed epoch for reproducibility

    # --- Normal web traffic ---
    for i in range(30):
        ts = base_time + i * 2
        packets_raw.append(build_packet(
            ts, 0,
            "10.0.0.50", "198.51.100.10",
            PROTO_TCP, random.randint(49152, 65535), 443,
            tcp_flags=0x02, payload_size=random.randint(40, 200)
        ))
        # Response
        packets_raw.append(build_packet(
            ts, 500000,
            "198.51.100.10", "10.0.0.50",
            PROTO_TCP, 443, random.randint(49152, 65535),
            tcp_flags=0x12, payload_size=random.randint(200, 1400)
        ))

    # --- Port scan: 10.0.0.200 -> 203.0.113.50, SYN packets to many ports ---
    scan_ports = list(range(20, 1025))
    random.shuffle(scan_ports)
    for i, port in enumerate(scan_ports[:50]):
        ts = base_time + 100 + i
        packets_raw.append(build_packet(
            ts, 0,
            "203.0.113.200", "10.0.0.25",
            PROTO_TCP, random.randint(49152, 65535), port,
            tcp_flags=0x02,  # SYN only
            payload_size=0
        ))

    # --- Beaconing: 10.0.0.75 -> 198.51.100.99 every ~60 seconds ---
    for i in range(10):
        ts = base_time + 200 + (i * 60)
        jitter = random.randint(-3, 3)
        packets_raw.append(build_packet(
            ts + jitter, 0,
            "10.0.0.75", "198.51.100.99",
            PROTO_TCP, random.randint(49152, 65535), 443,
            tcp_flags=0x02,
            payload_size=random.randint(80, 120)
        ))

    # --- Suspicious port connection ---
    packets_raw.append(build_packet(
        base_time + 900, 0,
        "10.0.0.30", "203.0.113.66",
        PROTO_TCP, random.randint(49152, 65535), 4444,
        tcp_flags=0x02,
        payload_size=0
    ))

    # --- DNS traffic with a suspiciously long query ---
    # Build a DNS query packet manually
    def build_dns_packet(ts_sec, src_ip, dst_ip, query_name):
        eth = struct.pack("!6s6sH",
                          b"\x00\x11\x22\x33\x44\x55",
                          b"\x66\x77\x88\x99\xaa\xbb",
                          ETHERTYPE_IPV4)
        # Build DNS payload
        dns_id = random.randint(0, 65535)
        dns_header = struct.pack("!HHHHHH",
                                 dns_id,    # Transaction ID
                                 0x0100,    # Flags: standard query
                                 1,         # Questions
                                 0, 0, 0)   # Answer, Authority, Additional

        # Encode query name
        qname = b""
        for label in query_name.split("."):
            qname += struct.pack("B", len(label)) + label.encode("ascii")
        qname += b"\x00"

        # QTYPE=A (1), QCLASS=IN (1)
        question = qname + struct.pack("!HH", 1, 1)
        dns_payload = dns_header + question

        udp_len = 8 + len(dns_payload)
        udp = struct.pack("!HHHH", random.randint(49152, 65535), 53, udp_len, 0)

        src_packed = socket.inet_aton(src_ip)
        dst_packed = socket.inet_aton(dst_ip)
        total_len = 20 + udp_len
        ip = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0x00, total_len,
                         random.randint(1, 65535), 0x4000,
                         64, PROTO_UDP, 0x0000,
                         src_packed, dst_packed)

        full_packet = eth + ip + udp + dns_payload
        pkt_record = struct.pack("<IIII", ts_sec, 0, len(full_packet), len(full_packet))
        return pkt_record + full_packet

    # Normal DNS
    packets_raw.append(build_dns_packet(
        base_time + 50, "10.0.0.50", "10.0.0.1", "www.example.com"
    ))

    # Suspicious DNS -- long subdomain (tunneling indicator)
    packets_raw.append(build_dns_packet(
        base_time + 55, "10.0.0.75", "10.0.0.1",
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgZG5z.tunnel.evil-c2.example.net"
    ))

    # Write pcap file
    # Global header: magic, version 2.4, timezone 0, sigfigs 0, snaplen 65535, Ethernet
    global_header = struct.pack("<IHHiIII",
                                PCAP_MAGIC_LE,
                                2, 4,
                                0, 0,
                                65535,
                                1)

    with open(filepath, "wb") as f:
        f.write(global_header)
        for pkt in packets_raw:
            f.write(pkt)

    print(f"[+] Demo pcap written to: {filepath}")
    print(f"    Packets: {len(packets_raw)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Lightweight PCAP traffic analyzer (standard library only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --pcap capture.pcap\n"
            "  %(prog)s --pcap capture.pcap --json report.json --top 20\n"
            "  %(prog)s --demo                # Generate and analyze a demo pcap\n"
            "\n"
            "NOTE: For production use, consider scapy, pyshark, or dpkt for\n"
            "more robust protocol parsing and malformed packet handling."
        ),
    )
    parser.add_argument(
        "--pcap", metavar="FILE",
        help="Path to the pcap file to analyze.",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="Write the report as JSON to the specified file.",
    )
    parser.add_argument(
        "--top", type=int, default=10,
        help="Number of entries in top-N lists (default: 10).",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Generate a synthetic demo pcap and analyze it.",
    )

    args = parser.parse_args()

    if args.demo:
        demo_path = os.path.join(os.path.dirname(__file__), "..", "captures", "demo_traffic.pcap")
        demo_path = os.path.abspath(demo_path)
        generate_demo_pcap(demo_path)
        args.pcap = demo_path

    if not args.pcap:
        parser.error("Provide --pcap FILE or use --demo to generate sample data.")

    if not os.path.isfile(args.pcap):
        print(f"[!] Error: File not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading pcap: {args.pcap}")
    reader = PcapReader(args.pcap)
    try:
        packets = reader.read()
    except ValueError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsed {len(packets)} packets. Running analysis...")

    analyzer = TrafficAnalyzer(packets, top_n=args.top)
    report = analyzer.analyze()

    print_report(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report written to: {args.json}")


if __name__ == "__main__":
    main()
