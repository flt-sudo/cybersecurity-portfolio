# Network Traffic Analysis

## Overview

This project demonstrates practical network traffic analysis skills used daily in
SOC and incident response roles. It covers packet-level inspection, protocol
analysis, threat detection through network telemetry, and structured investigation
workflows mapped to the MITRE ATT&CK framework.

Network traffic analysis is a core defensive skill. Attackers must use the network
to reach objectives -- whether exfiltrating data, communicating with C2
infrastructure, or moving laterally. Understanding how to capture, filter, and
interpret that traffic is essential for detection and response.

## Tools and Technologies

| Tool | Purpose |
|------|---------|
| **Wireshark** | GUI-based deep packet inspection and protocol dissection |
| **tcpdump** | Command-line packet capture and lightweight filtering |
| **Python (struct, socket)** | Custom pcap parsing and automated analysis |
| **Python (re, math, collections)** | DNS log analysis and anomaly detection |
| **Scapy** | Referenced as production-grade packet manipulation library |
| **BPF (Berkeley Packet Filter)** | Kernel-level capture filter syntax for tcpdump |

## Project Structure

```
06-network-traffic-analysis/
├── README.md                              # This file
├── captures/                              # Directory for pcap files (samples not included due to size)
├── scripts/
│   ├── pcap_analyzer.py                   # Lightweight pcap parser and traffic analyzer
│   └── dns_analyzer.py                    # DNS log analyzer for tunneling/DGA detection
├── filters/
│   ├── wireshark-filters.md               # Wireshark display filter reference by threat category
│   └── tcpdump-filters.md                 # BPF/tcpdump filter reference for capture scenarios
└── docs/
    ├── traffic-analysis-writeup-01.md     # C2 beaconing investigation write-up
    └── traffic-analysis-writeup-02.md     # Port scan investigation write-up
```

## Components

### Scripts

**pcap_analyzer.py** -- A Python script that parses pcap files using only the
standard library (`struct` module for binary unpacking). It reads the pcap global
header and per-packet record headers, then parses Ethernet, IPv4, TCP, and UDP
headers to extract flow information. The script generates:

- Top talkers (source IPs by packet count and byte volume)
- Top destinations
- Port distribution across TCP and UDP
- Protocol breakdown (TCP, UDP, ICMP, other)
- Suspicious pattern flags: port scans, beaconing behavior, DNS tunneling
  indicators, and connections to unusual ports

**dns_analyzer.py** -- A Python script that reads DNS query logs in common
tab-separated or space-delimited format and applies multiple detection heuristics:

- Shannon entropy calculation to detect DGA (Domain Generation Algorithm) domains
- Query length analysis to identify potential DNS tunneling
- Frequency analysis to find beaconing or high-volume lookups
- TLD reputation checks against a list of commonly abused TLDs
- Subdomain depth analysis for exfiltration patterns

### Filter References

**wireshark-filters.md** -- A categorized reference of Wireshark display filters
organized by threat type: reconnaissance, C2 communications, data exfiltration,
credential theft, web application attacks, and lateral movement. Each filter
includes an explanation of what it detects and why it matters.

**tcpdump-filters.md** -- Equivalent BPF filter expressions for tcpdump, organized
around common capture scenarios encountered during incident response and threat
hunting.

### Investigation Write-ups

**writeup-01: C2 Beaconing Detection** -- A structured investigation of periodic
outbound HTTPS connections to a suspicious domain. Walks through the full analysis
chain from initial detection through DNS inspection, TLS certificate examination,
payload size analysis, and endpoint correlation. Maps findings to MITRE ATT&CK
T1071.001 (Web Protocols) and T1573 (Encrypted Channel).

**writeup-02: Port Scan Analysis** -- Analysis of IDS alerts indicating port scan
activity targeting DMZ hosts. Covers TCP flag analysis to distinguish SYN scans
from full connect scans, timing analysis, target enumeration, and response actions.
Maps to MITRE ATT&CK T1046 (Network Service Discovery).

## Usage

### Analyzing a pcap file

```bash
python3 scripts/pcap_analyzer.py --pcap captures/suspicious_traffic.pcap
python3 scripts/pcap_analyzer.py --pcap captures/suspicious_traffic.pcap --json report.json
python3 scripts/pcap_analyzer.py --pcap captures/suspicious_traffic.pcap --top 20
```

### Analyzing DNS logs

```bash
python3 scripts/dns_analyzer.py --logfile /var/log/dns/query.log
python3 scripts/dns_analyzer.py --logfile dns_queries.log --entropy-threshold 3.8
python3 scripts/dns_analyzer.py --logfile dns_queries.log --json dns_report.json
```

## Key Concepts Demonstrated

- **Packet structure understanding** -- Parsing Ethernet frames, IP headers, and
  transport layer headers at the byte level
- **Traffic baselining** -- Identifying what normal looks like so anomalies stand out
- **Protocol analysis** -- Understanding expected behavior for DNS, HTTP/S, SMB, and
  other protocols to spot misuse
- **Statistical detection** -- Using frequency, entropy, and timing analysis to find
  threats that signature-based tools miss
- **Structured investigation** -- Following a repeatable methodology from alert to
  conclusion with documented evidence
- **MITRE ATT&CK mapping** -- Connecting observed network behaviors to adversary
  techniques for consistent reporting

## Note on Dependencies

The scripts in this project use only the Python standard library to demonstrate
understanding of underlying packet structures and analysis logic. In production
environments, libraries such as **scapy**, **pyshark**, and **dpkt** provide
more robust parsing, handle edge cases in malformed packets, and support a wider
range of protocols. The standard-library approach here is intentional -- it shows
the analyst understands what these libraries abstract away.
