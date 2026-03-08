#!/usr/bin/env python3
"""
dns_analyzer.py - DNS query log analyzer for detecting tunneling, DGA, and abuse.

Reads DNS query logs in common formats and applies multiple detection heuristics:
  - Shannon entropy calculation to detect DGA (Domain Generation Algorithm) domains
  - Query length analysis to identify potential DNS tunneling
  - Frequency analysis to find beaconing or high-volume lookups
  - TLD reputation checks against commonly abused TLDs
  - Subdomain depth and label analysis

Supports log formats:
  - BIND query log: "timestamp client IP#port (domain): view: query: domain IN type ..."
  - Simple tab/space-delimited: "timestamp source_ip query_name query_type"
  - One domain per line (plain list)

Usage:
    python3 dns_analyzer.py --logfile /var/log/dns/query.log
    python3 dns_analyzer.py --logfile queries.log --entropy-threshold 3.8 --json report.json
    python3 dns_analyzer.py --demo
"""

import re
import math
import argparse
import collections
import json
import os
import sys
import datetime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# TLDs frequently observed in malicious infrastructure
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",        # Freenom free TLDs (heavy abuse)
    "top", "xyz", "club", "work", "date",  # Cheap TLDs popular with spam/malware
    "stream", "download", "racing",        # Often seen in adware/malware
    "win", "bid", "loan", "click",         # Phishing/scam heavy
    "pw", "cc", "su",                      # Country codes with high abuse rates
    "onion",                               # Tor hidden services (via DNS = suspicious)
}

# Thresholds
DEFAULT_ENTROPY_THRESHOLD = 3.5
QUERY_LENGTH_THRESHOLD = 50          # Total FQDN length
LABEL_LENGTH_THRESHOLD = 24          # Single label length
HIGH_FREQUENCY_THRESHOLD = 50        # Queries to same domain in log window
SUBDOMAIN_DEPTH_THRESHOLD = 5        # Number of labels before effective TLD
DGA_MIN_LABEL_LENGTH = 8             # Minimum length for entropy check to matter

# Known legitimate high-entropy domains to reduce false positives
WHITELIST_PATTERNS = [
    re.compile(r".*\.amazonaws\.com$"),
    re.compile(r".*\.cloudfront\.net$"),
    re.compile(r".*\.googlevideo\.com$"),
    re.compile(r".*\.akamaiedge\.net$"),
    re.compile(r".*\.akamai\.net$"),
    re.compile(r".*\.cloudflare\.com$"),
    re.compile(r".*\.windows\.net$"),
    re.compile(r".*\.microsoft\.com$"),
    re.compile(r".*\.apple\.com$"),
    re.compile(r".*\.icloud\.com$"),
    re.compile(r"_[a-z]+\._tcp\..*"),  # SRV records
    re.compile(r"_[a-z]+\._udp\..*"),  # SRV records
]


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

class DNSLogParser:
    """Parse DNS query logs in multiple common formats."""

    # BIND-style: 06-Mar-2026 14:22:01.123 client 10.0.0.50#12345 (example.com): ...
    BIND_RE = re.compile(
        r"(?P<timestamp>\S+\s+\S+)\s+"
        r".*?client\s+(?P<client_ip>[\d.]+)#\d+\s+"
        r"\((?P<domain>[^)]+)\)"
    )

    # Dnsmasq-style: Mar  6 14:22:01 dnsmasq[1234]: query[A] example.com from 10.0.0.50
    DNSMASQ_RE = re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+.*?"
        r"query\[(?P<qtype>\w+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client_ip>[\d.]+)"
    )

    # Simple space/tab-delimited: 2026-03-06T14:22:01Z 10.0.0.50 example.com A
    SIMPLE_RE = re.compile(
        r"(?P<timestamp>\S+)\s+(?P<client_ip>[\d.]+)\s+(?P<domain>\S+)\s*(?P<qtype>\w+)?"
    )

    @classmethod
    def parse_file(cls, filepath):
        """Parse a DNS log file and return a list of query records."""
        records = []
        with open(filepath, "r", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                record = cls._parse_line(line, line_num)
                if record:
                    records.append(record)

        return records

    @classmethod
    def _parse_line(cls, line, line_num):
        """Attempt to parse a single log line using multiple format patterns."""
        # Try BIND format first
        m = cls.BIND_RE.search(line)
        if m:
            return {
                "line_num": line_num,
                "timestamp": m.group("timestamp"),
                "client_ip": m.group("client_ip"),
                "domain": m.group("domain").lower().rstrip("."),
                "query_type": "A",  # BIND format parsed here doesn't always include type
            }

        # Try dnsmasq format
        m = cls.DNSMASQ_RE.search(line)
        if m:
            return {
                "line_num": line_num,
                "timestamp": m.group("timestamp"),
                "client_ip": m.group("client_ip"),
                "domain": m.group("domain").lower().rstrip("."),
                "query_type": m.group("qtype") or "A",
            }

        # Try simple format
        m = cls.SIMPLE_RE.match(line)
        if m and m.group("domain") and "." in m.group("domain"):
            return {
                "line_num": line_num,
                "timestamp": m.group("timestamp"),
                "client_ip": m.group("client_ip"),
                "domain": m.group("domain").lower().rstrip("."),
                "query_type": m.group("qtype") or "A",
            }

        # Last resort: treat as plain domain name (one per line)
        if "." in line and " " not in line and len(line) < 255:
            return {
                "line_num": line_num,
                "timestamp": "N/A",
                "client_ip": "unknown",
                "domain": line.lower().rstrip("."),
                "query_type": "A",
            }

        return None


# ---------------------------------------------------------------------------
# Analysis engine
# ---------------------------------------------------------------------------

class DNSAnalyzer:
    """Analyze parsed DNS records for suspicious patterns."""

    def __init__(self, records, entropy_threshold=DEFAULT_ENTROPY_THRESHOLD):
        self.records = records
        self.entropy_threshold = entropy_threshold
        self.findings = []

    def analyze(self):
        """Run all detection heuristics and return a structured report."""
        self._detect_high_frequency()
        self._detect_long_queries()
        self._detect_dga_domains()
        self._detect_suspicious_tlds()
        self._detect_deep_subdomains()

        # Deduplicate findings by domain (keep highest severity)
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        seen = {}
        for f in self.findings:
            key = (f["domain"], f["detection_type"])
            existing = seen.get(key)
            if not existing or severity_rank.get(f["severity"], 0) > severity_rank.get(existing["severity"], 0):
                seen[key] = f
        self.findings = sorted(seen.values(), key=lambda x: severity_rank.get(x["severity"], 0), reverse=True)

        return {
            "summary": {
                "total_queries": len(self.records),
                "unique_domains": len(set(r["domain"] for r in self.records)),
                "unique_clients": len(set(r["client_ip"] for r in self.records)),
                "total_findings": len(self.findings),
                "entropy_threshold": self.entropy_threshold,
            },
            "top_queried_domains": self._top_domains(),
            "top_clients": self._top_clients(),
            "query_type_distribution": self._query_type_distribution(),
            "findings": self.findings,
        }

    # -- Statistics --

    def _top_domains(self, n=15):
        counter = collections.Counter(r["domain"] for r in self.records)
        return [{"domain": d, "count": c} for d, c in counter.most_common(n)]

    def _top_clients(self, n=10):
        counter = collections.Counter(r["client_ip"] for r in self.records)
        return [{"client": ip, "queries": c} for ip, c in counter.most_common(n)]

    def _query_type_distribution(self):
        counter = collections.Counter(r["query_type"] for r in self.records)
        total = len(self.records)
        return {
            qtype: {"count": count, "percent": round(count / total * 100, 1)}
            for qtype, count in counter.most_common()
        }

    # -- Detection routines --

    def _detect_high_frequency(self):
        """Detect domains queried at unusually high frequency."""
        counter = collections.Counter(r["domain"] for r in self.records)
        for domain, count in counter.items():
            if count >= HIGH_FREQUENCY_THRESHOLD:
                # Check which clients are making the queries
                clients = set(
                    r["client_ip"] for r in self.records if r["domain"] == domain
                )
                self.findings.append({
                    "detection_type": "HIGH_FREQUENCY",
                    "severity": "MEDIUM",
                    "domain": domain,
                    "query_count": count,
                    "client_ips": sorted(clients),
                    "reason": (
                        f"Domain queried {count} times "
                        f"(threshold: {HIGH_FREQUENCY_THRESHOLD}). "
                        f"From {len(clients)} unique client(s). "
                        "May indicate beaconing, tunneling, or misconfiguration."
                    ),
                })

    def _detect_long_queries(self):
        """Detect unusually long domain names (DNS tunneling indicator)."""
        seen_domains = set()
        for r in self.records:
            domain = r["domain"]
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            labels = domain.split(".")
            max_label_len = max((len(l) for l in labels), default=0)

            reasons = []
            if len(domain) > QUERY_LENGTH_THRESHOLD:
                reasons.append(f"total length {len(domain)} chars (threshold: {QUERY_LENGTH_THRESHOLD})")
            if max_label_len > LABEL_LENGTH_THRESHOLD:
                reasons.append(f"label length {max_label_len} chars (threshold: {LABEL_LENGTH_THRESHOLD})")

            if reasons:
                clients = set(
                    rec["client_ip"] for rec in self.records if rec["domain"] == domain
                )
                self.findings.append({
                    "detection_type": "DNS_TUNNELING_LENGTH",
                    "severity": "HIGH",
                    "domain": domain,
                    "total_length": len(domain),
                    "max_label_length": max_label_len,
                    "label_count": len(labels),
                    "client_ips": sorted(clients),
                    "reason": (
                        f"Unusually long DNS query: {'; '.join(reasons)}. "
                        "Long queries can encode data in subdomain labels, "
                        "a common DNS tunneling technique."
                    ),
                    "mitre_attack": "T1071.004 - Application Layer Protocol: DNS",
                })

    def _detect_dga_domains(self):
        """Detect DGA-like domains using Shannon entropy analysis."""
        seen_domains = set()
        for r in self.records:
            domain = r["domain"]
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            # Skip whitelisted domains
            if self._is_whitelisted(domain):
                continue

            labels = domain.split(".")
            # Analyze the leftmost label (most likely to be DGA-generated)
            # Skip if TLD or too short
            if len(labels) < 2:
                continue

            # For domains like "abc123def.evil.com", check "abc123def"
            candidate_label = labels[0]
            if len(candidate_label) < DGA_MIN_LABEL_LENGTH:
                continue

            entropy = self._shannon_entropy(candidate_label)

            if entropy >= self.entropy_threshold:
                # Additional DGA indicators
                digit_ratio = sum(1 for c in candidate_label if c.isdigit()) / len(candidate_label)
                consonant_ratio = self._consonant_ratio(candidate_label)

                # High entropy alone can be a CDN hash -- require additional signals
                dga_score = 0
                dga_reasons = []

                if entropy >= 4.0:
                    dga_score += 2
                    dga_reasons.append(f"very high entropy ({entropy:.2f})")
                elif entropy >= self.entropy_threshold:
                    dga_score += 1
                    dga_reasons.append(f"elevated entropy ({entropy:.2f})")

                if digit_ratio > 0.3:
                    dga_score += 1
                    dga_reasons.append(f"high digit ratio ({digit_ratio:.0%})")

                if consonant_ratio > 0.7:
                    dga_score += 1
                    dga_reasons.append(f"high consonant ratio ({consonant_ratio:.0%})")

                if not any(c == "-" for c in candidate_label) and len(candidate_label) > 12:
                    dga_score += 1
                    dga_reasons.append("long label without hyphens")

                if dga_score >= 2:
                    severity = "HIGH" if dga_score >= 3 else "MEDIUM"
                    clients = set(
                        rec["client_ip"] for rec in self.records if rec["domain"] == domain
                    )
                    self.findings.append({
                        "detection_type": "DGA_DOMAIN",
                        "severity": severity,
                        "domain": domain,
                        "candidate_label": candidate_label,
                        "entropy": round(entropy, 3),
                        "digit_ratio": round(digit_ratio, 3),
                        "consonant_ratio": round(consonant_ratio, 3),
                        "dga_score": dga_score,
                        "client_ips": sorted(clients),
                        "reason": (
                            f"Domain appears algorithmically generated: "
                            f"{'; '.join(dga_reasons)}. "
                            "DGA domains are used by malware to dynamically "
                            "locate C2 infrastructure."
                        ),
                        "mitre_attack": "T1568.002 - Dynamic Resolution: Domain Generation Algorithms",
                    })

    def _detect_suspicious_tlds(self):
        """Flag queries to TLDs with high abuse rates."""
        seen_domains = set()
        for r in self.records:
            domain = r["domain"]
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                count = sum(1 for rec in self.records if rec["domain"] == domain)
                clients = set(
                    rec["client_ip"] for rec in self.records if rec["domain"] == domain
                )
                self.findings.append({
                    "detection_type": "SUSPICIOUS_TLD",
                    "severity": "LOW",
                    "domain": domain,
                    "tld": tld,
                    "query_count": count,
                    "client_ips": sorted(clients),
                    "reason": (
                        f"Query to .{tld} TLD which has historically high abuse "
                        f"rates. Domain queried {count} time(s). Warrants "
                        "additional investigation."
                    ),
                })

    def _detect_deep_subdomains(self):
        """Detect domains with unusually deep subdomain nesting."""
        seen_domains = set()
        for r in self.records:
            domain = r["domain"]
            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            if self._is_whitelisted(domain):
                continue

            labels = domain.split(".")
            # Subtract 2 for the base domain + TLD (approximation)
            depth = len(labels) - 2 if len(labels) > 2 else 0

            if depth >= SUBDOMAIN_DEPTH_THRESHOLD:
                clients = set(
                    rec["client_ip"] for rec in self.records if rec["domain"] == domain
                )
                self.findings.append({
                    "detection_type": "DEEP_SUBDOMAIN",
                    "severity": "MEDIUM",
                    "domain": domain,
                    "subdomain_depth": depth,
                    "label_count": len(labels),
                    "client_ips": sorted(clients),
                    "reason": (
                        f"Domain has {depth} subdomain levels "
                        f"(threshold: {SUBDOMAIN_DEPTH_THRESHOLD}). "
                        "Deep nesting can indicate DNS tunneling where data "
                        "is encoded across multiple subdomain labels."
                    ),
                    "mitre_attack": "T1071.004 - Application Layer Protocol: DNS",
                })

    # -- Utility methods --

    @staticmethod
    def _shannon_entropy(text):
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = collections.Counter(text.lower())
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @staticmethod
    def _consonant_ratio(text):
        """Calculate the ratio of consonants to total alphabetic characters."""
        vowels = set("aeiou")
        alpha_chars = [c for c in text.lower() if c.isalpha()]
        if not alpha_chars:
            return 0.0
        consonants = sum(1 for c in alpha_chars if c not in vowels)
        return consonants / len(alpha_chars)

    @staticmethod
    def _is_whitelisted(domain):
        """Check if a domain matches known legitimate high-entropy patterns."""
        for pattern in WHITELIST_PATTERNS:
            if pattern.match(domain):
                return True
        return False


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def print_report(report):
    """Print a human-readable DNS analysis report."""
    s = report["summary"]

    print("=" * 72)
    print("  DNS QUERY LOG ANALYSIS REPORT")
    print("=" * 72)

    print(f"\n  Total queries analyzed: {s['total_queries']}")
    print(f"  Unique domains:        {s['unique_domains']}")
    print(f"  Unique clients:        {s['unique_clients']}")
    print(f"  Entropy threshold:     {s['entropy_threshold']}")

    # Query type distribution
    print("\n" + "-" * 40)
    print("  QUERY TYPE DISTRIBUTION")
    print("-" * 40)
    for qtype, info in report["query_type_distribution"].items():
        bar = "#" * int(info["percent"] / 2)
        print(f"  {qtype:<8} {info['count']:>6}  ({info['percent']:>5.1f}%)  {bar}")

    # Top queried domains
    print("\n" + "-" * 40)
    print("  TOP QUERIED DOMAINS")
    print("-" * 40)
    for entry in report["top_queried_domains"]:
        name = entry["domain"]
        if len(name) > 45:
            name = name[:42] + "..."
        print(f"  {name:<48} {entry['count']:>6}")

    # Top clients
    print("\n" + "-" * 40)
    print("  TOP CLIENTS BY QUERY VOLUME")
    print("-" * 40)
    for entry in report["top_clients"]:
        print(f"  {entry['client']:<18} {entry['queries']:>6} queries")

    # Findings
    findings = report["findings"]
    print("\n" + "=" * 72)
    print(f"  FINDINGS ({len(findings)} suspicious patterns detected)")
    print("=" * 72)

    if not findings:
        print("  No suspicious patterns detected.")
    else:
        for i, f in enumerate(findings, 1):
            severity_marker = {
                "CRITICAL": "[!!!]",
                "HIGH":     "[!! ]",
                "MEDIUM":   "[!  ]",
                "LOW":      "[.  ]",
                "INFO":     "[i  ]",
            }.get(f["severity"], "[?  ]")

            print(f"\n  {severity_marker} Finding #{i}: {f['detection_type']}")
            print(f"         Severity: {f['severity']}")
            print(f"         Domain:   {f['domain']}")
            if "client_ips" in f:
                print(f"         Clients:  {', '.join(f['client_ips'])}")
            print(f"         Reason:   {f['reason']}")
            if "mitre_attack" in f:
                print(f"         MITRE:    {f['mitre_attack']}")

    print("\n" + "=" * 72)


# ---------------------------------------------------------------------------
# Demo data generation
# ---------------------------------------------------------------------------

def generate_demo_log(filepath):
    """Generate a sample DNS query log with both normal and suspicious entries."""
    import random
    import string

    lines = []
    base_ts = datetime.datetime(2026, 3, 6, 14, 0, 0)

    normal_domains = [
        "www.google.com", "mail.google.com", "dns.google.com",
        "www.microsoft.com", "login.microsoftonline.com",
        "outlook.office365.com", "www.github.com", "api.github.com",
        "cdn.jsdelivr.net", "fonts.googleapis.com",
        "ocsp.digicert.com", "crl.pki.goog",
        "connectivity-check.ubuntu.com", "ntp.ubuntu.com",
        "updates.example.com", "mail.example.com",
        "intranet.example.com", "wiki.example.com",
    ]

    client_ips = [
        "10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53",
        "10.0.0.75", "10.0.0.100", "10.0.0.101",
    ]

    # Normal traffic (bulk)
    for i in range(200):
        ts = base_ts + datetime.timedelta(seconds=random.randint(0, 3600))
        client = random.choice(client_ips)
        domain = random.choice(normal_domains)
        qtype = random.choice(["A", "A", "A", "AAAA", "CNAME", "MX"])
        lines.append(f"{ts.isoformat()}Z {client} {domain} {qtype}")

    # High-frequency domain (beaconing indicator) -- same client hammering one domain
    beacon_domain = "update-check.198-51-100-99.example.net"
    for i in range(80):
        ts = base_ts + datetime.timedelta(seconds=i * 45)  # every 45 seconds
        lines.append(f"{ts.isoformat()}Z 10.0.0.75 {beacon_domain} A")

    # DNS tunneling -- long subdomain labels with encoded data
    tunnel_base = "tun.data-exfil.example.net"
    for i in range(15):
        # Simulate base64-like encoded data in subdomain
        encoded = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(30, 50)))
        domain = f"{encoded}.{tunnel_base}"
        ts = base_ts + datetime.timedelta(seconds=random.randint(0, 3600))
        lines.append(f"{ts.isoformat()}Z 10.0.0.75 {domain} TXT")

    # DGA domains -- algorithmically generated hostnames
    dga_domains = []
    for _ in range(20):
        length = random.randint(10, 18)
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        tld = random.choice(["com", "net", "org", "top", "xyz"])
        dga_domains.append(f"{label}.{tld}")

    for domain in dga_domains:
        ts = base_ts + datetime.timedelta(seconds=random.randint(0, 3600))
        client = "10.0.0.100"  # Single compromised host
        lines.append(f"{ts.isoformat()}Z {client} {domain} A")

    # Suspicious TLD queries
    bad_tld_domains = [
        "free-download.tk", "secure-login.ml", "update-system.ga",
        "my-account-verify.cf", "prize-winner.gq",
    ]
    for domain in bad_tld_domains:
        ts = base_ts + datetime.timedelta(seconds=random.randint(0, 3600))
        client = random.choice(["10.0.0.51", "10.0.0.52"])
        lines.append(f"{ts.isoformat()}Z {client} {domain} A")

    # Deep subdomain nesting
    deep_domain = "a.b.c.d.e.f.g.deep-nested.evil-c2.example.net"
    for i in range(5):
        ts = base_ts + datetime.timedelta(seconds=random.randint(0, 3600))
        lines.append(f"{ts.isoformat()}Z 10.0.0.75 {deep_domain} A")

    # Shuffle to simulate realistic log ordering (mostly chronological with some out-of-order)
    random.shuffle(lines)

    with open(filepath, "w") as f:
        f.write("# DNS Query Log - Generated for analysis demo\n")
        f.write(f"# Generated: {datetime.datetime.now().isoformat()}\n")
        f.write("# Format: timestamp client_ip domain query_type\n")
        for line in lines:
            f.write(line + "\n")

    print(f"[+] Demo DNS log written to: {filepath}")
    print(f"    Entries: {len(lines)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DNS query log analyzer for detecting tunneling, DGA, and abuse.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --logfile /var/log/dns/query.log\n"
            "  %(prog)s --logfile queries.log --entropy-threshold 3.8\n"
            "  %(prog)s --logfile queries.log --json dns_report.json\n"
            "  %(prog)s --demo\n"
            "\n"
            "Supported log formats:\n"
            "  - BIND query log format\n"
            "  - Dnsmasq log format\n"
            "  - Simple: timestamp source_ip domain query_type\n"
            "  - Plain list: one domain per line\n"
        ),
    )
    parser.add_argument(
        "--logfile", metavar="FILE",
        help="Path to the DNS query log file.",
    )
    parser.add_argument(
        "--entropy-threshold", type=float, default=DEFAULT_ENTROPY_THRESHOLD,
        help=f"Shannon entropy threshold for DGA detection (default: {DEFAULT_ENTROPY_THRESHOLD}).",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="Write the report as JSON to the specified file.",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Generate a synthetic DNS log and analyze it.",
    )

    args = parser.parse_args()

    if args.demo:
        demo_path = os.path.join(os.path.dirname(__file__), "..", "captures", "demo_dns_queries.log")
        demo_path = os.path.abspath(demo_path)
        generate_demo_log(demo_path)
        args.logfile = demo_path

    if not args.logfile:
        parser.error("Provide --logfile FILE or use --demo to generate sample data.")

    if not os.path.isfile(args.logfile):
        print(f"[!] Error: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing DNS log: {args.logfile}")
    records = DNSLogParser.parse_file(args.logfile)

    if not records:
        print("[!] No DNS query records found. Check log format.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsed {len(records)} DNS query records. Running analysis...")

    analyzer = DNSAnalyzer(records, entropy_threshold=args.entropy_threshold)
    report = analyzer.analyze()

    print_report(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] JSON report written to: {args.json}")


if __name__ == "__main__":
    main()
