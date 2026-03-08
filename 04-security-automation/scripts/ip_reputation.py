#!/usr/bin/env python3
"""
ip_reputation.py - IP Address Reputation Checker

Queries AbuseIPDB for abuse reports on IP addresses. Falls back to local
threat feed files when no API key is available.

Features:
    - Single IP, comma-separated list, or file input
    - AbuseIPDB v2 API integration
    - Offline fallback against local threat intelligence feeds
    - CSV and JSON output modes
    - Bulk lookup support with rate-limit awareness

Author: Security Automation Toolkit
"""

import argparse
import csv
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_ENV_KEY = "ABUSEIPDB_API_KEY"

# IANA reserved / private ranges (for quick pre-filtering)
PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
)


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

def is_valid_ipv4(ip):
    """Basic IPv4 validation."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            n = int(p)
            if n < 0 or n > 255:
                return False
        except ValueError:
            return False
    return True


def is_private_ip(ip):
    """Check if IP belongs to a private/reserved range."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# AbuseIPDB lookup
# ---------------------------------------------------------------------------

def check_abuseipdb(ip, api_key, max_age_days=90):
    """Query AbuseIPDB v2 API for an IP address.

    Returns a dict with reputation details or error info.
    """
    params = urllib.request.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
        "verbose": "",
    })
    url = f"{ABUSEIPDB_API_URL}?{params}"

    req = urllib.request.Request(url, method="GET")
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return {"ip": ip, "error": "Rate limit exceeded", "success": False}
        if exc.code == 422:
            return {"ip": ip, "error": "Invalid IP address", "success": False}
        return {"ip": ip, "error": f"HTTP {exc.code}: {exc.reason}", "success": False}
    except urllib.error.URLError as exc:
        return {"ip": ip, "error": f"Connection error: {exc.reason}", "success": False}

    data = body.get("data", {})

    return {
        "ip": ip,
        "success": True,
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "country_code": data.get("countryCode", "N/A"),
        "isp": data.get("isp", "N/A"),
        "domain": data.get("domain", "N/A"),
        "total_reports": data.get("totalReports", 0),
        "num_distinct_users": data.get("numDistinctUsers", 0),
        "last_reported_at": data.get("lastReportedAt", "never"),
        "is_whitelisted": data.get("isWhitelisted", False),
        "usage_type": data.get("usageType", "N/A"),
        "is_tor": data.get("isTor", False),
        "is_public": data.get("isPublic", True),
    }


# ---------------------------------------------------------------------------
# Local threat feed lookup
# ---------------------------------------------------------------------------

def load_threat_feed(filepath):
    """Load a local threat feed file.

    Supports plain text (one IP per line) and CSV with an 'ip' column.
    Lines starting with '#' are comments. Additional columns are stored
    as metadata.
    """
    feed = {}
    try:
        with open(filepath, "r") as fh:
            first_line = fh.readline().strip()
            fh.seek(0)

            # Detect CSV with headers
            if "," in first_line and not first_line.startswith("#"):
                reader = csv.DictReader(fh)
                ip_col = None
                for col in reader.fieldnames or []:
                    if col.strip().lower() in ("ip", "ip_address", "indicator", "ioc"):
                        ip_col = col
                        break
                if ip_col is None:
                    # Fall back to first column
                    ip_col = (reader.fieldnames or [""])[0]
                for row in reader:
                    ip = row.get(ip_col, "").strip()
                    if ip and is_valid_ipv4(ip):
                        feed[ip] = {k: v for k, v in row.items() if k != ip_col}
            else:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(",", 1)
                    ip = parts[0].strip()
                    meta = parts[1].strip() if len(parts) > 1 else ""
                    if is_valid_ipv4(ip):
                        feed[ip] = {"label": meta} if meta else {}
    except FileNotFoundError:
        print(f"[!] Threat feed not found: {filepath}", file=sys.stderr)
    except PermissionError:
        print(f"[!] Permission denied: {filepath}", file=sys.stderr)
    return feed


def check_local_feeds(ip, feeds):
    """Check an IP against all loaded local threat feeds.

    Returns a result dict.
    """
    for feed_name, feed_data in feeds.items():
        if ip in feed_data:
            meta = feed_data[ip]
            return {
                "ip": ip,
                "success": True,
                "source": f"local:{feed_name}",
                "found": True,
                "metadata": meta,
                "verdict": "LISTED IN THREAT FEED",
            }
    return {
        "ip": ip,
        "success": True,
        "source": "local",
        "found": False,
        "verdict": "NOT FOUND IN LOCAL FEEDS",
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_result(result, index=None):
    """Pretty-print a single IP result."""
    prefix = f"[{index}] " if index is not None else ""

    if not result.get("success"):
        print(f"  {prefix}{result['ip']}  ->  ERROR: {result.get('error', 'unknown')}")
        return

    ip = result["ip"]

    # AbuseIPDB-style result
    if "abuse_confidence_score" in result:
        score = result["abuse_confidence_score"]
        if score >= 75:
            threat_level = "HIGH"
        elif score >= 25:
            threat_level = "MEDIUM"
        elif score > 0:
            threat_level = "LOW"
        else:
            threat_level = "NONE"

        print(f"  {prefix}{ip}")
        print(f"    Abuse Score    : {score}% ({threat_level})")
        print(f"    Country        : {result['country_code']}")
        print(f"    ISP            : {result['isp']}")
        print(f"    Domain         : {result['domain']}")
        print(f"    Total Reports  : {result['total_reports']}")
        print(f"    Reporters      : {result['num_distinct_users']}")
        print(f"    Last Reported  : {result['last_reported_at']}")
        print(f"    Usage Type     : {result['usage_type']}")
        if result.get("is_tor"):
            print(f"    Tor Exit Node  : YES")
        print()
        return

    # Local feed result
    if result.get("found"):
        print(f"  {prefix}{ip}  ->  {result['verdict']}")
        if result.get("metadata"):
            for k, v in result["metadata"].items():
                print(f"    {k}: {v}")
    else:
        print(f"  {prefix}{ip}  ->  {result['verdict']}")
    print()


def write_csv(results, filepath):
    """Write results to CSV."""
    if not results:
        return

    # Collect all keys across results
    all_keys = []
    for r in results:
        for k in r.keys():
            if k not in all_keys:
                all_keys.append(k)

    try:
        with open(filepath, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=all_keys, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                flat = {}
                for k, v in r.items():
                    if isinstance(v, dict):
                        flat[k] = json.dumps(v)
                    else:
                        flat[k] = v
                writer.writerow(flat)
        print(f"[+] CSV results written to {filepath}")
    except OSError as exc:
        print(f"[!] Could not write CSV: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# IP collection helpers
# ---------------------------------------------------------------------------

def collect_ips(args):
    """Gather all IPs from CLI arguments and files."""
    ips = []

    # From positional args
    for item in args.ips or []:
        for part in item.split(","):
            part = part.strip()
            if part:
                ips.append(part)

    # From file
    if args.file:
        try:
            with open(args.file, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        for part in line.split(","):
                            part = part.strip()
                            if part:
                                ips.append(part)
        except FileNotFoundError:
            print(f"[!] IP list file not found: {args.file}", file=sys.stderr)
        except PermissionError:
            print(f"[!] Permission denied: {args.file}", file=sys.stderr)

    return ips


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Check IP addresses against AbuseIPDB or local threat feeds "
                    "for reputation and abuse history.",
        epilog="Examples:\n"
               "  %(prog)s 185.220.101.1\n"
               "  %(prog)s 8.8.8.8 1.1.1.1 --csv results.csv\n"
               "  %(prog)s --file suspicious_ips.txt\n"
               "  %(prog)s --file ips.txt --feed threat_feed.csv --feed blocklist.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "ips", nargs="*", metavar="IP",
        help="IP address(es) to check (comma-separated ok)",
    )
    parser.add_argument(
        "--file", "-f", metavar="FILE",
        help="File containing IP addresses (one per line)",
    )
    parser.add_argument(
        "--feed", action="append", metavar="FILE",
        help="Local threat feed file(s) for offline lookup (repeatable)",
    )
    parser.add_argument(
        "--max-age", type=int, default=90,
        help="AbuseIPDB: max age of reports in days (default: 90)",
    )
    parser.add_argument(
        "--csv", metavar="OUTFILE",
        help="Write results to CSV file",
    )
    parser.add_argument(
        "--json", metavar="OUTFILE",
        help="Write results to JSON file",
    )
    parser.add_argument(
        "--delay", type=float, default=1.2,
        help="Delay between API calls in seconds for rate limiting (default: 1.2)",
    )
    args = parser.parse_args()

    ips = collect_ips(args)
    if not ips:
        parser.error("No IP addresses provided. Use positional args or --file.")

    api_key = os.environ.get(ABUSEIPDB_ENV_KEY, "")
    local_feeds = {}
    if args.feed:
        for fp in args.feed:
            feed_name = os.path.basename(fp)
            local_feeds[feed_name] = load_threat_feed(fp)

    use_api = bool(api_key)
    use_local = bool(local_feeds)

    width = 60
    print("=" * width)
    print("  IP REPUTATION CHECKER".center(width))
    print("=" * width)

    if use_api:
        print("  Mode: AbuseIPDB API (online)")
    elif use_local:
        print("  Mode: Local threat feeds (offline)")
        for name in local_feeds:
            print(f"    Feed: {name} ({len(local_feeds[name])} entries)")
    else:
        print("  [!] No AbuseIPDB API key and no local feeds provided.")
        print(f"      Set {ABUSEIPDB_ENV_KEY} env var or use --feed <file>")
        print("      Proceeding with validation only.\n")

    print(f"  IPs to check: {len(ips)}\n")

    results = []

    for i, ip in enumerate(ips, 1):
        # Validate
        if not is_valid_ipv4(ip):
            print(f"  [{i}] {ip}  ->  INVALID IPv4 ADDRESS")
            results.append({"ip": ip, "success": False, "error": "Invalid IPv4"})
            continue

        if is_private_ip(ip):
            print(f"  [{i}] {ip}  ->  PRIVATE/RESERVED (skipped)")
            results.append({"ip": ip, "success": True, "verdict": "PRIVATE/RESERVED"})
            continue

        # Check
        if use_api:
            result = check_abuseipdb(ip, api_key, args.max_age)
            print_result(result, index=i)
            results.append(result)
            # Rate limiting
            if i < len(ips):
                time.sleep(args.delay)
        elif use_local:
            result = check_local_feeds(ip, local_feeds)
            print_result(result, index=i)
            results.append(result)
        else:
            results.append({"ip": ip, "success": True, "verdict": "NO LOOKUP SOURCE"})
            print(f"  [{i}] {ip}  ->  NO LOOKUP SOURCE CONFIGURED")

    # Write outputs
    if args.csv:
        write_csv(results, args.csv)
    if args.json:
        try:
            with open(args.json, "w") as fh:
                json.dump(results, fh, indent=2)
            print(f"[+] JSON results written to {args.json}")
        except OSError as exc:
            print(f"[!] Could not write JSON: {exc}", file=sys.stderr)

    # Summary
    print(f"\n{'--- Summary ':->{ width}}")
    print(f"  Total IPs checked : {len(results)}")
    if use_api:
        high = sum(1 for r in results if r.get("abuse_confidence_score", 0) >= 75)
        med = sum(1 for r in results if 25 <= r.get("abuse_confidence_score", 0) < 75)
        low = sum(1 for r in results if 0 < r.get("abuse_confidence_score", 0) < 25)
        clean = sum(1 for r in results if r.get("abuse_confidence_score", 0) == 0 and r.get("success"))
        print(f"  High threat       : {high}")
        print(f"  Medium threat     : {med}")
        print(f"  Low threat        : {low}")
        print(f"  Clean             : {clean}")
    elif use_local:
        found = sum(1 for r in results if r.get("found"))
        print(f"  Found in feeds    : {found}")
        print(f"  Not found         : {len(results) - found}")

    print("=" * width)


if __name__ == "__main__":
    main()
