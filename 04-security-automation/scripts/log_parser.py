#!/usr/bin/env python3
"""
log_parser.py - Multi-Format Security Log Parser

Parses auth.log, Apache/Nginx access logs, and syslog entries to detect
suspicious activity patterns relevant to SOC analysis.

Detections:
    - Failed login attempts (SSH brute-force indicators)
    - Successful logins from unusual source IPs
    - Privilege escalation via sudo
    - Error rate spikes across time windows
    - Top talkers by source IP

Author: Security Automation Toolkit
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Regex patterns for supported log formats
# ---------------------------------------------------------------------------

# auth.log: "Mar  5 14:22:01 server sshd[12345]: Failed password for ..."
AUTH_FAILED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+"
    r"from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
)

AUTH_ACCEPTED_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUDO_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:\s+"
    r"(?P<result>.*?)\s*;\s+COMMAND=(?P<command>.+)"
)

# Apache / Nginx combined log format
# 192.168.1.10 - - [05/Mar/2026:14:22:01 +0000] "GET /path HTTP/1.1" 200 1234
ACCESS_LOG_RE = re.compile(
    r"^(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\d+)"
)

# Generic syslog
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)"
)


# ---------------------------------------------------------------------------
# Timestamp parsing helpers
# ---------------------------------------------------------------------------

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_timestamp(ts_str, reference_year=None):
    """Parse 'Mar  5 14:22:01' style timestamps.

    syslog timestamps lack a year, so we default to the current year
    or a caller-supplied reference year.
    """
    if reference_year is None:
        reference_year = datetime.now().year
    parts = ts_str.split()
    month = MONTH_MAP.get(parts[0], 1)
    day = int(parts[1])
    time_parts = parts[2].split(":")
    return datetime(
        reference_year, month, day,
        int(time_parts[0]), int(time_parts[1]), int(time_parts[2]),
    )


def parse_access_log_timestamp(ts_str):
    """Parse '05/Mar/2026:14:22:01 +0000' style timestamps."""
    try:
        return datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Core analysis engine
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """Aggregate and analyze parsed log events."""

    def __init__(self, start_time=None, end_time=None):
        self.start_time = start_time
        self.end_time = end_time

        # Counters
        self.failed_logins = []          # list of dicts
        self.accepted_logins = []
        self.sudo_events = []
        self.access_entries = []
        self.syslog_entries = []

        self.failed_by_user = Counter()
        self.failed_by_ip = Counter()
        self.accepted_by_ip = Counter()
        self.status_codes = Counter()
        self.errors_by_hour = Counter()
        self.all_src_ips = Counter()
        self.total_lines = 0
        self.unparsed_lines = 0

    # ---- filtering --------------------------------------------------------

    def _in_range(self, ts):
        """Return True if timestamp falls within the configured window."""
        if ts is None:
            return True
        if self.start_time and ts < self.start_time:
            return False
        if self.end_time and ts > self.end_time:
            return False
        return True

    # ---- ingestion --------------------------------------------------------

    def ingest_line(self, line):
        """Try every known pattern against a single log line."""
        self.total_lines += 1
        line = line.strip()
        if not line:
            return

        # Auth failed
        m = AUTH_FAILED_RE.match(line)
        if m:
            ts = parse_syslog_timestamp(m.group("timestamp"))
            if not self._in_range(ts):
                return
            rec = {
                "timestamp": ts.isoformat(),
                "host": m.group("host"),
                "user": m.group("user"),
                "src_ip": m.group("src_ip"),
                "event": "failed_login",
            }
            self.failed_logins.append(rec)
            self.failed_by_user[rec["user"]] += 1
            self.failed_by_ip[rec["src_ip"]] += 1
            self.all_src_ips[rec["src_ip"]] += 1
            return

        # Auth accepted
        m = AUTH_ACCEPTED_RE.match(line)
        if m:
            ts = parse_syslog_timestamp(m.group("timestamp"))
            if not self._in_range(ts):
                return
            rec = {
                "timestamp": ts.isoformat(),
                "host": m.group("host"),
                "user": m.group("user"),
                "src_ip": m.group("src_ip"),
                "event": "accepted_login",
            }
            self.accepted_logins.append(rec)
            self.accepted_by_ip[rec["src_ip"]] += 1
            self.all_src_ips[rec["src_ip"]] += 1
            return

        # Sudo
        m = SUDO_RE.match(line)
        if m:
            ts = parse_syslog_timestamp(m.group("timestamp"))
            if not self._in_range(ts):
                return
            rec = {
                "timestamp": ts.isoformat(),
                "host": m.group("host"),
                "user": m.group("user"),
                "result": m.group("result").strip(),
                "command": m.group("command").strip(),
                "event": "sudo",
            }
            self.sudo_events.append(rec)
            return

        # Access log
        m = ACCESS_LOG_RE.match(line)
        if m:
            ts = parse_access_log_timestamp(m.group("timestamp"))
            if not self._in_range(ts):
                return
            status = int(m.group("status"))
            rec = {
                "timestamp": ts.isoformat() if ts else "unknown",
                "src_ip": m.group("src_ip"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": status,
                "size": int(m.group("size")),
                "event": "http_request",
            }
            self.access_entries.append(rec)
            self.status_codes[status] += 1
            self.all_src_ips[rec["src_ip"]] += 1
            if status >= 400:
                hour_key = ts.strftime("%Y-%m-%d %H:00") if ts else "unknown"
                self.errors_by_hour[hour_key] += 1
            return

        # Generic syslog (catch-all)
        m = SYSLOG_RE.match(line)
        if m:
            ts = parse_syslog_timestamp(m.group("timestamp"))
            if not self._in_range(ts):
                return
            rec = {
                "timestamp": ts.isoformat(),
                "host": m.group("host"),
                "service": m.group("service"),
                "message": m.group("message"),
                "event": "syslog",
            }
            self.syslog_entries.append(rec)
            return

        self.unparsed_lines += 1

    def ingest_file(self, filepath):
        """Read and ingest every line of a log file."""
        try:
            with open(filepath, "r", errors="replace") as fh:
                for line in fh:
                    self.ingest_line(line)
        except FileNotFoundError:
            print(f"[!] File not found: {filepath}", file=sys.stderr)
        except PermissionError:
            print(f"[!] Permission denied: {filepath}", file=sys.stderr)

    # ---- reporting --------------------------------------------------------

    def _detect_brute_force(self, threshold=5):
        """IPs with failed login count >= threshold."""
        return {ip: cnt for ip, cnt in self.failed_by_ip.items() if cnt >= threshold}

    def _detect_error_spikes(self, threshold=10):
        """Hours where HTTP error count exceeds threshold."""
        return {hour: cnt for hour, cnt in self.errors_by_hour.items() if cnt >= threshold}

    def build_report(self):
        """Build a structured report dict."""
        brute_force_ips = self._detect_brute_force()
        error_spikes = self._detect_error_spikes()

        report = {
            "summary": {
                "total_lines_processed": self.total_lines,
                "unparsed_lines": self.unparsed_lines,
                "failed_logins": len(self.failed_logins),
                "accepted_logins": len(self.accepted_logins),
                "sudo_events": len(self.sudo_events),
                "http_requests": len(self.access_entries),
                "syslog_entries": len(self.syslog_entries),
            },
            "top_source_ips": dict(self.all_src_ips.most_common(15)),
            "failed_logins_by_user": dict(self.failed_by_user.most_common(15)),
            "failed_logins_by_ip": dict(self.failed_by_ip.most_common(15)),
            "accepted_logins_by_ip": dict(self.accepted_by_ip.most_common(15)),
            "http_status_distribution": {str(k): v for k, v in sorted(self.status_codes.items())},
            "alerts": {
                "potential_brute_force_ips": brute_force_ips,
                "error_spikes_by_hour": error_spikes,
                "sudo_commands": [
                    {"user": e["user"], "command": e["command"], "timestamp": e["timestamp"]}
                    for e in self.sudo_events
                ],
            },
            "timeline": {
                "failed_logins": self.failed_logins,
                "accepted_logins": self.accepted_logins,
            },
        }
        return report

    def print_report(self):
        """Pretty-print the analysis report to stdout."""
        r = self.build_report()
        width = 72

        print("=" * width)
        print("  SECURITY LOG ANALYSIS REPORT".center(width))
        print("=" * width)

        # Summary
        s = r["summary"]
        print(f"\n{'--- Summary ':->{ width}}")
        print(f"  Total lines processed : {s['total_lines_processed']}")
        print(f"  Unparsed lines        : {s['unparsed_lines']}")
        print(f"  Failed SSH logins     : {s['failed_logins']}")
        print(f"  Accepted SSH logins   : {s['accepted_logins']}")
        print(f"  Sudo events           : {s['sudo_events']}")
        print(f"  HTTP requests         : {s['http_requests']}")
        print(f"  Syslog entries        : {s['syslog_entries']}")

        # Top source IPs
        if r["top_source_ips"]:
            print(f"\n{'--- Top Source IPs ':->{ width}}")
            for ip, count in r["top_source_ips"].items():
                print(f"  {ip:<20s} {count:>6d} events")

        # Failed logins by user
        if r["failed_logins_by_user"]:
            print(f"\n{'--- Failed Logins by User ':->{ width}}")
            for user, count in r["failed_logins_by_user"].items():
                print(f"  {user:<24s} {count:>6d} failures")

        # Failed logins by IP
        if r["failed_logins_by_ip"]:
            print(f"\n{'--- Failed Logins by Source IP ':->{ width}}")
            for ip, count in r["failed_logins_by_ip"].items():
                marker = " ** BRUTE-FORCE CANDIDATE" if count >= 5 else ""
                print(f"  {ip:<20s} {count:>6d} failures{marker}")

        # Accepted logins
        if r["accepted_logins_by_ip"]:
            print(f"\n{'--- Accepted Logins by Source IP ':->{ width}}")
            for ip, count in r["accepted_logins_by_ip"].items():
                print(f"  {ip:<20s} {count:>6d} logins")

        # HTTP status codes
        if r["http_status_distribution"]:
            print(f"\n{'--- HTTP Status Code Distribution ':->{ width}}")
            for code, count in r["http_status_distribution"].items():
                print(f"  HTTP {code}  : {count:>6d}")

        # Alerts
        alerts = r["alerts"]

        if alerts["potential_brute_force_ips"]:
            print(f"\n{'--- ALERT: Potential Brute-Force Sources ':->{ width}}")
            for ip, count in alerts["potential_brute_force_ips"].items():
                print(f"  [!] {ip} -- {count} failed attempts")

        if alerts["error_spikes_by_hour"]:
            print(f"\n{'--- ALERT: HTTP Error Spikes ':->{ width}}")
            for hour, count in alerts["error_spikes_by_hour"].items():
                print(f"  [!] {hour} -- {count} errors")

        if alerts["sudo_commands"]:
            print(f"\n{'--- Privilege Escalation (sudo) ':->{ width}}")
            for ev in alerts["sudo_commands"]:
                print(f"  [{ev['timestamp']}] {ev['user']} -> {ev['command']}")

        print("\n" + "=" * width)
        print("  END OF REPORT".center(width))
        print("=" * width)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_datetime(value):
    """Parse user-supplied datetime string."""
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Invalid datetime: '{value}'. Use YYYY-MM-DD [HH:MM[:SS]]"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Parser -- Analyze auth.log, access logs, and syslog "
                    "for suspicious activity patterns.",
        epilog="Examples:\n"
               "  %(prog)s /var/log/auth.log\n"
               "  %(prog)s /var/log/auth.log /var/log/apache2/access.log --json report.json\n"
               "  %(prog)s /var/log/auth.log --start '2026-03-01' --end '2026-03-05'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "logfiles", nargs="+", metavar="LOGFILE",
        help="One or more log files to analyze",
    )
    parser.add_argument(
        "--start", type=parse_datetime, default=None,
        help="Start of time window (YYYY-MM-DD [HH:MM[:SS]])",
    )
    parser.add_argument(
        "--end", type=parse_datetime, default=None,
        help="End of time window (YYYY-MM-DD [HH:MM[:SS]])",
    )
    parser.add_argument(
        "--json", metavar="OUTFILE", default=None,
        help="Write structured JSON report to OUTFILE",
    )
    parser.add_argument(
        "--brute-threshold", type=int, default=5,
        help="Number of failures to flag as brute-force (default: 5)",
    )
    args = parser.parse_args()

    analyzer = LogAnalyzer(start_time=args.start, end_time=args.end)

    for path in args.logfiles:
        analyzer.ingest_file(path)

    analyzer.print_report()

    if args.json:
        report = analyzer.build_report()
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"\n[+] JSON report written to {args.json}")
        except OSError as exc:
            print(f"[!] Could not write JSON report: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
