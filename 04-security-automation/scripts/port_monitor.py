#!/usr/bin/env python3
"""
port_monitor.py - Network Port State Change Monitor

Performs periodic port scans against a target host and alerts on state
changes -- new open ports that were previously closed or ports that have
gone offline since the last check.

Features:
    - Baseline scan with persistent storage (JSON)
    - Configurable port range and scan interval
    - Timestamped change logging to file and stdout
    - Optional continuous monitoring mode

Author: Security Automation Toolkit
"""

import argparse
import datetime
import json
import os
import socket
import sys
import time

# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9200: "Elasticsearch",
    27017: "MongoDB",
}


def scan_port(host, port, timeout=1.0):
    """Return True if port is open on host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except (socket.error, OSError):
        return False


def scan_ports(host, ports, timeout=1.0, verbose=False):
    """Scan a list of ports and return set of open ports."""
    open_ports = set()
    total = len(ports)
    for i, port in enumerate(ports, 1):
        if verbose and i % 100 == 0:
            print(f"  Scanning... {i}/{total} ports checked", end="\r")
        if scan_port(host, port, timeout):
            open_ports.add(port)
    if verbose:
        print(f"  Scanning... {total}/{total} ports checked -- done")
    return open_ports


def port_label(port):
    """Return 'port/service' string."""
    svc = COMMON_PORTS.get(port, "unknown")
    return f"{port}/{svc}"


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def save_baseline(filepath, host, open_ports):
    """Persist a baseline scan to JSON."""
    data = {
        "host": host,
        "timestamp": datetime.datetime.now().isoformat(),
        "open_ports": sorted(open_ports),
    }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    return data


def load_baseline(filepath):
    """Load a previously saved baseline."""
    try:
        with open(filepath, "r") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        print(f"[!] Corrupt baseline file: {filepath}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Change detection & logging
# ---------------------------------------------------------------------------

def detect_changes(baseline_ports, current_ports):
    """Compare two sets of ports and return new / closed sets."""
    baseline_set = set(baseline_ports)
    current_set = set(current_ports)
    new_ports = current_set - baseline_set
    closed_ports = baseline_set - current_set
    return new_ports, closed_ports


def log_event(message, logfile=None):
    """Print a timestamped message and optionally append to a log file."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line)
    if logfile:
        try:
            with open(logfile, "a") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_port_range(value):
    """Parse '1-1024' or '22,80,443' into a list of ints."""
    ports = []
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > 65535:
                raise argparse.ArgumentTypeError(f"Invalid range: {part}")
            ports.extend(range(lo, hi + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise argparse.ArgumentTypeError(f"Invalid port: {p}")
            ports.append(p)
    return ports


def main():
    parser = argparse.ArgumentParser(
        description="Monitor a target host for port state changes. Creates a "
                    "baseline on the first run and alerts on deviations.",
        epilog="Examples:\n"
               "  %(prog)s --target 192.168.1.1 --ports 1-1024\n"
               "  %(prog)s --target 10.0.0.5 --ports 22,80,443,3306,8080\n"
               "  %(prog)s --target 10.0.0.5 --ports 1-1024 --monitor --interval 300\n"
               "  %(prog)s --target 10.0.0.5 --baseline baseline.json --logfile changes.log\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target", required=True,
        help="Target host (IP address or hostname)",
    )
    parser.add_argument(
        "--ports", type=parse_port_range, default=list(range(1, 1025)),
        help="Port range to scan, e.g. '1-1024' or '22,80,443' (default: 1-1024)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Socket timeout per port in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--baseline", default="port_baseline.json",
        help="Path to baseline JSON file (default: port_baseline.json)",
    )
    parser.add_argument(
        "--logfile", default=None,
        help="Path to change log file (default: stdout only)",
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="Run continuously and re-scan at --interval seconds",
    )
    parser.add_argument(
        "--interval", type=int, default=300,
        help="Seconds between scans in monitor mode (default: 300)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show scan progress",
    )
    args = parser.parse_args()

    target = args.target
    ports = args.ports
    width = 60

    # Resolve hostname
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Cannot resolve hostname: {target}", file=sys.stderr)
        sys.exit(1)

    print("=" * width)
    print("  PORT STATE MONITOR".center(width))
    print("=" * width)
    print(f"  Target   : {target} ({resolved_ip})")
    print(f"  Ports    : {len(ports)} ports")
    print(f"  Timeout  : {args.timeout}s per port")
    print(f"  Baseline : {args.baseline}")
    if args.logfile:
        print(f"  Log file : {args.logfile}")
    print()

    # Load or create baseline
    existing = load_baseline(args.baseline)

    if existing is None:
        log_event(f"No baseline found. Performing initial scan of {target}...", args.logfile)
        open_ports = scan_ports(target, ports, args.timeout, args.verbose)
        baseline_data = save_baseline(args.baseline, target, open_ports)
        log_event(f"Baseline created: {len(open_ports)} open port(s)", args.logfile)
        if open_ports:
            print(f"\n  {'--- Baseline Open Ports ':->{width}}")
            for p in sorted(open_ports):
                print(f"    {port_label(p)}")
        print()
        if not args.monitor:
            print("[+] Baseline saved. Run again to detect changes.")
            return
    else:
        log_event(f"Loaded baseline from {args.baseline} "
                  f"(taken {existing['timestamp']}, {len(existing['open_ports'])} open ports)",
                  args.logfile)

    # Scan loop
    iteration = 0
    try:
        while True:
            iteration += 1
            log_event(f"Scan #{iteration} starting against {target}...", args.logfile)
            current_open = scan_ports(target, ports, args.timeout, args.verbose)

            baseline_ports = existing["open_ports"] if existing else []
            new_ports, closed_ports = detect_changes(baseline_ports, current_open)

            if new_ports or closed_ports:
                log_event("*** CHANGES DETECTED ***", args.logfile)

                if new_ports:
                    for p in sorted(new_ports):
                        log_event(f"  [NEW OPEN]   {port_label(p)}", args.logfile)

                if closed_ports:
                    for p in sorted(closed_ports):
                        log_event(f"  [NOW CLOSED] {port_label(p)}", args.logfile)

                # Update baseline to current state
                existing = save_baseline(args.baseline, target, current_open)
                log_event("Baseline updated to current state.", args.logfile)
            else:
                log_event(f"No changes detected. {len(current_open)} open port(s).", args.logfile)

            if not args.monitor:
                break

            log_event(f"Next scan in {args.interval} seconds...", args.logfile)
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")
        sys.exit(0)

    print("\n" + "=" * width)


if __name__ == "__main__":
    main()
