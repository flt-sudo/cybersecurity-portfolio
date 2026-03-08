#!/usr/bin/env python3
"""
hash_checker.py - File Hash Calculator & Reputation Checker

Computes MD5, SHA1, and SHA256 hashes for files and checks them against
VirusTotal's public API. Falls back to an offline known-bad hash list when
no API key is available.

Usage:
    # Compute hashes only
    hash_checker.py /path/to/file

    # Check computed hashes against VirusTotal
    VIRUSTOTAL_API_KEY=<key> hash_checker.py /path/to/file --check

    # Check a raw hash value
    hash_checker.py --hash <sha256value> --check

    # Use offline bad-hash list
    hash_checker.py /path/to/file --check --bad-hashes known_bad.txt

Author: Security Automation Toolkit
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
VT_ENV_KEY = "VIRUSTOTAL_API_KEY"
HASH_ALGORITHMS = ("md5", "sha1", "sha256")
READ_CHUNK = 65536  # 64 KiB


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

def compute_hashes(filepath):
    """Return a dict of {algorithm: hex_digest} for a file."""
    hashers = {alg: hashlib.new(alg) for alg in HASH_ALGORITHMS}
    try:
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                for h in hashers.values():
                    h.update(chunk)
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}", file=sys.stderr)
        return None
    except PermissionError:
        print(f"[!] Permission denied: {filepath}", file=sys.stderr)
        return None

    return {alg: h.hexdigest() for alg, h in hashers.items()}


def identify_hash_type(hash_str):
    """Guess hash algorithm from string length."""
    length_map = {32: "md5", 40: "sha1", 64: "sha256"}
    return length_map.get(len(hash_str))


# ---------------------------------------------------------------------------
# VirusTotal lookup
# ---------------------------------------------------------------------------

def check_virustotal(hash_value, api_key):
    """Query VirusTotal API v3 for a hash.

    Returns a dict with detection results or None on failure.
    """
    url = VT_API_URL.format(hash=hash_value)
    req = urllib.request.Request(url, method="GET")
    req.add_header("x-apikey", api_key)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"found": False, "hash": hash_value, "message": "Not found in VirusTotal database"}
        if exc.code == 429:
            return {"found": False, "hash": hash_value, "message": "API rate limit exceeded -- try again later"}
        return {"found": False, "hash": hash_value, "message": f"HTTP {exc.code}: {exc.reason}"}
    except urllib.error.URLError as exc:
        return {"found": False, "hash": hash_value, "message": f"Connection error: {exc.reason}"}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    return {
        "found": True,
        "hash": hash_value,
        "file_name": attrs.get("meaningful_name", "unknown"),
        "file_type": attrs.get("type_description", "unknown"),
        "file_size": attrs.get("size", 0),
        "detection_ratio": f"{malicious}/{total}",
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "reputation": attrs.get("reputation", "N/A"),
        "last_analysis_date": attrs.get("last_analysis_date", "N/A"),
        "verdict": "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN"),
    }


# ---------------------------------------------------------------------------
# Offline known-bad hash checking
# ---------------------------------------------------------------------------

def load_bad_hashes(filepath):
    """Load a set of known-bad hashes from a text file (one per line).

    Lines starting with '#' are treated as comments. Each line may
    optionally contain a description after the hash separated by
    whitespace or comma.
    """
    hashes = {}
    try:
        with open(filepath, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.replace(",", " ").split(maxsplit=1)
                hash_val = parts[0].lower()
                label = parts[1] if len(parts) > 1 else "unknown-malware"
                hashes[hash_val] = label
    except FileNotFoundError:
        print(f"[!] Bad-hash list not found: {filepath}", file=sys.stderr)
    except PermissionError:
        print(f"[!] Permission denied: {filepath}", file=sys.stderr)
    return hashes


def check_offline(hash_values, bad_hash_db):
    """Check a list of hash values against the offline database."""
    results = []
    for h in hash_values:
        h_lower = h.lower()
        if h_lower in bad_hash_db:
            results.append({
                "hash": h,
                "match": True,
                "label": bad_hash_db[h_lower],
                "verdict": "KNOWN-BAD",
            })
        else:
            results.append({
                "hash": h,
                "match": False,
                "label": None,
                "verdict": "NOT IN LOCAL DB",
            })
    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_hashes(filepath, hashes):
    """Pretty-print computed hashes."""
    print(f"\n  File : {filepath}")
    print(f"  Size : {os.path.getsize(filepath):,} bytes")
    for alg in HASH_ALGORITHMS:
        print(f"  {alg.upper():<6s}: {hashes[alg]}")


def print_vt_result(result):
    """Pretty-print a VirusTotal lookup result."""
    if not result["found"]:
        print(f"\n  [VirusTotal] {result['message']}")
        return
    print(f"\n  {'--- VirusTotal Results ':->{60}}")
    print(f"  File Name       : {result['file_name']}")
    print(f"  File Type       : {result['file_type']}")
    print(f"  File Size       : {result['file_size']:,} bytes")
    print(f"  Detection Ratio : {result['detection_ratio']}")
    print(f"    Malicious     : {result['malicious']}")
    print(f"    Suspicious    : {result['suspicious']}")
    print(f"    Undetected    : {result['undetected']}")
    print(f"    Harmless      : {result['harmless']}")
    print(f"  Reputation      : {result['reputation']}")
    verdict = result["verdict"]
    if verdict == "MALICIOUS":
        print(f"  Verdict         : *** {verdict} ***")
    elif verdict == "SUSPICIOUS":
        print(f"  Verdict         : *   {verdict}   *")
    else:
        print(f"  Verdict         : {verdict}")


def print_offline_result(result):
    """Pretty-print an offline check result."""
    if result["match"]:
        print(f"  [MATCH] {result['hash']}  ->  {result['label']}  [{result['verdict']}]")
    else:
        print(f"  [-----] {result['hash']}  ->  {result['verdict']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Compute file hashes (MD5/SHA1/SHA256) and check against "
                    "VirusTotal or a local known-bad hash list.",
        epilog="Examples:\n"
               "  %(prog)s /path/to/suspicious_file\n"
               "  %(prog)s /path/to/file --check\n"
               "  %(prog)s --hash 44d88612fea8a8f36de82e1278abb02f --check\n"
               "  %(prog)s /path/to/file --check --bad-hashes known_bad.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files", nargs="*", metavar="FILE",
        help="File(s) to hash",
    )
    parser.add_argument(
        "--hash", dest="raw_hash", metavar="HASH",
        help="Check a raw hash value instead of computing from a file",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Check hashes against VirusTotal (requires VIRUSTOTAL_API_KEY env var) "
             "or offline list (--bad-hashes)",
    )
    parser.add_argument(
        "--bad-hashes", metavar="FILE",
        help="Path to a text file of known-bad hashes (one per line) for offline checking",
    )
    parser.add_argument(
        "--json", metavar="OUTFILE",
        help="Write results as JSON to OUTFILE",
    )
    args = parser.parse_args()

    if not args.files and not args.raw_hash:
        parser.error("Provide at least one FILE or use --hash")

    api_key = os.environ.get(VT_ENV_KEY, "")
    bad_hash_db = {}
    if args.bad_hashes:
        bad_hash_db = load_bad_hashes(args.bad_hashes)

    all_results = []
    width = 60

    print("=" * width)
    print("  FILE HASH CHECKER".center(width))
    print("=" * width)

    # --- Process files -------------------------------------------------------
    for filepath in args.files or []:
        hashes = compute_hashes(filepath)
        if hashes is None:
            continue
        print_hashes(filepath, hashes)

        result_entry = {"file": filepath, "hashes": hashes}

        if args.check:
            sha256 = hashes["sha256"]
            if api_key:
                vt_result = check_virustotal(sha256, api_key)
                print_vt_result(vt_result)
                result_entry["virustotal"] = vt_result
            elif bad_hash_db:
                print(f"\n  {'--- Offline Hash Check ':->{60}}")
                offline = check_offline(list(hashes.values()), bad_hash_db)
                for r in offline:
                    print_offline_result(r)
                result_entry["offline_check"] = offline
            else:
                print("\n  [!] No API key set and no --bad-hashes file provided.")
                print(f"      Set {VT_ENV_KEY} or use --bad-hashes for reputation checks.")

        all_results.append(result_entry)
        print()

    # --- Process raw hash ----------------------------------------------------
    if args.raw_hash:
        h = args.raw_hash.strip()
        hash_type = identify_hash_type(h)
        print(f"\n  Raw Hash  : {h}")
        print(f"  Algorithm : {hash_type or 'unknown'}")

        result_entry = {"raw_hash": h, "hash_type": hash_type}

        if args.check:
            if api_key:
                vt_result = check_virustotal(h, api_key)
                print_vt_result(vt_result)
                result_entry["virustotal"] = vt_result
            elif bad_hash_db:
                print(f"\n  {'--- Offline Hash Check ':->{60}}")
                offline = check_offline([h], bad_hash_db)
                for r in offline:
                    print_offline_result(r)
                result_entry["offline_check"] = offline
            else:
                print(f"\n  [!] Set {VT_ENV_KEY} or use --bad-hashes for reputation checks.")

        all_results.append(result_entry)

    # --- JSON output ---------------------------------------------------------
    if args.json:
        try:
            with open(args.json, "w") as fh:
                json.dump(all_results, fh, indent=2)
            print(f"[+] JSON results written to {args.json}")
        except OSError as exc:
            print(f"[!] Could not write JSON: {exc}", file=sys.stderr)
            sys.exit(1)

    print("=" * width)


if __name__ == "__main__":
    main()
