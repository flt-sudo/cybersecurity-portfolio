#!/usr/bin/env python3
"""
Email Header Analyzer
=====================
Parses a raw .eml file and produces a structured analysis report covering
envelope metadata, mail server hops, authentication results, extracted URLs,
and attachment hashes.

Uses only the Python standard library.

Usage:
    python3 email_header_analyzer.py MESSAGE.eml
    python3 email_header_analyzer.py --json MESSAGE.eml
"""

import argparse
import email
import email.policy
import email.utils
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def parse_received_headers(msg):
    """Return an ordered list of Received header hops (oldest first).

    Each hop is a dict with keys: from_host, by_host, protocol, timestamp, raw.
    """
    hops = []
    received_headers = msg.get_all("Received", [])
    # Received headers are prepended, so the last one in the list is the
    # first hop (closest to the originating server).
    for raw in reversed(received_headers):
        hop = {"raw": " ".join(raw.split())}

        from_match = re.search(r"from\s+([\w.\-]+)", raw, re.IGNORECASE)
        by_match = re.search(r"by\s+([\w.\-]+)", raw, re.IGNORECASE)
        with_match = re.search(r"with\s+(\w+)", raw, re.IGNORECASE)
        # The timestamp is typically after the last semicolon.
        ts_match = re.search(r";\s*(.+)$", raw)

        hop["from_host"] = from_match.group(1) if from_match else None
        hop["by_host"] = by_match.group(1) if by_match else None
        hop["protocol"] = with_match.group(1) if with_match else None
        hop["timestamp"] = ts_match.group(1).strip() if ts_match else None
        hops.append(hop)
    return hops


def parse_authentication_results(msg):
    """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results."""
    results = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "raw": None,
    }
    auth_header = msg.get("Authentication-Results")
    if not auth_header:
        return results

    # Normalise whitespace for easier regex matching.
    auth_flat = " ".join(auth_header.split())
    results["raw"] = auth_flat

    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", auth_flat, re.IGNORECASE)
    dkim_match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)", auth_flat, re.IGNORECASE)
    dmarc_match = re.search(r"dmarc=(pass|fail|bestguesspass|none|temperror|permerror)", auth_flat, re.IGNORECASE)

    if spf_match:
        results["spf"] = spf_match.group(1).lower()
    if dkim_match:
        results["dkim"] = dkim_match.group(1).lower()
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).lower()
    return results


def extract_urls(msg):
    """Return a deduplicated list of URLs found in all text/* body parts."""
    urls = set()
    url_pattern = re.compile(
        r'https?://[^\s<>\"\'\)]+',
        re.IGNORECASE,
    )
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type and content_type.startswith("text/"):
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    urls.update(url_pattern.findall(text))
            except Exception:
                continue
    # Clean trailing punctuation that is unlikely to be part of a URL.
    cleaned = []
    for u in sorted(urls):
        u = u.rstrip(".,;:!?)")
        cleaned.append(u)
    return sorted(set(cleaned))


def extract_attachments(msg):
    """Return metadata and SHA-256 hashes for every attachment."""
    attachments = []
    for part in msg.walk():
        disposition = part.get("Content-Disposition", "")
        if "attachment" in disposition or "inline" in disposition:
            filename = part.get_filename() or "(unnamed)"
            payload = part.get_payload(decode=True)
            if payload:
                sha256 = hashlib.sha256(payload).hexdigest()
                size = len(payload)
            else:
                sha256 = None
                size = 0
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": size,
                "sha256": sha256,
            })
    return attachments


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

SECTION_SEP = "=" * 72
SUB_SEP = "-" * 72

def _verdict_flag(value):
    """Return a visual flag for authentication verdicts."""
    if value is None:
        return "[?] NOT PRESENT"
    v = value.lower()
    if v == "pass":
        return "[+] PASS"
    if v in ("fail", "permerror"):
        return "[!] FAIL"
    return f"[~] {v.upper()}"


def format_text_report(envelope, hops, auth, urls, attachments):
    """Build a human-readable analysis report string."""
    lines = []
    lines.append(SECTION_SEP)
    lines.append("  EMAIL HEADER ANALYSIS REPORT")
    lines.append(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(SECTION_SEP)

    # -- Envelope --
    lines.append("")
    lines.append("1. ENVELOPE INFORMATION")
    lines.append(SUB_SEP)
    for label, value in envelope.items():
        lines.append(f"  {label:16s}: {value or '(not present)'}")

    # -- Hops --
    lines.append("")
    lines.append("2. MAIL SERVER HOPS  (oldest -> newest)")
    lines.append(SUB_SEP)
    if not hops:
        lines.append("  No Received headers found.")
    for i, hop in enumerate(hops, 1):
        lines.append(f"  Hop {i}:")
        lines.append(f"    From     : {hop['from_host'] or '(unknown)'}")
        lines.append(f"    By       : {hop['by_host'] or '(unknown)'}")
        lines.append(f"    Protocol : {hop['protocol'] or '(unknown)'}")
        lines.append(f"    Timestamp: {hop['timestamp'] or '(unknown)'}")
        lines.append(f"    Raw      : {hop['raw']}")
        lines.append("")

    # -- Authentication --
    lines.append("3. AUTHENTICATION RESULTS")
    lines.append(SUB_SEP)
    lines.append(f"  SPF   : {_verdict_flag(auth['spf'])}")
    lines.append(f"  DKIM  : {_verdict_flag(auth['dkim'])}")
    lines.append(f"  DMARC : {_verdict_flag(auth['dmarc'])}")
    if auth["raw"]:
        lines.append(f"  Raw   : {auth['raw']}")

    # -- URLs --
    lines.append("")
    lines.append("4. EXTRACTED URLs")
    lines.append(SUB_SEP)
    if not urls:
        lines.append("  No URLs found in message body.")
    for url in urls:
        parsed = urlparse(url)
        lines.append(f"  [{parsed.scheme}] {url}")

    # -- Attachments --
    lines.append("")
    lines.append("5. ATTACHMENTS")
    lines.append(SUB_SEP)
    if not attachments:
        lines.append("  No attachments found.")
    for att in attachments:
        lines.append(f"  File : {att['filename']}")
        lines.append(f"    Type   : {att['content_type']}")
        lines.append(f"    Size   : {att['size_bytes']} bytes")
        lines.append(f"    SHA-256: {att['sha256'] or '(empty payload)'}")
        lines.append("")

    # -- Suspicious-indicator summary --
    lines.append("6. QUICK ASSESSMENT")
    lines.append(SUB_SEP)
    warnings = []
    if auth["spf"] and auth["spf"] != "pass":
        warnings.append("SPF did not pass -- sender domain may be spoofed.")
    if auth["dkim"] and auth["dkim"] != "pass":
        warnings.append("DKIM did not pass -- message integrity unverified.")
    if auth["dmarc"] and auth["dmarc"] != "pass":
        warnings.append("DMARC did not pass -- domain alignment failure.")
    if envelope.get("Return-Path") and envelope.get("From"):
        rp_domain = envelope["Return-Path"].split("@")[-1].rstrip(">").lower()
        from_domain = envelope["From"].split("@")[-1].rstrip(">").lower()
        if rp_domain != from_domain:
            warnings.append(
                f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain})."
            )
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname and re.match(r"\d+\.\d+\.\d+\.\d+", parsed.hostname):
            warnings.append(f"URL uses raw IP address: {url}")
    for att in attachments:
        risky_exts = (
            ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1",
            ".hta", ".lnk", ".iso", ".img", ".dll",
        )
        if any(att["filename"].lower().endswith(ext) for ext in risky_exts):
            warnings.append(f"Potentially dangerous attachment: {att['filename']}")

    if warnings:
        for w in warnings:
            lines.append(f"  [!] {w}")
    else:
        lines.append("  No obvious red flags detected (manual review still recommended).")

    lines.append("")
    lines.append(SECTION_SEP)
    return "\n".join(lines)


def build_json_report(envelope, hops, auth, urls, attachments):
    """Return the report as a JSON-serialisable dict."""
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "envelope": envelope,
        "hops": hops,
        "authentication": {
            "spf": auth["spf"],
            "dkim": auth["dkim"],
            "dmarc": auth["dmarc"],
            "raw": auth["raw"],
        },
        "urls": urls,
        "attachments": attachments,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyze(eml_path, output_json=False):
    """Parse the .eml file and return the formatted report string."""
    with open(eml_path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=email.policy.default)

    envelope = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Date": msg.get("Date"),
        "Return-Path": msg.get("Return-Path"),
        "Message-ID": msg.get("Message-ID"),
        "Reply-To": msg.get("Reply-To"),
        "X-Mailer": msg.get("X-Mailer"),
    }

    hops = parse_received_headers(msg)
    auth = parse_authentication_results(msg)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)

    if output_json:
        return json.dumps(build_json_report(envelope, hops, auth, urls, attachments), indent=2)
    return format_text_report(envelope, hops, auth, urls, attachments)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a raw .eml file and produce a structured phishing analysis report.",
    )
    parser.add_argument(
        "eml_file",
        help="Path to the .eml file to analyze.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output the report in JSON format instead of plain text.",
    )
    args = parser.parse_args()

    try:
        report = analyze(args.eml_file, output_json=args.output_json)
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(report)


if __name__ == "__main__":
    main()
