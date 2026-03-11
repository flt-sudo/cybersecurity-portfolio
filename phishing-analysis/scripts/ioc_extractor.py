#!/usr/bin/env python3
"""
IOC Extractor
=============
Extracts Indicators of Compromise (IOCs) from arbitrary text input,
deduplicates them, and outputs results in plain text, JSON, or CSV.

Supported IOC types:
    - IPv4 addresses
    - Domain names
    - URLs
    - Email addresses
    - File hashes (MD5, SHA-1, SHA-256)
    - File names (common executable / document extensions)

Uses only the Python standard library.

Usage:
    python3 ioc_extractor.py -f report.txt
    cat alert.log | python3 ioc_extractor.py
    python3 ioc_extractor.py -f report.txt --format json --defang
    python3 ioc_extractor.py -f report.txt --format csv -o iocs.csv --refang
"""

import argparse
import csv
import io
import json
import re
import sys
from collections import OrderedDict


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IPv4 -- four octets (0-255) separated by dots.  We validate the range in
# the post-processing step to keep the regex readable.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# URLs -- http(s) and ftp, also matches defanged hxxp(s) after refanging.
_URL_RE = re.compile(
    r"https?://[^\s<>\"'\)]+",
    re.IGNORECASE,
)

# Email addresses.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Domain names -- at least one dot, TLD >= 2 chars.  We exclude IPs and
# common false positives in post-processing.
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}\b"
)

# Hashes.
_MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")

# File names with extensions commonly associated with malware delivery.
_FILENAME_EXTENSIONS = (
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "hta", "lnk",
    "iso", "img", "msi", "jar", "py", "wsf",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm",
    "pdf", "rtf", "zip", "rar", "7z", "gz", "tar",
    "html", "htm", "svg",
)
_FILENAME_RE = re.compile(
    r"\b[\w\-. ]+\.(?:" + "|".join(_FILENAME_EXTENSIONS) + r")\b",
    re.IGNORECASE,
)

# Private / reserved IP ranges we want to flag but still extract.
_PRIVATE_RANGES = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)


# ---------------------------------------------------------------------------
# Defang / refang helpers
# ---------------------------------------------------------------------------

def refang(text):
    """Convert common defanged notations back to operational form."""
    text = text.replace("hxxp", "http").replace("hXXp", "http")
    text = text.replace("[.]", ".").replace("(dot)", ".")
    text = text.replace("[:]", ":").replace("(colon)", ":")
    text = text.replace("[at]", "@").replace("(at)", "@")
    text = text.replace("[//]", "://")
    return text


def defang_value(value, ioc_type):
    """Return a defanged version of a single IOC value."""
    if ioc_type == "url":
        return value.replace("http", "hxxp", 1).replace(".", "[.]")
    if ioc_type in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if ioc_type == "email":
        return value.replace("@", "[at]").replace(".", "[.]")
    return value


# ---------------------------------------------------------------------------
# Extraction engine
# ---------------------------------------------------------------------------

def extract_iocs(text):
    """Return a dict mapping IOC type -> sorted deduplicated list of values."""
    results = OrderedDict()

    # --- SHA-256 first (64 hex chars) so we can exclude them from SHA-1/MD5
    sha256 = set(_SHA256_RE.findall(text))
    sha256_lower = {h.lower() for h in sha256}

    sha1_candidates = set(_SHA1_RE.findall(text))
    sha1 = {h for h in sha1_candidates if h.lower() not in sha256_lower}
    sha1_lower = {h.lower() for h in sha1}

    md5_candidates = set(_MD5_RE.findall(text))
    md5 = set()
    for h in md5_candidates:
        # A 32-char hex string that is a substring of a longer match is not MD5.
        if h.lower() not in sha256_lower and h.lower() not in sha1_lower:
            md5.add(h)

    # Filter out strings that look like hashes but are actually common hex
    # words (very short entropy).  We keep everything here since 32+ hex chars
    # is extremely unlikely to appear in normal prose by accident.

    urls = set()
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)'\"")
        urls.add(url)

    emails = set(_EMAIL_RE.findall(text))

    # Domains -- deduplicate against domains already captured inside URLs
    # and email addresses to reduce noise.
    url_domains = set()
    for u in urls:
        try:
            from urllib.parse import urlparse as _urlparse
            host = _urlparse(u).hostname
            if host:
                url_domains.add(host.lower())
        except Exception:
            pass

    email_domains = {e.split("@")[1].lower() for e in emails}

    # Gather all hostnames that already appear inside a URL path/query so
    # we can suppress them from the standalone domain list.
    url_path_tokens = set()
    for u in urls:
        try:
            from urllib.parse import urlparse as _urlparse
            parsed = _urlparse(u)
            # Tokenise the path by "/" and add anything that looks like a
            # domain-ish string (contains a dot).
            for segment in parsed.path.split("/"):
                if "." in segment:
                    url_path_tokens.add(segment.lower())
        except Exception:
            pass

    # Well-known TLDs (minimal set) for validating candidate domains.
    _VALID_TLDS = {
        "com", "net", "org", "edu", "gov", "mil", "int",
        "io", "co", "us", "uk", "de", "fr", "ru", "cn", "jp", "au",
        "ca", "br", "in", "it", "nl", "se", "no", "fi", "be", "ch",
        "info", "biz", "xyz", "online", "site", "top", "club",
        "me", "tv", "cc", "ws", "mobi", "pro", "name", "travel",
    }

    domain_candidates = set(_DOMAIN_RE.findall(text))
    domains = set()
    for d in domain_candidates:
        dl = d.lower()
        # Skip if it looks like a filename with a known extension.
        if any(dl.endswith("." + ext) for ext in _FILENAME_EXTENSIONS):
            continue
        # Skip if already covered by a URL or email.
        if dl in url_domains or dl in email_domains:
            continue
        # Skip if it appeared as a path segment inside a URL.
        if dl in url_path_tokens:
            continue
        # Skip very short two-part "domains" that are likely header field
        # names or artefacts (e.g. "header.from", "smtp.mailfrom").
        parts = dl.split(".")
        tld = parts[-1]
        if len(parts) == 2 and tld not in _VALID_TLDS:
            continue
        # Skip MIME-type-like strings (many parts or very long).
        if len(parts) > 4 or len(dl) > 60:
            continue
        # Skip if any label is excessively long (real domain labels rarely
        # exceed ~20 chars, MIME types have very long labels).
        if any(len(p) > 25 for p in parts):
            continue
        domains.add(d)

    ipv4 = set(_IPV4_RE.findall(text))

    filenames = set()
    for m in _FILENAME_RE.finditer(text):
        fn = m.group(0).strip()
        # Skip very short matches that are likely false positives.
        if len(fn) > 3:
            filenames.add(fn)

    # Build ordered result dict.
    if ipv4:
        results["ipv4"] = sorted(ipv4)
    if domains:
        results["domain"] = sorted(domains, key=str.lower)
    if urls:
        results["url"] = sorted(urls)
    if emails:
        results["email"] = sorted(emails, key=str.lower)
    if md5:
        results["md5"] = sorted(md5, key=str.lower)
    if sha1:
        results["sha1"] = sorted(sha1, key=str.lower)
    if sha256:
        results["sha256"] = sorted(sha256, key=str.lower)
    if filenames:
        results["filename"] = sorted(filenames, key=str.lower)

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_text(iocs, do_defang=False):
    """Return a human-readable text report."""
    lines = []
    total = sum(len(v) for v in iocs.values())
    lines.append(f"IOC Extraction Results  ({total} indicators found)")
    lines.append("=" * 60)
    for ioc_type, values in iocs.items():
        lines.append(f"\n[{ioc_type.upper()}]  ({len(values)})")
        lines.append("-" * 40)
        for v in values:
            display = defang_value(v, ioc_type) if do_defang else v
            extra = ""
            if ioc_type == "ipv4" and _PRIVATE_RANGES.match(v):
                extra = "  (private/reserved)"
            lines.append(f"  {display}{extra}")
    lines.append("")
    return "\n".join(lines)


def format_json(iocs, do_defang=False):
    """Return a JSON string."""
    if do_defang:
        defanged = OrderedDict()
        for ioc_type, values in iocs.items():
            defanged[ioc_type] = [defang_value(v, ioc_type) for v in values]
        return json.dumps(defanged, indent=2)
    return json.dumps(iocs, indent=2)


def format_csv(iocs, do_defang=False):
    """Return a CSV string with columns: type, value."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value"])
    for ioc_type, values in iocs.items():
        for v in values:
            display = defang_value(v, ioc_type) if do_defang else v
            writer.writerow([ioc_type, display])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract IOCs (IPs, domains, URLs, emails, hashes, filenames) from text.",
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to a text file to analyze.  If omitted, reads from stdin.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write output to this file instead of stdout.",
    )
    parser.add_argument(
        "--refang",
        action="store_true",
        help="Refang defanged indicators in the input before extraction.",
    )
    parser.add_argument(
        "--defang",
        action="store_true",
        help="Defang indicators in the output for safe sharing.",
    )
    args = parser.parse_args()

    # Read input.
    if args.file:
        try:
            with open(args.file, "r", errors="replace") as fh:
                text = fh.read()
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            print("Reading from stdin (paste text then press Ctrl-D):", file=sys.stderr)
        text = sys.stdin.read()

    if not text.strip():
        print("Error: no input text provided.", file=sys.stderr)
        sys.exit(1)

    # Optional refang pass.
    if args.refang:
        text = refang(text)

    iocs = extract_iocs(text)

    if not iocs:
        print("No IOCs found in input.", file=sys.stderr)
        sys.exit(0)

    # Format output.
    if args.format == "json":
        output = format_json(iocs, do_defang=args.defang)
    elif args.format == "csv":
        output = format_csv(iocs, do_defang=args.defang)
    else:
        output = format_text(iocs, do_defang=args.defang)

    # Write output.
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(output)
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
