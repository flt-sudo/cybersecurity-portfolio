#!/usr/bin/env python3
"""
file_integrity_monitor.py - File Integrity Monitoring (FIM) Tool

Monitors a directory for unauthorized changes by comparing file states
against a known-good baseline. Detects:
    - New files added since baseline
    - Files deleted since baseline
    - Content modifications (SHA256 hash changes)
    - Permission / ownership changes
    - Timestamp modifications

Baseline data is stored as JSON for portability and easy inspection.

Author: Security Automation Toolkit
"""

import argparse
import datetime
import hashlib
import json
import os
import stat
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

READ_CHUNK = 65536
DEFAULT_BASELINE = "fim_baseline.json"
EXCLUDED_DIRS = {".git", "__pycache__", ".svn", ".hg", "node_modules", ".venv"}


# ---------------------------------------------------------------------------
# File metadata collection
# ---------------------------------------------------------------------------

def compute_sha256(filepath):
    """Compute SHA256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        return None


def get_file_metadata(filepath):
    """Collect metadata for a single file."""
    try:
        st = os.stat(filepath)
    except (PermissionError, OSError):
        return None

    permissions = stat.filemode(st.st_mode)
    sha256 = compute_sha256(filepath)

    return {
        "path": filepath,
        "sha256": sha256,
        "size": st.st_size,
        "permissions": permissions,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
        "ctime": datetime.datetime.fromtimestamp(st.st_ctime).isoformat(),
    }


def walk_directory(dirpath, exclude_patterns=None):
    """Recursively collect metadata for all files in a directory.

    Returns a dict keyed by relative file path.
    """
    if exclude_patterns is None:
        exclude_patterns = set()

    files = {}
    dirpath = os.path.abspath(dirpath)

    for root, dirs, filenames in os.walk(dirpath):
        # Prune excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and d not in exclude_patterns]

        for fname in filenames:
            fullpath = os.path.join(root, fname)
            relpath = os.path.relpath(fullpath, dirpath)

            meta = get_file_metadata(fullpath)
            if meta is not None:
                # Store with relative path as key for portability
                meta["path"] = relpath
                files[relpath] = meta

    return files


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def create_baseline(dirpath, exclude_patterns=None):
    """Scan a directory and return a baseline dict."""
    files = walk_directory(dirpath, exclude_patterns)
    baseline = {
        "version": 1,
        "target_directory": os.path.abspath(dirpath),
        "created_at": datetime.datetime.now().isoformat(),
        "file_count": len(files),
        "files": files,
    }
    return baseline


def save_baseline(baseline, filepath):
    """Write baseline to a JSON file."""
    with open(filepath, "w") as fh:
        json.dump(baseline, fh, indent=2)


def load_baseline(filepath):
    """Load a baseline from JSON."""
    try:
        with open(filepath, "r") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        print(f"[!] Corrupt baseline file: {filepath}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Integrity checking
# ---------------------------------------------------------------------------

class IntegrityReport:
    """Holds the results of a baseline vs. current comparison."""

    def __init__(self):
        self.new_files = []         # files present now but not in baseline
        self.deleted_files = []     # files in baseline but no longer present
        self.modified_files = []    # files with changed content
        self.permission_changes = []  # files with changed permissions
        self.timestamp_changes = []   # files with changed mtime only (no content change)
        self.unchanged_files = 0
        self.errors = []

    @property
    def total_changes(self):
        return (len(self.new_files) + len(self.deleted_files) +
                len(self.modified_files) + len(self.permission_changes))

    @property
    def has_changes(self):
        return self.total_changes > 0


def compare_baselines(baseline_files, current_files):
    """Compare baseline file metadata to current state."""
    report = IntegrityReport()

    baseline_paths = set(baseline_files.keys())
    current_paths = set(current_files.keys())

    # New files
    for path in sorted(current_paths - baseline_paths):
        report.new_files.append(current_files[path])

    # Deleted files
    for path in sorted(baseline_paths - current_paths):
        report.deleted_files.append(baseline_files[path])

    # Changed files
    for path in sorted(baseline_paths & current_paths):
        old = baseline_files[path]
        new = current_files[path]

        content_changed = old.get("sha256") != new.get("sha256")
        perms_changed = old.get("permissions") != new.get("permissions")
        owner_changed = (old.get("uid") != new.get("uid") or
                         old.get("gid") != new.get("gid"))
        mtime_changed = old.get("mtime") != new.get("mtime")

        if content_changed:
            report.modified_files.append({
                "path": path,
                "old_sha256": old.get("sha256"),
                "new_sha256": new.get("sha256"),
                "old_size": old.get("size"),
                "new_size": new.get("size"),
                "old_mtime": old.get("mtime"),
                "new_mtime": new.get("mtime"),
            })
        elif perms_changed or owner_changed:
            report.permission_changes.append({
                "path": path,
                "old_permissions": old.get("permissions"),
                "new_permissions": new.get("permissions"),
                "old_uid": old.get("uid"),
                "new_uid": new.get("uid"),
                "old_gid": old.get("gid"),
                "new_gid": new.get("gid"),
            })
        elif mtime_changed:
            report.timestamp_changes.append({
                "path": path,
                "old_mtime": old.get("mtime"),
                "new_mtime": new.get("mtime"),
            })
        else:
            report.unchanged_files += 1

    return report


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_report(report, target_dir):
    """Pretty-print the integrity comparison report."""
    width = 72
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * width)
    print("  FILE INTEGRITY MONITOR -- CHANGE REPORT".center(width))
    print("=" * width)
    print(f"  Target Directory : {target_dir}")
    print(f"  Check Time       : {ts}")
    print(f"  Unchanged Files  : {report.unchanged_files}")
    print(f"  Total Changes    : {report.total_changes}")

    if not report.has_changes and not report.timestamp_changes:
        print(f"\n  [OK] No changes detected. All files match the baseline.")
        print("=" * width)
        return

    # New files
    if report.new_files:
        print(f"\n{'--- NEW FILES (not in baseline) ':->{ width}}")
        for f in report.new_files:
            print(f"  [+] {f['path']}")
            print(f"      SHA256: {f.get('sha256', 'N/A')}")
            print(f"      Size:   {f.get('size', 0):,} bytes")
            print(f"      Perms:  {f.get('permissions', 'N/A')}")

    # Deleted files
    if report.deleted_files:
        print(f"\n{'--- DELETED FILES (missing from disk) ':->{ width}}")
        for f in report.deleted_files:
            print(f"  [-] {f['path']}")
            print(f"      SHA256: {f.get('sha256', 'N/A')}")
            print(f"      Size:   {f.get('size', 0):,} bytes")

    # Modified files
    if report.modified_files:
        print(f"\n{'--- MODIFIED FILES (content changed) ':->{ width}}")
        for f in report.modified_files:
            size_delta = (f.get("new_size", 0) or 0) - (f.get("old_size", 0) or 0)
            sign = "+" if size_delta >= 0 else ""
            print(f"  [*] {f['path']}")
            print(f"      Old SHA256 : {f.get('old_sha256', 'N/A')}")
            print(f"      New SHA256 : {f.get('new_sha256', 'N/A')}")
            print(f"      Size Delta : {sign}{size_delta:,} bytes")
            print(f"      Old mtime  : {f.get('old_mtime', 'N/A')}")
            print(f"      New mtime  : {f.get('new_mtime', 'N/A')}")

    # Permission changes
    if report.permission_changes:
        print(f"\n{'--- PERMISSION CHANGES ':->{ width}}")
        for f in report.permission_changes:
            print(f"  [!] {f['path']}")
            if f["old_permissions"] != f["new_permissions"]:
                print(f"      Perms: {f['old_permissions']} -> {f['new_permissions']}")
            if f["old_uid"] != f["new_uid"]:
                print(f"      UID:   {f['old_uid']} -> {f['new_uid']}")
            if f["old_gid"] != f["new_gid"]:
                print(f"      GID:   {f['old_gid']} -> {f['new_gid']}")

    # Timestamp-only changes (informational)
    if report.timestamp_changes:
        print(f"\n{'--- TIMESTAMP CHANGES (content unchanged) ':->{ width}}")
        for f in report.timestamp_changes[:20]:  # Cap display
            print(f"  [~] {f['path']}  mtime: {f['old_mtime']} -> {f['new_mtime']}")
        if len(report.timestamp_changes) > 20:
            print(f"      ... and {len(report.timestamp_changes) - 20} more")

    print("\n" + "=" * width)


def export_report_json(report, filepath):
    """Export the integrity report as JSON."""
    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "summary": {
            "new_files": len(report.new_files),
            "deleted_files": len(report.deleted_files),
            "modified_files": len(report.modified_files),
            "permission_changes": len(report.permission_changes),
            "timestamp_changes": len(report.timestamp_changes),
            "unchanged_files": report.unchanged_files,
            "total_changes": report.total_changes,
        },
        "new_files": report.new_files,
        "deleted_files": report.deleted_files,
        "modified_files": report.modified_files,
        "permission_changes": report.permission_changes,
    }
    try:
        with open(filepath, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"[+] JSON report written to {filepath}")
    except OSError as exc:
        print(f"[!] Could not write JSON report: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor -- Detect unauthorized changes to files "
                    "by comparing against a known-good baseline.",
        epilog="Examples:\n"
               "  # Create a baseline\n"
               "  %(prog)s --init --target /etc --baseline /tmp/etc_baseline.json\n\n"
               "  # Check against baseline\n"
               "  %(prog)s --check --target /etc --baseline /tmp/etc_baseline.json\n\n"
               "  # Check and export JSON report\n"
               "  %(prog)s --check --target /etc --baseline base.json --report changes.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--init", action="store_true",
        help="Create a new baseline for the target directory",
    )
    mode.add_argument(
        "--check", action="store_true",
        help="Check current state against an existing baseline",
    )
    mode.add_argument(
        "--update", action="store_true",
        help="Check and then update the baseline to current state",
    )
    parser.add_argument(
        "--target", "-t", required=True,
        help="Directory to monitor",
    )
    parser.add_argument(
        "--baseline", "-b", default=DEFAULT_BASELINE,
        help=f"Path to baseline JSON file (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "--report", "-r", metavar="OUTFILE",
        help="Export change report as JSON",
    )
    parser.add_argument(
        "--exclude", action="append", metavar="DIR",
        help="Directory names to exclude from scanning (repeatable)",
    )
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"[!] Target is not a directory: {target}", file=sys.stderr)
        sys.exit(1)

    excludes = set(args.exclude or [])

    # --- INIT mode -----------------------------------------------------------
    if args.init:
        print(f"[*] Scanning {target} ...")
        baseline = create_baseline(target, excludes)
        save_baseline(baseline, args.baseline)
        print(f"[+] Baseline created: {baseline['file_count']} files indexed")
        print(f"[+] Saved to {args.baseline}")
        return

    # --- CHECK / UPDATE mode -------------------------------------------------
    baseline = load_baseline(args.baseline)
    if baseline is None:
        print(f"[!] No baseline found at {args.baseline}", file=sys.stderr)
        print("    Run with --init first to create a baseline.", file=sys.stderr)
        sys.exit(1)

    # Verify target matches baseline
    baseline_target = baseline.get("target_directory", "")
    if os.path.abspath(baseline_target) != target:
        print(f"[!] WARNING: Baseline was created for '{baseline_target}',")
        print(f"    but you are checking '{target}'.")
        print(f"    Proceeding anyway -- results may be inaccurate.\n")

    print(f"[*] Baseline loaded: {baseline['file_count']} files "
          f"(created {baseline['created_at']})")
    print(f"[*] Scanning {target} for changes ...")

    current = walk_directory(target, excludes)
    report = compare_baselines(baseline.get("files", {}), current)

    print_report(report, target)

    if args.report:
        export_report_json(report, args.report)

    # --- UPDATE: overwrite baseline ------------------------------------------
    if args.update and report.has_changes:
        new_baseline = create_baseline(target, excludes)
        save_baseline(new_baseline, args.baseline)
        print(f"[+] Baseline updated: {new_baseline['file_count']} files indexed")

    # Exit code: 0 = no changes, 1 = changes detected
    if report.has_changes:
        sys.exit(1)


if __name__ == "__main__":
    main()
