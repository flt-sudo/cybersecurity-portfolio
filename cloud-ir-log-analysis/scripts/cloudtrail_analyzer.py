#!/usr/bin/env python3
"""
CloudTrail Log Analyzer
-----------------------
Parses AWS CloudTrail JSON log files from the local filesystem (no AWS account
required).  Detects suspicious API activity, builds a chronological timeline,
assigns severity ratings, maps findings to the MITRE ATT&CK Cloud Matrix, and
generates a structured investigation report.

Usage:
    python3 cloudtrail_analyzer.py -d /path/to/logs/
    python3 cloudtrail_analyzer.py -f single_file.json
    python3 cloudtrail_analyzer.py -d /path/to/logs/ --severity high
    python3 cloudtrail_analyzer.py -d /path/to/logs/ --json

Author:  Security Analyst Portfolio Project
License: MIT
"""

import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# MITRE ATT&CK Cloud Matrix Mapping
# ---------------------------------------------------------------------------
MITRE_MAP = {
    # Initial Access
    "ConsoleLogin": {
        "tactic": "Initial Access",
        "technique": "T1078 - Valid Accounts",
        "sub": "T1078.004 - Cloud Accounts",
    },
    # Reconnaissance / Discovery
    "GetCallerIdentity": {
        "tactic": "Discovery",
        "technique": "T1087 - Account Discovery",
        "sub": "T1087.004 - Cloud Account",
    },
    "ListUsers": {
        "tactic": "Discovery",
        "technique": "T1087 - Account Discovery",
        "sub": "T1087.004 - Cloud Account",
    },
    "ListRoles": {
        "tactic": "Discovery",
        "technique": "T1087 - Account Discovery",
        "sub": "T1087.004 - Cloud Account",
    },
    "ListBuckets": {
        "tactic": "Discovery",
        "technique": "T1580 - Cloud Infrastructure Discovery",
        "sub": None,
    },
    "DescribeInstances": {
        "tactic": "Discovery",
        "technique": "T1580 - Cloud Infrastructure Discovery",
        "sub": None,
    },
    "DescribeSecurityGroups": {
        "tactic": "Discovery",
        "technique": "T1580 - Cloud Infrastructure Discovery",
        "sub": None,
    },
    # Privilege Escalation
    "AttachUserPolicy": {
        "tactic": "Privilege Escalation",
        "technique": "T1098 - Account Manipulation",
        "sub": "T1098.003 - Additional Cloud Roles",
    },
    "PutUserPolicy": {
        "tactic": "Privilege Escalation",
        "technique": "T1098 - Account Manipulation",
        "sub": "T1098.003 - Additional Cloud Roles",
    },
    "AttachRolePolicy": {
        "tactic": "Privilege Escalation",
        "technique": "T1098 - Account Manipulation",
        "sub": "T1098.003 - Additional Cloud Roles",
    },
    # Persistence
    "CreateUser": {
        "tactic": "Persistence",
        "technique": "T1136 - Create Account",
        "sub": "T1136.003 - Cloud Account",
    },
    "CreateAccessKey": {
        "tactic": "Persistence",
        "technique": "T1098 - Account Manipulation",
        "sub": "T1098.001 - Additional Cloud Credentials",
    },
    "CreateLoginProfile": {
        "tactic": "Persistence",
        "technique": "T1098 - Account Manipulation",
        "sub": "T1098.001 - Additional Cloud Credentials",
    },
    "CreateKeyPair": {
        "tactic": "Persistence",
        "technique": "T1098 - Account Manipulation",
        "sub": "T1098.001 - Additional Cloud Credentials",
    },
    # Defense Evasion
    "StopLogging": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": "T1562.008 - Disable Cloud Logs",
    },
    "DeleteTrail": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": "T1562.008 - Disable Cloud Logs",
    },
    "UpdateTrail": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": "T1562.008 - Disable Cloud Logs",
    },
    "DeleteDetector": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": "T1562.001 - Disable or Modify Tools",
    },
    "DeleteConfigRule": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": "T1562.001 - Disable or Modify Tools",
    },
    # Lateral Movement / Credential Access
    "AssumeRole": {
        "tactic": "Lateral Movement",
        "technique": "T1550 - Use Alternate Authentication Material",
        "sub": "T1550.001 - Application Access Token",
    },
    # Impact / Collection
    "RunInstances": {
        "tactic": "Impact",
        "technique": "T1496 - Resource Hijacking",
        "sub": None,
    },
    "ModifyInstanceAttribute": {
        "tactic": "Impact",
        "technique": "T1496 - Resource Hijacking",
        "sub": None,
    },
    # Exfiltration / Collection
    "GetObject": {
        "tactic": "Collection",
        "technique": "T1530 - Data from Cloud Storage",
        "sub": None,
    },
    # S3 policy / config changes
    "PutBucketPolicy": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": None,
    },
    "PutBucketAcl": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": None,
    },
    "DeleteBucketEncryption": {
        "tactic": "Defense Evasion",
        "technique": "T1562 - Impair Defenses",
        "sub": None,
    },
    # Security group changes
    "AuthorizeSecurityGroupIngress": {
        "tactic": "Persistence",
        "technique": "T1098 - Account Manipulation",
        "sub": None,
    },
}

# ---------------------------------------------------------------------------
# Detection Rules
# ---------------------------------------------------------------------------

SENSITIVE_BUCKET_PATTERNS = [
    r"confidential",
    r"secret",
    r"private",
    r"backup",
    r"financial",
    r"hr[-_]data",
    r"pii",
    r"credentials",
    r"keys",
]


def _get_username(event):
    """Extract a human-readable identity from the event."""
    uid = event.get("userIdentity", {})
    name = uid.get("userName")
    if name:
        return name
    arn = uid.get("arn", "")
    if arn:
        return arn.split("/")[-1] if "/" in arn else arn
    invoked = uid.get("invokedBy", "")
    if invoked:
        return invoked
    return uid.get("type", "Unknown")


def _get_source_ip(event):
    return event.get("sourceIPAddress", "N/A")


def _is_mfa(event):
    """Return True if MFA was used for a console login."""
    add = event.get("additionalEventData", {})
    if add and add.get("MFAUsed") == "Yes":
        return True
    sess = event.get("userIdentity", {}).get("sessionContext", {})
    attrs = sess.get("attributes", {})
    return str(attrs.get("mfaAuthenticated", "false")).lower() == "true"


def _is_aws_service(event):
    uid = event.get("userIdentity", {})
    return uid.get("type") == "AWSService" or uid.get("invokedBy", "").endswith(
        ".amazonaws.com"
    )


def _cidr_is_open(event):
    """Check if a security group rule opens to 0.0.0.0/0 or ::/0."""
    params = event.get("requestParameters", {}) or {}
    perms = params.get("ipPermissions", {}).get("items", [])
    for perm in perms:
        for rng in perm.get("ipRanges", {}).get("items", []):
            cidr = rng.get("cidrIp", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                return True
        for rng in perm.get("ipv6Ranges", {}).get("items", []):
            cidr = rng.get("cidrIpv6", "")
            if cidr in ("::/0",):
                return True
    return False


def _bucket_is_sensitive(event):
    params = event.get("requestParameters", {}) or {}
    bucket = params.get("bucketName", "")
    for pat in SENSITIVE_BUCKET_PATTERNS:
        if re.search(pat, bucket, re.IGNORECASE):
            return True
    return False


# ---------------------------------------------------------------------------
# Finding data structure
# ---------------------------------------------------------------------------


class Finding:
    __slots__ = (
        "timestamp",
        "severity",
        "title",
        "description",
        "user",
        "source_ip",
        "event_name",
        "event_source",
        "region",
        "mitre",
        "raw_event",
    )

    def __init__(
        self,
        timestamp,
        severity,
        title,
        description,
        user,
        source_ip,
        event_name,
        event_source,
        region,
        mitre=None,
        raw_event=None,
    ):
        self.timestamp = timestamp
        self.severity = severity
        self.title = title
        self.description = description
        self.user = user
        self.source_ip = source_ip
        self.event_name = event_name
        self.event_source = event_source
        self.region = region
        self.mitre = mitre or {}
        self.raw_event = raw_event

    def to_dict(self):
        d = {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "user": self.user,
            "source_ip": self.source_ip,
            "event_name": self.event_name,
            "event_source": self.event_source,
            "region": self.region,
        }
        if self.mitre:
            d["mitre_attack"] = self.mitre
        return d


# ---------------------------------------------------------------------------
# Core Analysis Engine
# ---------------------------------------------------------------------------


class CloudTrailAnalyzer:
    def __init__(self):
        self.events = []
        self.findings = []
        self.files_processed = 0

    # -- Loading ----------------------------------------------------------

    def load_file(self, filepath):
        """Load a single CloudTrail JSON file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as exc:
            print(f"[!] Error loading {filepath}: {exc}", file=sys.stderr)
            return
        records = data.get("Records", [])
        if not records and isinstance(data, list):
            records = data
        self.events.extend(records)
        self.files_processed += 1

    def load_directory(self, dirpath):
        """Load all *.json files under *dirpath*."""
        patterns = [
            os.path.join(dirpath, "*.json"),
            os.path.join(dirpath, "**", "*.json"),
        ]
        seen = set()
        for pat in patterns:
            for fp in glob.glob(pat, recursive=True):
                real = os.path.realpath(fp)
                if real not in seen:
                    seen.add(real)
                    self.load_file(real)

    # -- Detection rules --------------------------------------------------

    def _check_console_login(self, ev):
        if ev.get("eventName") != "ConsoleLogin":
            return
        resp = ev.get("responseElements", {}) or {}
        if resp.get("ConsoleLogin") != "Success":
            return
        user = _get_username(ev)
        ip = _get_source_ip(ev)
        mfa = _is_mfa(ev)
        if not mfa:
            self.findings.append(
                Finding(
                    timestamp=ev.get("eventTime", ""),
                    severity="HIGH",
                    title="Console Login Without MFA",
                    description=(
                        f"User '{user}' logged into the AWS Console from "
                        f"{ip} without multi-factor authentication."
                    ),
                    user=user,
                    source_ip=ip,
                    event_name="ConsoleLogin",
                    event_source=ev.get("eventSource", ""),
                    region=ev.get("awsRegion", ""),
                    mitre=MITRE_MAP.get("ConsoleLogin", {}),
                    raw_event=ev,
                )
            )

    def _check_iam_changes(self, ev):
        high_actions = {
            "CreateUser",
            "AttachUserPolicy",
            "CreateAccessKey",
            "PutUserPolicy",
            "AttachRolePolicy",
            "CreateLoginProfile",
        }
        name = ev.get("eventName", "")
        if name not in high_actions:
            return
        if _is_aws_service(ev):
            return
        user = _get_username(ev)
        ip = _get_source_ip(ev)
        params = ev.get("requestParameters", {}) or {}
        target = params.get("userName", params.get("roleName", "N/A"))
        policy = params.get("policyArn", params.get("policyName", ""))

        severity = "HIGH"
        desc_extra = ""
        if name in ("AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy"):
            if "AdministratorAccess" in str(policy) or '"Action":"*"' in str(
                params.get("policyDocument", "")
            ):
                severity = "HIGH"
                desc_extra = f" Policy grants broad/admin access ({policy or 'inline *'})."
            else:
                severity = "MEDIUM"
                desc_extra = f" Policy: {policy}." if policy else ""

        self.findings.append(
            Finding(
                timestamp=ev.get("eventTime", ""),
                severity=severity,
                title=f"IAM Change: {name}",
                description=(
                    f"User '{user}' performed {name} targeting '{target}' "
                    f"from {ip}.{desc_extra}"
                ),
                user=user,
                source_ip=ip,
                event_name=name,
                event_source=ev.get("eventSource", ""),
                region=ev.get("awsRegion", ""),
                mitre=MITRE_MAP.get(name, {}),
                raw_event=ev,
            )
        )

    def _check_s3_changes(self, ev):
        s3_write_actions = {
            "PutBucketPolicy",
            "PutBucketAcl",
            "DeleteBucketEncryption",
        }
        name = ev.get("eventName", "")
        if name in s3_write_actions:
            user = _get_username(ev)
            ip = _get_source_ip(ev)
            params = ev.get("requestParameters", {}) or {}
            bucket = params.get("bucketName", "N/A")
            self.findings.append(
                Finding(
                    timestamp=ev.get("eventTime", ""),
                    severity="HIGH",
                    title=f"S3 Configuration Change: {name}",
                    description=(
                        f"User '{user}' called {name} on bucket '{bucket}' "
                        f"from {ip}. This may expose data or weaken encryption."
                    ),
                    user=user,
                    source_ip=ip,
                    event_name=name,
                    event_source=ev.get("eventSource", ""),
                    region=ev.get("awsRegion", ""),
                    mitre=MITRE_MAP.get(name, {}),
                    raw_event=ev,
                )
            )

        if name == "GetObject" and _bucket_is_sensitive(ev):
            user = _get_username(ev)
            ip = _get_source_ip(ev)
            params = ev.get("requestParameters", {}) or {}
            bucket = params.get("bucketName", "N/A")
            key = params.get("key", "N/A")
            self.findings.append(
                Finding(
                    timestamp=ev.get("eventTime", ""),
                    severity="MEDIUM",
                    title="Sensitive S3 Object Access",
                    description=(
                        f"User '{user}' downloaded '{key}' from sensitive "
                        f"bucket '{bucket}' (IP: {ip})."
                    ),
                    user=user,
                    source_ip=ip,
                    event_name=name,
                    event_source=ev.get("eventSource", ""),
                    region=ev.get("awsRegion", ""),
                    mitre=MITRE_MAP.get("GetObject", {}),
                    raw_event=ev,
                )
            )

    def _check_security_group(self, ev):
        if ev.get("eventName") != "AuthorizeSecurityGroupIngress":
            return
        if not _cidr_is_open(ev):
            return
        user = _get_username(ev)
        ip = _get_source_ip(ev)
        params = ev.get("requestParameters", {}) or {}
        sg = params.get("groupId", "N/A")
        perms = params.get("ipPermissions", {}).get("items", [])
        ports = []
        for p in perms:
            proto = p.get("ipProtocol", "tcp")
            if proto == "-1":
                ports.append("ALL TRAFFIC")
            else:
                fr = p.get("fromPort", "?")
                to = p.get("toPort", "?")
                ports.append(f"{proto}/{fr}-{to}" if fr != to else f"{proto}/{fr}")

        self.findings.append(
            Finding(
                timestamp=ev.get("eventTime", ""),
                severity="HIGH",
                title="Security Group Opened to 0.0.0.0/0",
                description=(
                    f"User '{user}' opened security group {sg} to the "
                    f"internet (0.0.0.0/0) on ports [{', '.join(ports)}] "
                    f"from {ip}."
                ),
                user=user,
                source_ip=ip,
                event_name="AuthorizeSecurityGroupIngress",
                event_source=ev.get("eventSource", ""),
                region=ev.get("awsRegion", ""),
                mitre=MITRE_MAP.get("AuthorizeSecurityGroupIngress", {}),
                raw_event=ev,
            )
        )

    def _check_cloudtrail_tampering(self, ev):
        tamper_actions = {"StopLogging", "DeleteTrail", "UpdateTrail"}
        name = ev.get("eventName", "")
        if name not in tamper_actions:
            return
        user = _get_username(ev)
        ip = _get_source_ip(ev)
        params = ev.get("requestParameters", {}) or {}
        trail = params.get("name", params.get("trailName", "N/A"))
        extra = ""
        if name == "UpdateTrail":
            if params.get("isMultiRegionTrail") is False:
                extra = " Multi-region logging was DISABLED."
            if params.get("enableLogFileValidation") is False:
                extra += " Log file validation was DISABLED."
        self.findings.append(
            Finding(
                timestamp=ev.get("eventTime", ""),
                severity="HIGH",
                title=f"CloudTrail Tampering: {name}",
                description=(
                    f"User '{user}' called {name} on trail '{trail}' "
                    f"from {ip}.{extra} This is a strong indicator of "
                    f"defense evasion."
                ),
                user=user,
                source_ip=ip,
                event_name=name,
                event_source=ev.get("eventSource", ""),
                region=ev.get("awsRegion", ""),
                mitre=MITRE_MAP.get(name, {}),
                raw_event=ev,
            )
        )

    def _check_ec2_suspicious(self, ev):
        name = ev.get("eventName", "")
        if _is_aws_service(ev):
            return

        if name == "RunInstances":
            user = _get_username(ev)
            ip = _get_source_ip(ev)
            params = ev.get("requestParameters", {}) or {}
            items = params.get("instancesSet", {}).get("items", [{}])
            itype = items[0].get("instanceType", "unknown") if items else "unknown"
            count = items[0].get("maxCount", 1) if items else 1
            region = ev.get("awsRegion", "")

            gpu_types = re.compile(r"^(p[2-5]|g[3-5]|inf|trn|dl)", re.IGNORECASE)
            severity = "MEDIUM"
            note = ""
            if gpu_types.match(itype):
                severity = "HIGH"
                note = " GPU/accelerated instance type is a strong crypto-mining indicator."
            if int(count) >= 4:
                severity = "HIGH"
                note += f" Launching {count} instances simultaneously."

            self.findings.append(
                Finding(
                    timestamp=ev.get("eventTime", ""),
                    severity=severity,
                    title=f"EC2 Instance Launch: {itype} x{count}",
                    description=(
                        f"User '{user}' launched {count}x {itype} in "
                        f"{region} from {ip}.{note}"
                    ),
                    user=user,
                    source_ip=ip,
                    event_name=name,
                    event_source=ev.get("eventSource", ""),
                    region=region,
                    mitre=MITRE_MAP.get("RunInstances", {}),
                    raw_event=ev,
                )
            )

        if name == "CreateKeyPair":
            user = _get_username(ev)
            ip = _get_source_ip(ev)
            params = ev.get("requestParameters", {}) or {}
            kname = params.get("keyName", "N/A")
            self.findings.append(
                Finding(
                    timestamp=ev.get("eventTime", ""),
                    severity="MEDIUM",
                    title=f"EC2 Key Pair Created: {kname}",
                    description=(
                        f"User '{user}' created SSH key pair '{kname}' from {ip}. "
                        f"This could establish persistent SSH access to EC2 instances."
                    ),
                    user=user,
                    source_ip=ip,
                    event_name=name,
                    event_source=ev.get("eventSource", ""),
                    region=ev.get("awsRegion", ""),
                    mitre=MITRE_MAP.get("CreateKeyPair", {}),
                    raw_event=ev,
                )
            )

        if name == "ModifyInstanceAttribute":
            user = _get_username(ev)
            ip = _get_source_ip(ev)
            params = ev.get("requestParameters", {}) or {}
            iid = params.get("instanceId", "N/A")
            dat = params.get("disableApiTermination", {})
            if dat and dat.get("value") is True:
                self.findings.append(
                    Finding(
                        timestamp=ev.get("eventTime", ""),
                        severity="MEDIUM",
                        title="Termination Protection Enabled",
                        description=(
                            f"User '{user}' enabled termination protection on "
                            f"{iid} from {ip}. Attackers use this to prevent "
                            f"defenders from shutting down rogue instances."
                        ),
                        user=user,
                        source_ip=ip,
                        event_name=name,
                        event_source=ev.get("eventSource", ""),
                        region=ev.get("awsRegion", ""),
                        mitre=MITRE_MAP.get("ModifyInstanceAttribute", {}),
                        raw_event=ev,
                    )
                )

    def _check_credential_abuse(self, ev):
        name = ev.get("eventName", "")
        if name != "AssumeRole":
            return
        if _is_aws_service(ev):
            return
        user = _get_username(ev)
        ip = _get_source_ip(ev)
        params = ev.get("requestParameters", {}) or {}
        role_arn = params.get("roleArn", "N/A")
        resp = ev.get("responseElements", {}) or {}
        assumed = resp.get("assumedRoleUser", {}).get("arn", "")

        severity = "LOW"
        note = ""
        # Cross-account detection
        uid_acct = ev.get("userIdentity", {}).get("accountId", "")
        role_acct_match = re.search(r":(\d{12}):", role_arn)
        if role_acct_match:
            role_acct = role_acct_match.group(1)
            if uid_acct and role_acct != uid_acct:
                severity = "HIGH"
                note = (
                    f" CROSS-ACCOUNT: user from {uid_acct} assumed role in "
                    f"{role_acct}."
                )

        self.findings.append(
            Finding(
                timestamp=ev.get("eventTime", ""),
                severity=severity,
                title="AssumeRole Call",
                description=(
                    f"User '{user}' assumed role '{role_arn}' from {ip}.{note}"
                ),
                user=user,
                source_ip=ip,
                event_name=name,
                event_source=ev.get("eventSource", ""),
                region=ev.get("awsRegion", ""),
                mitre=MITRE_MAP.get("AssumeRole", {}),
                raw_event=ev,
            )
        )

    def _check_guardduty_disable(self, ev):
        name = ev.get("eventName", "")
        if name not in ("DeleteDetector", "DisassociateMembers", "DeleteMembers"):
            return
        user = _get_username(ev)
        ip = _get_source_ip(ev)
        self.findings.append(
            Finding(
                timestamp=ev.get("eventTime", ""),
                severity="HIGH",
                title=f"GuardDuty Disabled: {name}",
                description=(
                    f"User '{user}' called {name} from {ip}. "
                    f"Disabling GuardDuty removes automated threat detection."
                ),
                user=user,
                source_ip=ip,
                event_name=name,
                event_source=ev.get("eventSource", ""),
                region=ev.get("awsRegion", ""),
                mitre=MITRE_MAP.get("DeleteDetector", {}),
                raw_event=ev,
            )
        )

    # -- Run all checks ---------------------------------------------------

    def analyze(self):
        """Run every detection rule against all loaded events."""
        for ev in self.events:
            self._check_console_login(ev)
            self._check_iam_changes(ev)
            self._check_s3_changes(ev)
            self._check_security_group(ev)
            self._check_cloudtrail_tampering(ev)
            self._check_ec2_suspicious(ev)
            self._check_credential_abuse(ev)
            self._check_guardduty_disable(ev)

        # Sort findings chronologically
        self.findings.sort(key=lambda f: f.timestamp)

    # -- Reporting --------------------------------------------------------

    def build_timeline(self):
        """Return all loaded events sorted by time."""
        return sorted(self.events, key=lambda e: e.get("eventTime", ""))

    def get_findings(self, severity_filter=None):
        if severity_filter:
            sev = severity_filter.upper()
            return [f for f in self.findings if f.severity == sev]
        return self.findings

    def summary_stats(self):
        sev_counts = collections.Counter(f.severity for f in self.findings)
        user_counts = collections.Counter(f.user for f in self.findings)
        ip_counts = collections.Counter(f.source_ip for f in self.findings)
        tactic_counts = collections.Counter(
            f.mitre.get("tactic", "Unknown") for f in self.findings if f.mitre
        )
        return {
            "total_events": len(self.events),
            "total_findings": len(self.findings),
            "files_processed": self.files_processed,
            "severity_breakdown": dict(sev_counts),
            "top_users": dict(user_counts.most_common(10)),
            "top_source_ips": dict(ip_counts.most_common(10)),
            "mitre_tactics": dict(tactic_counts),
        }

    # -- Output formatters ------------------------------------------------

    def print_text_report(self, severity_filter=None):
        findings = self.get_findings(severity_filter)
        stats = self.summary_stats()

        width = 78
        print("=" * width)
        print("  CLOUDTRAIL SECURITY ANALYSIS REPORT".center(width))
        print("=" * width)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        print(f"  Generated : {now_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"  Files     : {stats['files_processed']}")
        print(f"  Events    : {stats['total_events']}")
        print(f"  Findings  : {stats['total_findings']}")
        if severity_filter:
            print(f"  Filter    : {severity_filter.upper()} only ({len(findings)} shown)")
        print("-" * width)

        # Severity breakdown
        print("\n  SEVERITY BREAKDOWN")
        print("  " + "-" * 30)
        for sev in ("HIGH", "MEDIUM", "LOW"):
            cnt = stats["severity_breakdown"].get(sev, 0)
            bar = "#" * min(cnt, 40)
            print(f"  {sev:<8} {cnt:>4}  {bar}")

        # MITRE ATT&CK Tactics
        if stats["mitre_tactics"]:
            print("\n  MITRE ATT&CK TACTICS OBSERVED")
            print("  " + "-" * 40)
            for tactic, cnt in sorted(
                stats["mitre_tactics"].items(), key=lambda x: -x[1]
            ):
                print(f"  {tactic:<30} {cnt:>4}")

        # Top users
        print("\n  TOP USERS IN FINDINGS")
        print("  " + "-" * 40)
        for usr, cnt in sorted(stats["top_users"].items(), key=lambda x: -x[1]):
            print(f"  {usr:<35} {cnt:>4}")

        # Top source IPs
        print("\n  TOP SOURCE IPs")
        print("  " + "-" * 40)
        for ip, cnt in sorted(stats["top_source_ips"].items(), key=lambda x: -x[1]):
            print(f"  {ip:<35} {cnt:>4}")

        # Detailed findings
        print("\n" + "=" * width)
        print("  DETAILED FINDINGS")
        print("=" * width)

        for i, f in enumerate(findings, 1):
            sev_label = f"[{f.severity}]"
            print(f"\n--- Finding #{i} {sev_label} ---")
            print(f"  Time      : {f.timestamp}")
            print(f"  Title     : {f.title}")
            print(f"  User      : {f.user}")
            print(f"  Source IP : {f.source_ip}")
            print(f"  Region    : {f.region}")
            print(f"  API Call  : {f.event_source} / {f.event_name}")
            if f.mitre:
                print(f"  ATT&CK    : {f.mitre.get('tactic', 'N/A')} / {f.mitre.get('technique', 'N/A')}")
                if f.mitre.get("sub"):
                    print(f"              {f.mitre['sub']}")
            print(f"  Detail    : {f.description}")

        if not findings:
            print("\n  No findings matched the current filter.\n")

        print("\n" + "=" * width)
        print("  END OF REPORT")
        print("=" * width)

    def print_timeline(self, limit=50):
        """Print a chronological timeline of all events."""
        timeline = self.build_timeline()
        width = 78
        print("=" * width)
        print("  EVENT TIMELINE".center(width))
        print("=" * width)
        shown = timeline[:limit] if limit else timeline
        for ev in shown:
            ts = ev.get("eventTime", "N/A")
            name = ev.get("eventName", "N/A")
            user = _get_username(ev)
            ip = _get_source_ip(ev)
            src = ev.get("eventSource", "").replace(".amazonaws.com", "")
            ro = "R" if ev.get("readOnly", False) else "W"
            print(f"  {ts}  [{ro}] {src:>14}.{name:<35} {user:<20} {ip}")
        if len(timeline) > len(shown):
            print(f"\n  ... {len(timeline) - len(shown)} more events (use --timeline-limit to show more)")
        print("=" * width)

    def print_json_report(self, severity_filter=None):
        findings = self.get_findings(severity_filter)
        report = {
            "report_generated": datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": self.summary_stats(),
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(report, indent=2))


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Analyze AWS CloudTrail logs for suspicious activity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -d ./samples/
  %(prog)s -f samples/cloudtrail-attack.json --severity high
  %(prog)s -d ./samples/ --json
  %(prog)s -f samples/cloudtrail-attack.json --timeline
""",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "-d", "--directory", help="Directory containing CloudTrail JSON files"
    )
    source.add_argument("-f", "--file", help="Single CloudTrail JSON file")
    parser.add_argument(
        "--severity",
        choices=["high", "medium", "low"],
        help="Filter findings by severity",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )
    parser.add_argument(
        "--timeline", action="store_true", help="Print event timeline"
    )
    parser.add_argument(
        "--timeline-limit",
        type=int,
        default=100,
        help="Max events in timeline (default: 100, 0=all)",
    )

    args = parser.parse_args()

    analyzer = CloudTrailAnalyzer()

    if args.directory:
        if not os.path.isdir(args.directory):
            print(f"[!] Directory not found: {args.directory}", file=sys.stderr)
            sys.exit(1)
        analyzer.load_directory(args.directory)
    else:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        analyzer.load_file(args.file)

    if not analyzer.events:
        print("[!] No CloudTrail events found.", file=sys.stderr)
        sys.exit(1)

    analyzer.analyze()

    if args.timeline:
        analyzer.print_timeline(limit=args.timeline_limit)
        print()

    if args.json_output:
        analyzer.print_json_report(severity_filter=args.severity)
    else:
        analyzer.print_text_report(severity_filter=args.severity)


if __name__ == "__main__":
    main()
