#!/usr/bin/env python3
"""
Cloud IOC Detector
------------------
Analyzes AWS CloudTrail JSON logs for cloud-specific Indicators of Compromise
(IOCs).  Works entirely with local log files -- no AWS account required.

Detections:
  - Impossible travel (same user, different geo-regions, short time gap)
  - Off-hours API activity (configurable business-hours window)
  - Enumeration patterns (rapid discovery / recon calls)
  - Data exfiltration indicators (mass S3 GetObject calls)
  - Persistence mechanisms (new IAM users, roles, access keys)
  - Defense evasion (GuardDuty disabled, CloudTrail stopped, Config deleted)

Each user or session receives a cumulative risk score.  The tool outputs a
threat assessment report to stdout or JSON.

Usage:
    python3 cloud_ioc_detector.py -d /path/to/logs/
    python3 cloud_ioc_detector.py -f cloudtrail-attack.json
    python3 cloud_ioc_detector.py -d ./samples/ --business-hours 8-18
    python3 cloud_ioc_detector.py -f attack.json --json

Author:  Security Analyst Portfolio Project
License: MIT
"""

import argparse
import collections
import datetime
import json
import math
import os
import sys
import glob
import re

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Rough longitude centroids for AWS region geo-mapping (used for impossible
# travel heuristic).  We only need coarse distances.
REGION_GEO = {
    "us-east-1": (39.0, -77.5),       # N. Virginia
    "us-east-2": (40.0, -83.0),        # Ohio
    "us-west-1": (37.3, -121.9),       # N. California
    "us-west-2": (46.2, -122.8),       # Oregon
    "af-south-1": (-33.9, 18.4),       # Cape Town
    "ap-east-1": (22.3, 114.2),        # Hong Kong
    "ap-south-1": (19.1, 72.9),        # Mumbai
    "ap-south-2": (17.4, 78.5),        # Hyderabad
    "ap-southeast-1": (1.3, 103.8),    # Singapore
    "ap-southeast-2": (-33.9, 151.2),  # Sydney
    "ap-southeast-3": (-6.2, 106.8),   # Jakarta
    "ap-northeast-1": (35.7, 139.7),   # Tokyo
    "ap-northeast-2": (37.6, 127.0),   # Seoul
    "ap-northeast-3": (34.7, 135.5),   # Osaka
    "ca-central-1": (45.5, -73.6),     # Canada
    "eu-central-1": (50.1, 8.7),       # Frankfurt
    "eu-central-2": (47.4, 8.5),       # Zurich
    "eu-west-1": (53.3, -6.3),         # Ireland
    "eu-west-2": (51.5, -0.1),         # London
    "eu-west-3": (48.9, 2.3),          # Paris
    "eu-south-1": (45.5, 9.2),         # Milan
    "eu-south-2": (40.4, -3.7),        # Spain
    "eu-north-1": (59.3, 18.1),        # Stockholm
    "il-central-1": (32.1, 34.8),      # Tel Aviv
    "me-south-1": (26.1, 50.5),        # Bahrain
    "me-central-1": (24.5, 54.7),      # UAE
    "sa-east-1": (-23.5, -46.6),       # Sao Paulo
}

ENUMERATION_CALLS = {
    "ListBuckets",
    "ListUsers",
    "ListRoles",
    "ListGroups",
    "ListPolicies",
    "DescribeInstances",
    "DescribeSecurityGroups",
    "DescribeSubnets",
    "DescribeVpcs",
    "DescribeRegions",
    "DescribeImages",
    "DescribeKeyPairs",
    "DescribeDBInstances",
    "GetCallerIdentity",
    "GetAccountAuthorizationDetails",
    "GetAccountSummary",
    "ListAttachedUserPolicies",
    "ListInstanceTypeOfferings",
    "DescribeInstanceTypeOfferings",
    "ListFunctions20150331",
    "DescribeAlarms",
}

PERSISTENCE_CALLS = {
    "CreateUser",
    "CreateRole",
    "CreateAccessKey",
    "CreateLoginProfile",
    "PutUserPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreateKeyPair",
}

DEFENSE_EVASION_CALLS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "DeleteDetector",           # GuardDuty
    "DisassociateMembers",      # GuardDuty
    "DeleteConfigRule",         # AWS Config
    "StopConfigurationRecorder",
    "DeleteFlowLogs",           # VPC Flow Logs
}

# Points assigned per IOC category
RISK_WEIGHTS = {
    "impossible_travel": 30,
    "off_hours": 5,
    "enumeration": 15,
    "exfiltration": 25,
    "persistence": 20,
    "defense_evasion": 30,
    "no_mfa_login": 15,
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _parse_time(ts):
    """Parse an ISO-8601 timestamp string into a datetime object."""
    # Handle fractional seconds if present
    ts = ts.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _get_username(event):
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


def _is_aws_service(event):
    uid = event.get("userIdentity", {})
    return uid.get("type") == "AWSService" or uid.get("invokedBy", "").endswith(
        ".amazonaws.com"
    )


def _haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points in km."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ---------------------------------------------------------------------------
# IOC data structure
# ---------------------------------------------------------------------------

class IOC:
    __slots__ = ("category", "severity", "title", "detail", "user",
                 "timestamp", "risk_points", "events")

    def __init__(self, category, severity, title, detail, user, timestamp,
                 risk_points, events=None):
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.user = user
        self.timestamp = timestamp
        self.risk_points = risk_points
        self.events = events or []

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "user": self.user,
            "timestamp": self.timestamp,
            "risk_points": self.risk_points,
        }


# ---------------------------------------------------------------------------
# IOC Detection Engine
# ---------------------------------------------------------------------------

class CloudIOCDetector:
    def __init__(self, business_hours_start=8, business_hours_end=18,
                 enum_threshold=5, enum_window_minutes=10,
                 exfil_threshold=5, exfil_window_minutes=10,
                 travel_max_minutes=60):
        self.events = []
        self.iocs = []
        self.files_processed = 0

        # Configurable thresholds
        self.bh_start = business_hours_start
        self.bh_end = business_hours_end
        self.enum_threshold = enum_threshold
        self.enum_window = datetime.timedelta(minutes=enum_window_minutes)
        self.exfil_threshold = exfil_threshold
        self.exfil_window = datetime.timedelta(minutes=exfil_window_minutes)
        self.travel_max = datetime.timedelta(minutes=travel_max_minutes)

    # -- Loading ----------------------------------------------------------

    def load_file(self, filepath):
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

    # -- Detection methods ------------------------------------------------

    def _detect_impossible_travel(self):
        """Detect same user appearing in geographically distant AWS regions
        within a short time window."""
        user_events = collections.defaultdict(list)
        for ev in self.events:
            if _is_aws_service(ev):
                continue
            user = _get_username(ev)
            region = ev.get("awsRegion", "")
            ts = _parse_time(ev.get("eventTime", ""))
            if ts and region:
                user_events[user].append((ts, region, ev))

        for user, entries in user_events.items():
            entries.sort(key=lambda x: x[0])
            for i in range(1, len(entries)):
                ts_prev, reg_prev, ev_prev = entries[i - 1]
                ts_curr, reg_curr, ev_curr = entries[i]
                if reg_prev == reg_curr:
                    continue
                geo_prev = REGION_GEO.get(reg_prev)
                geo_curr = REGION_GEO.get(reg_curr)
                if not geo_prev or not geo_curr:
                    continue
                dist = _haversine_km(*geo_prev, *geo_curr)
                delta = ts_curr - ts_prev
                if delta <= self.travel_max and dist > 1000:
                    self.iocs.append(IOC(
                        category="impossible_travel",
                        severity="HIGH",
                        title="Impossible Travel Detected",
                        detail=(
                            f"User '{user}' was active in {reg_prev} at "
                            f"{ts_prev.isoformat()}Z and {reg_curr} at "
                            f"{ts_curr.isoformat()}Z ({delta} apart, "
                            f"~{int(dist)} km distance)."
                        ),
                        user=user,
                        timestamp=ts_curr.isoformat() + "Z",
                        risk_points=RISK_WEIGHTS["impossible_travel"],
                        events=[ev_prev, ev_curr],
                    ))

    def _detect_off_hours(self):
        """Flag API calls made outside configured business hours (UTC)."""
        user_offhours = collections.defaultdict(list)
        for ev in self.events:
            if _is_aws_service(ev):
                continue
            ts = _parse_time(ev.get("eventTime", ""))
            if not ts:
                continue
            if ts.hour < self.bh_start or ts.hour >= self.bh_end:
                user = _get_username(ev)
                user_offhours[user].append(ev)

        for user, evts in user_offhours.items():
            if len(evts) < 2:
                continue  # single off-hours event is not notable
            first_ts = min(
                e.get("eventTime", "") for e in evts
            )
            actions = list({e.get("eventName", "") for e in evts})
            self.iocs.append(IOC(
                category="off_hours",
                severity="MEDIUM" if len(evts) > 5 else "LOW",
                title="Off-Hours API Activity",
                detail=(
                    f"User '{user}' made {len(evts)} API calls outside "
                    f"business hours ({self.bh_start:02d}:00-{self.bh_end:02d}:00 UTC). "
                    f"Actions: {', '.join(actions[:8])}"
                    + (f" (and {len(actions)-8} more)" if len(actions) > 8 else "")
                ),
                user=user,
                timestamp=first_ts,
                risk_points=RISK_WEIGHTS["off_hours"] * min(len(evts), 5),
            ))

    def _detect_enumeration(self):
        """Detect rapid enumeration / discovery calls."""
        user_enum = collections.defaultdict(list)
        for ev in self.events:
            if _is_aws_service(ev):
                continue
            name = ev.get("eventName", "")
            if name in ENUMERATION_CALLS:
                user = _get_username(ev)
                ts = _parse_time(ev.get("eventTime", ""))
                if ts:
                    user_enum[user].append((ts, name, ev))

        for user, entries in user_enum.items():
            entries.sort(key=lambda x: x[0])
            # Sliding window check
            i = 0
            reported_windows = set()
            for j in range(len(entries)):
                while entries[j][0] - entries[i][0] > self.enum_window:
                    i += 1
                window_count = j - i + 1
                if window_count >= self.enum_threshold:
                    window_key = (user, entries[i][0].isoformat())
                    if window_key in reported_windows:
                        continue
                    reported_windows.add(window_key)
                    calls_in_window = [e[1] for e in entries[i:j + 1]]
                    unique_calls = list(dict.fromkeys(calls_in_window))
                    self.iocs.append(IOC(
                        category="enumeration",
                        severity="HIGH" if window_count >= 8 else "MEDIUM",
                        title="Rapid Enumeration Pattern",
                        detail=(
                            f"User '{user}' made {window_count} discovery/"
                            f"enumeration calls within "
                            f"{int(self.enum_window.total_seconds()//60)} min "
                            f"starting at {entries[i][0].isoformat()}Z. "
                            f"Calls: {', '.join(unique_calls)}"
                        ),
                        user=user,
                        timestamp=entries[i][0].isoformat() + "Z",
                        risk_points=RISK_WEIGHTS["enumeration"],
                    ))

    def _detect_exfiltration(self):
        """Detect mass S3 GetObject calls (data exfiltration indicator)."""
        user_gets = collections.defaultdict(list)
        for ev in self.events:
            if _is_aws_service(ev):
                continue
            if ev.get("eventName") == "GetObject":
                user = _get_username(ev)
                ts = _parse_time(ev.get("eventTime", ""))
                params = ev.get("requestParameters", {}) or {}
                bucket = params.get("bucketName", "unknown")
                key = params.get("key", "unknown")
                if ts:
                    user_gets[user].append((ts, bucket, key, ev))

        for user, entries in user_gets.items():
            entries.sort(key=lambda x: x[0])
            i = 0
            for j in range(len(entries)):
                while entries[j][0] - entries[i][0] > self.exfil_window:
                    i += 1
                window_count = j - i + 1
                if window_count >= self.exfil_threshold:
                    buckets = list({e[1] for e in entries[i:j + 1]})
                    keys = [e[2] for e in entries[i:j + 1]]
                    self.iocs.append(IOC(
                        category="exfiltration",
                        severity="HIGH",
                        title="Potential Data Exfiltration via S3",
                        detail=(
                            f"User '{user}' downloaded {window_count} objects "
                            f"from S3 within "
                            f"{int(self.exfil_window.total_seconds()//60)} min. "
                            f"Buckets: {', '.join(buckets)}. "
                            f"Sample keys: {', '.join(keys[:5])}"
                        ),
                        user=user,
                        timestamp=entries[i][0].isoformat() + "Z",
                        risk_points=RISK_WEIGHTS["exfiltration"],
                    ))
                    break  # one report per user is enough

    def _detect_persistence(self):
        """Detect creation of new IAM users, roles, access keys."""
        for ev in self.events:
            if _is_aws_service(ev):
                continue
            name = ev.get("eventName", "")
            if name not in PERSISTENCE_CALLS:
                continue
            user = _get_username(ev)
            ip = ev.get("sourceIPAddress", "N/A")
            params = ev.get("requestParameters", {}) or {}
            target = params.get("userName", params.get("roleName",
                       params.get("keyName", "N/A")))
            policy = params.get("policyArn", params.get("policyName", ""))

            sev = "MEDIUM"
            extra = ""
            if name in ("AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy"):
                if "AdministratorAccess" in str(policy):
                    sev = "HIGH"
                    extra = f" with AdministratorAccess"
                elif '"Action":"*"' in str(params.get("policyDocument", "")):
                    sev = "HIGH"
                    extra = " with full wildcard access (*:*)"

            if name in ("CreateUser", "CreateRole"):
                sev = "HIGH"

            self.iocs.append(IOC(
                category="persistence",
                severity=sev,
                title=f"Persistence: {name}",
                detail=(
                    f"User '{user}' ({ip}) performed {name} on "
                    f"'{target}'{extra}."
                ),
                user=user,
                timestamp=ev.get("eventTime", ""),
                risk_points=RISK_WEIGHTS["persistence"],
            ))

    def _detect_defense_evasion(self):
        """Detect disabling of security monitoring tools."""
        for ev in self.events:
            if _is_aws_service(ev):
                continue
            name = ev.get("eventName", "")
            if name not in DEFENSE_EVASION_CALLS:
                continue
            user = _get_username(ev)
            ip = ev.get("sourceIPAddress", "N/A")
            params = ev.get("requestParameters", {}) or {}

            details_extra = ""
            if name == "UpdateTrail":
                if params.get("isMultiRegionTrail") is False:
                    details_extra = " Disabled multi-region logging."
                if params.get("enableLogFileValidation") is False:
                    details_extra += " Disabled log validation."
                if not details_extra:
                    continue  # benign update

            src_service = ev.get("eventSource", "").replace(".amazonaws.com", "")

            self.iocs.append(IOC(
                category="defense_evasion",
                severity="HIGH",
                title=f"Defense Evasion: {name} ({src_service})",
                detail=(
                    f"User '{user}' ({ip}) called {name} to impair "
                    f"security monitoring.{details_extra}"
                ),
                user=user,
                timestamp=ev.get("eventTime", ""),
                risk_points=RISK_WEIGHTS["defense_evasion"],
            ))

    def _detect_no_mfa_login(self):
        """Detect console logins without MFA."""
        for ev in self.events:
            if ev.get("eventName") != "ConsoleLogin":
                continue
            resp = ev.get("responseElements", {}) or {}
            if resp.get("ConsoleLogin") != "Success":
                continue
            add = ev.get("additionalEventData", {}) or {}
            sess = ev.get("userIdentity", {}).get("sessionContext", {})
            attrs = sess.get("attributes", {})
            mfa_add = add.get("MFAUsed", "No")
            mfa_sess = str(attrs.get("mfaAuthenticated", "false")).lower()
            if mfa_add == "Yes" or mfa_sess == "true":
                continue
            user = _get_username(ev)
            ip = ev.get("sourceIPAddress", "N/A")
            self.iocs.append(IOC(
                category="no_mfa_login",
                severity="HIGH",
                title="Console Login Without MFA",
                detail=(
                    f"User '{user}' authenticated to the AWS Console from "
                    f"{ip} without MFA."
                ),
                user=user,
                timestamp=ev.get("eventTime", ""),
                risk_points=RISK_WEIGHTS["no_mfa_login"],
            ))

    # -- Run all ----------------------------------------------------------

    def analyze(self):
        self._detect_no_mfa_login()
        self._detect_impossible_travel()
        self._detect_off_hours()
        self._detect_enumeration()
        self._detect_exfiltration()
        self._detect_persistence()
        self._detect_defense_evasion()
        self.iocs.sort(key=lambda x: x.timestamp)

    # -- Scoring ----------------------------------------------------------

    def user_risk_scores(self):
        """Compute cumulative risk score per user."""
        scores = collections.defaultdict(lambda: {"score": 0, "categories": collections.Counter(), "ioc_count": 0})
        for ioc in self.iocs:
            scores[ioc.user]["score"] += ioc.risk_points
            scores[ioc.user]["categories"][ioc.category] += 1
            scores[ioc.user]["ioc_count"] += 1
        return dict(scores)

    def _risk_rating(self, score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    # -- Reporting --------------------------------------------------------

    def print_text_report(self):
        scores = self.user_risk_scores()
        width = 78

        print("=" * width)
        print("  CLOUD IOC THREAT ASSESSMENT REPORT".center(width))
        print("=" * width)
        print(f"  Generated    : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"  Files        : {self.files_processed}")
        print(f"  Total Events : {len(self.events)}")
        print(f"  IOCs Found   : {len(self.iocs)}")
        print(f"  Biz Hours    : {self.bh_start:02d}:00 - {self.bh_end:02d}:00 UTC")
        print("-" * width)

        # -- User Risk Scores ---------------------------------------------
        print("\n  USER / SESSION RISK SCORES")
        print("  " + "-" * 60)
        print(f"  {'USER':<30} {'SCORE':>6}  {'RATING':<10} {'IOCs':>5}")
        print("  " + "-" * 60)

        sorted_users = sorted(scores.items(), key=lambda x: -x[1]["score"])
        for user, data in sorted_users:
            rating = self._risk_rating(data["score"])
            bar = "#" * min(data["score"] // 5, 20)
            print(f"  {user:<30} {data['score']:>6}  {rating:<10} {data['ioc_count']:>5}  {bar}")

        # -- Category Breakdown -------------------------------------------
        cat_counts = collections.Counter()
        cat_sev = collections.defaultdict(lambda: collections.Counter())
        for ioc in self.iocs:
            cat_counts[ioc.category] += 1
            cat_sev[ioc.category][ioc.severity] += 1

        print("\n  IOC CATEGORY BREAKDOWN")
        print("  " + "-" * 55)
        print(f"  {'CATEGORY':<25} {'COUNT':>5}  {'HIGH':>5} {'MED':>5} {'LOW':>5}")
        print("  " + "-" * 55)
        for cat, cnt in cat_counts.most_common():
            h = cat_sev[cat].get("HIGH", 0)
            m = cat_sev[cat].get("MEDIUM", 0)
            lo = cat_sev[cat].get("LOW", 0)
            label = cat.replace("_", " ").title()
            print(f"  {label:<25} {cnt:>5}  {h:>5} {m:>5} {lo:>5}")

        # -- Detailed IOCs ------------------------------------------------
        print("\n" + "=" * width)
        print("  DETAILED INDICATORS OF COMPROMISE")
        print("=" * width)

        for i, ioc in enumerate(self.iocs, 1):
            print(f"\n--- IOC #{i} [{ioc.severity}] (risk +{ioc.risk_points}) ---")
            print(f"  Category  : {ioc.category.replace('_', ' ').title()}")
            print(f"  Time      : {ioc.timestamp}")
            print(f"  Title     : {ioc.title}")
            print(f"  User      : {ioc.user}")
            print(f"  Detail    : {ioc.detail}")

        if not self.iocs:
            print("\n  No IOCs detected in the analyzed logs.\n")

        # -- Recommendations based on highest-risk user -------------------
        print("\n" + "=" * width)
        print("  RECOMMENDED ACTIONS")
        print("=" * width)

        if sorted_users:
            top_user, top_data = sorted_users[0]
            rating = self._risk_rating(top_data["score"])
            print(f"\n  Highest-risk principal: {top_user} "
                  f"(score {top_data['score']}, rating {rating})")
            print()

            cats = top_data["categories"]
            if cats.get("no_mfa_login"):
                print("  [!] IMMEDIATE: Disable the compromised credentials")
                print("      aws iam update-login-profile --user-name <user> --password-reset-required")
                print("      aws iam deactivate-mfa-device (if attacker enrolled their own)")
            if cats.get("persistence"):
                print("  [!] IMMEDIATE: Audit and remove backdoor IAM entities")
                print("      aws iam list-access-keys --user-name <created-user>")
                print("      aws iam delete-access-key / delete-user")
            if cats.get("defense_evasion"):
                print("  [!] IMMEDIATE: Re-enable security monitoring")
                print("      aws cloudtrail start-logging --name <trail>")
                print("      aws guardduty create-detector --enable")
            if cats.get("exfiltration"):
                print("  [!] INVESTIGATE: Determine scope of data access")
                print("      Review S3 access logs for the affected buckets")
                print("      Check for external sharing or bucket policy changes")
            if cats.get("impossible_travel"):
                print("  [!] INVESTIGATE: Validate whether the user legitimately")
                print("      operated from multiple regions or if credentials were shared")
            if cats.get("enumeration"):
                print("  [!] INVESTIGATE: Reconnaissance activity may precede")
                print("      privilege escalation or lateral movement")
        else:
            print("\n  No high-risk principals identified.")

        print("\n" + "=" * width)
        print("  END OF REPORT")
        print("=" * width)

    def print_json_report(self):
        scores = self.user_risk_scores()
        user_summary = []
        for user, data in sorted(scores.items(), key=lambda x: -x[1]["score"]):
            user_summary.append({
                "user": user,
                "risk_score": data["score"],
                "risk_rating": self._risk_rating(data["score"]),
                "ioc_count": data["ioc_count"],
                "categories": dict(data["categories"]),
            })

        report = {
            "report_generated": datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_events": len(self.events),
            "total_iocs": len(self.iocs),
            "files_processed": self.files_processed,
            "user_risk_scores": user_summary,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
        }
        print(json.dumps(report, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect cloud-specific Indicators of Compromise in CloudTrail logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -d ./samples/
  %(prog)s -f samples/cloudtrail-attack.json
  %(prog)s -d ./samples/ --business-hours 9-17
  %(prog)s -f samples/cloudtrail-attack.json --json
""",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-d", "--directory",
                        help="Directory containing CloudTrail JSON files")
    source.add_argument("-f", "--file",
                        help="Single CloudTrail JSON file")
    parser.add_argument("--business-hours", default="8-18",
                        help="Business hours range in UTC, e.g. '8-18' (default: 8-18)")
    parser.add_argument("--enum-threshold", type=int, default=5,
                        help="Min enumeration calls to trigger alert (default: 5)")
    parser.add_argument("--enum-window", type=int, default=10,
                        help="Enumeration sliding window in minutes (default: 10)")
    parser.add_argument("--exfil-threshold", type=int, default=5,
                        help="Min S3 GetObject calls to flag exfil (default: 5)")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output as JSON")

    args = parser.parse_args()

    # Parse business hours
    try:
        bh_start, bh_end = [int(x) for x in args.business_hours.split("-")]
    except (ValueError, IndexError):
        print("[!] Invalid --business-hours format. Use 'START-END', e.g. '8-18'.",
              file=sys.stderr)
        sys.exit(1)

    detector = CloudIOCDetector(
        business_hours_start=bh_start,
        business_hours_end=bh_end,
        enum_threshold=args.enum_threshold,
        enum_window_minutes=args.enum_window,
        exfil_threshold=args.exfil_threshold,
    )

    if args.directory:
        if not os.path.isdir(args.directory):
            print(f"[!] Directory not found: {args.directory}", file=sys.stderr)
            sys.exit(1)
        detector.load_directory(args.directory)
    else:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        detector.load_file(args.file)

    if not detector.events:
        print("[!] No CloudTrail events found.", file=sys.stderr)
        sys.exit(1)

    detector.analyze()

    if args.json_output:
        detector.print_json_report()
    else:
        detector.print_text_report()


if __name__ == "__main__":
    main()
