#!/usr/bin/env python3
"""
S3 Bucket Security Scanner - Comprehensive S3 Security Assessment Tool

Evaluates every S3 bucket against security best practices: public access
controls, encryption at rest, versioning, logging, lifecycle rules, and
CORS configuration. Generates a per-bucket security score and overall
posture assessment.

Usage:
    python3 s3_bucket_scanner.py --demo               # Mock data scan
    python3 s3_bucket_scanner.py --profile prod        # Live scan
    python3 s3_bucket_scanner.py --demo -o report      # Save to file

Dependencies:
    - boto3 (pip install boto3)
    - Standard library only otherwise
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# ---------------------------------------------------------------------------
# Scoring - each check has a max score contribution
# ---------------------------------------------------------------------------
SCORE_WEIGHTS = {
    "block_public_access": 25,     # All four settings enabled
    "no_public_acl": 15,           # No public ACL grants
    "no_public_policy": 15,        # No public bucket policy
    "encryption_enabled": 15,      # Default encryption configured
    "encryption_kms": 5,           # Uses KMS rather than SSE-S3 (bonus)
    "versioning_enabled": 10,      # Versioning active
    "logging_enabled": 5,          # Server access logging on
    "lifecycle_rules": 5,          # At least one lifecycle rule
    "cors_restricted": 5,          # No wildcard CORS origin
}

MAX_SCORE = sum(SCORE_WEIGHTS.values())  # 100


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------
def generate_mock_s3_data():
    """Return realistic mock S3 bucket configurations."""
    now = datetime.now(timezone.utc)

    def ago(days):
        return (now - timedelta(days=days)).isoformat()

    return {
        "account_id": "123456789012",
        "buckets": [
            {
                "Name": "acme-prod-data-lake",
                "CreationDate": ago(365),
                "Region": "us-east-1",
                "BlockPublicAccess": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "ACL": {
                    "Grants": [
                        {"Grantee": {"Type": "CanonicalUser", "DisplayName": "acme-root"}, "Permission": "FULL_CONTROL"},
                    ],
                },
                "Policy": None,
                "Encryption": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
                        },
                        "BucketKeyEnabled": True,
                    }],
                },
                "Versioning": {"Status": "Enabled"},
                "Logging": {
                    "TargetBucket": "acme-access-logs",
                    "TargetPrefix": "data-lake/",
                },
                "LifecycleRules": [
                    {"ID": "archive-old-data", "Status": "Enabled",
                     "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}],
                     "Expiration": {"Days": 365}},
                ],
                "CORS": None,
                "ObjectCount": 2847593,
                "TotalSizeGB": 1842.7,
                "Tags": {"Environment": "production", "DataClass": "confidential"},
            },
            {
                "Name": "acme-website-assets",
                "CreationDate": ago(500),
                "Region": "us-east-1",
                "BlockPublicAccess": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "ACL": {
                    "Grants": [
                        {"Grantee": {"Type": "CanonicalUser", "DisplayName": "acme-root"}, "Permission": "FULL_CONTROL"},
                        {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"},
                    ],
                },
                "Policy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::acme-website-assets/*",
                    }],
                },
                "Encryption": None,
                "Versioning": {"Status": "Suspended"},
                "Logging": None,
                "LifecycleRules": [],
                "CORS": {
                    "CORSRules": [{
                        "AllowedOrigins": ["*"],
                        "AllowedMethods": ["GET", "HEAD"],
                        "AllowedHeaders": ["*"],
                        "MaxAgeSeconds": 3600,
                    }],
                },
                "ObjectCount": 15432,
                "TotalSizeGB": 28.3,
                "Tags": {"Environment": "production", "Purpose": "static-website"},
            },
            {
                "Name": "acme-cloudtrail-logs",
                "CreationDate": ago(300),
                "Region": "us-east-1",
                "BlockPublicAccess": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "ACL": {
                    "Grants": [
                        {"Grantee": {"Type": "CanonicalUser", "DisplayName": "acme-root"}, "Permission": "FULL_CONTROL"},
                    ],
                },
                "Policy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AWSCloudTrailAclCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::acme-cloudtrail-logs",
                    }, {
                        "Sid": "AWSCloudTrailWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::acme-cloudtrail-logs/AWSLogs/*",
                        "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                    }],
                },
                "Encryption": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                    }],
                },
                "Versioning": {"Status": "Enabled"},
                "Logging": {
                    "TargetBucket": "acme-access-logs",
                    "TargetPrefix": "cloudtrail-bucket/",
                },
                "LifecycleRules": [
                    {"ID": "expire-old-logs", "Status": "Enabled",
                     "Transitions": [{"Days": 90, "StorageClass": "GLACIER_IR"}],
                     "Expiration": {"Days": 2555}},
                ],
                "CORS": None,
                "ObjectCount": 9823456,
                "TotalSizeGB": 456.1,
                "Tags": {"Environment": "production", "DataClass": "audit-logs"},
            },
            {
                "Name": "acme-dev-scratch",
                "CreationDate": ago(45),
                "Region": "us-east-1",
                "BlockPublicAccess": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "ACL": {
                    "Grants": [
                        {"Grantee": {"Type": "CanonicalUser", "DisplayName": "acme-root"}, "Permission": "FULL_CONTROL"},
                    ],
                },
                "Policy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AllowDevAccess",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": "arn:aws:s3:::acme-dev-scratch/*",
                    }],
                },
                "Encryption": None,
                "Versioning": {"Status": None},
                "Logging": None,
                "LifecycleRules": [],
                "CORS": None,
                "ObjectCount": 342,
                "TotalSizeGB": 1.2,
                "Tags": {"Environment": "development"},
            },
            {
                "Name": "acme-backup-vault",
                "CreationDate": ago(400),
                "Region": "us-west-2",
                "BlockPublicAccess": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "ACL": {
                    "Grants": [
                        {"Grantee": {"Type": "CanonicalUser", "DisplayName": "acme-root"}, "Permission": "FULL_CONTROL"},
                    ],
                },
                "Policy": None,
                "Encryption": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-west-2:123456789012:key/backup-key-5678",
                        },
                    }],
                },
                "Versioning": {"Status": "Enabled"},
                "Logging": None,
                "LifecycleRules": [
                    {"ID": "deep-archive", "Status": "Enabled",
                     "Transitions": [{"Days": 30, "StorageClass": "DEEP_ARCHIVE"}]},
                ],
                "CORS": None,
                "ObjectCount": 584201,
                "TotalSizeGB": 3201.5,
                "Tags": {"Environment": "production", "DataClass": "backup", "CriticalData": "true"},
            },
            {
                "Name": "acme-public-datasets",
                "CreationDate": ago(200),
                "Region": "us-east-1",
                "BlockPublicAccess": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "ACL": {
                    "Grants": [
                        {"Grantee": {"Type": "CanonicalUser", "DisplayName": "acme-root"}, "Permission": "FULL_CONTROL"},
                    ],
                },
                "Policy": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "PublicReadOnly",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::acme-public-datasets/public/*",
                    }],
                },
                "Encryption": {
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                    }],
                },
                "Versioning": {"Status": "Enabled"},
                "Logging": {
                    "TargetBucket": "acme-access-logs",
                    "TargetPrefix": "public-datasets/",
                },
                "LifecycleRules": [],
                "CORS": {
                    "CORSRules": [{
                        "AllowedOrigins": ["https://acme.example.com", "https://data.acme.example.com"],
                        "AllowedMethods": ["GET"],
                        "AllowedHeaders": ["Authorization"],
                        "MaxAgeSeconds": 3600,
                    }],
                },
                "ObjectCount": 1205,
                "TotalSizeGB": 89.4,
                "Tags": {"Environment": "production", "DataClass": "public"},
            },
        ],
    }


# ---------------------------------------------------------------------------
# S3 Security Scanner
# ---------------------------------------------------------------------------
class S3BucketScanner:
    """Scans all S3 buckets and produces per-bucket security scores."""

    def __init__(self, session=None, demo=False):
        self.session = session
        self.demo = demo
        self.data = generate_mock_s3_data() if demo else None
        self.bucket_reports = []
        self.overall_stats = defaultdict(int)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def scan(self):
        """Scan all buckets."""
        print("\n[*] Starting S3 bucket security scan...")

        if self.demo:
            buckets = self.data["buckets"]
        else:
            s3 = self.session.client("s3")
            buckets = self._fetch_all_buckets(s3)

        for bucket in buckets:
            report = self._assess_bucket(bucket)
            self.bucket_reports.append(report)

        self.bucket_reports.sort(key=lambda r: r["security_score"])
        print(f"[+] Scanned {len(self.bucket_reports)} buckets")

    def _assess_bucket(self, bucket):
        """Evaluate a single bucket and produce a scored report."""
        name = bucket["Name"]
        score = 0
        findings = []
        checks = {}

        # --- Block Public Access ---
        bpa = bucket.get("BlockPublicAccess", {})
        all_blocked = all([
            bpa.get("BlockPublicAcls", False),
            bpa.get("IgnorePublicAcls", False),
            bpa.get("BlockPublicPolicy", False),
            bpa.get("RestrictPublicBuckets", False),
        ])
        if all_blocked:
            score += SCORE_WEIGHTS["block_public_access"]
            checks["block_public_access"] = {"status": "PASS", "points": SCORE_WEIGHTS["block_public_access"]}
        else:
            disabled = [k for k, v in bpa.items() if not v]
            checks["block_public_access"] = {"status": "FAIL", "points": 0}
            findings.append({
                "check_id": "S3-BPA-01",
                "severity": "HIGH",
                "title": "Block Public Access not fully enabled",
                "detail": f"Disabled settings: {', '.join(disabled)}",
                "remediation": f"aws s3api put-public-access-block --bucket {name} "
                               "--public-access-block-configuration "
                               "BlockPublicAcls=true,IgnorePublicAcls=true,"
                               "BlockPublicPolicy=true,RestrictPublicBuckets=true",
                "cis_ref": "CIS 2.1.5",
            })

        # --- Public ACL ---
        acl = bucket.get("ACL", {})
        has_public_acl = False
        public_acl_permissions = []
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                has_public_acl = True
                public_acl_permissions.append(f"{uri.split('/')[-1]}:{grant.get('Permission')}")

        if not has_public_acl:
            score += SCORE_WEIGHTS["no_public_acl"]
            checks["no_public_acl"] = {"status": "PASS", "points": SCORE_WEIGHTS["no_public_acl"]}
        else:
            checks["no_public_acl"] = {"status": "FAIL", "points": 0}
            sev = "CRITICAL" if any("WRITE" in p or "FULL_CONTROL" in p for p in public_acl_permissions) else "HIGH"
            findings.append({
                "check_id": "S3-ACL-01",
                "severity": sev,
                "title": "Bucket has public ACL grants",
                "detail": f"Public grants: {', '.join(public_acl_permissions)}",
                "remediation": f"aws s3api put-bucket-acl --bucket {name} --acl private",
                "cis_ref": "CIS 2.1.5",
            })

        # --- Public Bucket Policy ---
        policy = bucket.get("Policy")
        has_public_policy = False
        public_policy_actions = []
        is_write_public = False

        if policy:
            statements = policy.get("Statement", []) if isinstance(policy, dict) else []
            for stmt in statements:
                principal = stmt.get("Principal", "")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    # Check if it is a service principal (e.g. cloudtrail) - that is expected
                    if isinstance(principal, dict) and "Service" in principal:
                        continue
                    has_public_policy = True
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    public_policy_actions.extend(actions)
                    write_actions = {"s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy", "s3:*"}
                    if write_actions & set(actions):
                        is_write_public = True

        if not has_public_policy:
            score += SCORE_WEIGHTS["no_public_policy"]
            checks["no_public_policy"] = {"status": "PASS", "points": SCORE_WEIGHTS["no_public_policy"]}
        else:
            checks["no_public_policy"] = {"status": "FAIL", "points": 0}
            sev = "CRITICAL" if is_write_public else "HIGH"
            findings.append({
                "check_id": "S3-POL-01",
                "severity": sev,
                "title": "Bucket policy allows public access",
                "detail": f"Public actions: {', '.join(public_policy_actions)}"
                          f"{' (INCLUDES WRITE)' if is_write_public else ' (read-only)'}",
                "remediation": f"Review and restrict: aws s3api get-bucket-policy --bucket {name}",
            })

        # --- Encryption ---
        enc = bucket.get("Encryption")
        if enc and enc.get("Rules"):
            algo = enc["Rules"][0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
            score += SCORE_WEIGHTS["encryption_enabled"]
            checks["encryption_enabled"] = {"status": "PASS", "points": SCORE_WEIGHTS["encryption_enabled"],
                                            "algorithm": algo}
            if algo == "aws:kms":
                score += SCORE_WEIGHTS["encryption_kms"]
                checks["encryption_kms"] = {"status": "PASS", "points": SCORE_WEIGHTS["encryption_kms"]}
            else:
                checks["encryption_kms"] = {"status": "INFO", "points": 0,
                                            "detail": f"Using {algo} instead of KMS"}
        else:
            checks["encryption_enabled"] = {"status": "FAIL", "points": 0}
            checks["encryption_kms"] = {"status": "FAIL", "points": 0}
            findings.append({
                "check_id": "S3-ENC-01",
                "severity": "HIGH",
                "title": "Default encryption not enabled",
                "detail": "No server-side encryption configuration found",
                "remediation": f"aws s3api put-bucket-encryption --bucket {name} "
                               "--server-side-encryption-configuration "
                               "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
                "cis_ref": "CIS 2.1.1",
            })

        # --- Versioning ---
        versioning = bucket.get("Versioning", {})
        v_status = versioning.get("Status") if isinstance(versioning, dict) else versioning
        if v_status == "Enabled":
            score += SCORE_WEIGHTS["versioning_enabled"]
            checks["versioning_enabled"] = {"status": "PASS", "points": SCORE_WEIGHTS["versioning_enabled"]}
        else:
            checks["versioning_enabled"] = {"status": "FAIL", "points": 0}
            sev = "MEDIUM" if v_status == "Suspended" else "MEDIUM"
            findings.append({
                "check_id": "S3-VER-01",
                "severity": sev,
                "title": f"Versioning is {v_status or 'Disabled'}",
                "detail": f"Versioning status: {v_status or 'Never enabled'}",
                "remediation": f"aws s3api put-bucket-versioning --bucket {name} "
                               "--versioning-configuration Status=Enabled",
            })

        # --- Logging ---
        logging_config = bucket.get("Logging")
        if logging_config:
            score += SCORE_WEIGHTS["logging_enabled"]
            checks["logging_enabled"] = {"status": "PASS", "points": SCORE_WEIGHTS["logging_enabled"]}
        else:
            checks["logging_enabled"] = {"status": "FAIL", "points": 0}
            findings.append({
                "check_id": "S3-LOG-01",
                "severity": "LOW",
                "title": "Server access logging not enabled",
                "detail": "No access logging configuration found",
                "remediation": f"aws s3api put-bucket-logging --bucket {name} "
                               f"--bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"{name}/\"}}}}'",
            })

        # --- Lifecycle Rules ---
        lifecycle = bucket.get("LifecycleRules", [])
        active_rules = [r for r in lifecycle if r.get("Status") == "Enabled"]
        if active_rules:
            score += SCORE_WEIGHTS["lifecycle_rules"]
            checks["lifecycle_rules"] = {"status": "PASS", "points": SCORE_WEIGHTS["lifecycle_rules"],
                                         "rule_count": len(active_rules)}
        else:
            checks["lifecycle_rules"] = {"status": "FAIL", "points": 0}
            findings.append({
                "check_id": "S3-LCR-01",
                "severity": "LOW",
                "title": "No lifecycle rules configured",
                "detail": "Bucket has no active lifecycle rules for data management",
                "remediation": "Configure lifecycle rules to transition old objects to cheaper "
                               "storage classes or expire them.",
            })

        # --- CORS ---
        cors = bucket.get("CORS")
        if cors:
            cors_rules = cors.get("CORSRules", [])
            has_wildcard = any("*" in r.get("AllowedOrigins", []) for r in cors_rules)
            if has_wildcard:
                checks["cors_restricted"] = {"status": "FAIL", "points": 0}
                findings.append({
                    "check_id": "S3-CORS-01",
                    "severity": "MEDIUM",
                    "title": "CORS allows wildcard origin (*)",
                    "detail": "AllowedOrigins includes '*', allowing any website to make "
                              "cross-origin requests to this bucket",
                    "remediation": "Restrict AllowedOrigins to specific domains.",
                })
            else:
                score += SCORE_WEIGHTS["cors_restricted"]
                checks["cors_restricted"] = {"status": "PASS", "points": SCORE_WEIGHTS["cors_restricted"]}
        else:
            # No CORS = fine (restrictive by default)
            score += SCORE_WEIGHTS["cors_restricted"]
            checks["cors_restricted"] = {"status": "PASS", "points": SCORE_WEIGHTS["cors_restricted"],
                                         "detail": "No CORS configuration (default deny)"}

        # Grade
        pct = round((score / MAX_SCORE) * 100)
        if pct >= 90:
            grade = "A"
        elif pct >= 75:
            grade = "B"
        elif pct >= 60:
            grade = "C"
        elif pct >= 40:
            grade = "D"
        else:
            grade = "F"

        tags = bucket.get("Tags", {})

        report = {
            "bucket_name": name,
            "arn": f"arn:aws:s3:::{name}",
            "region": bucket.get("Region", "unknown"),
            "creation_date": bucket.get("CreationDate", ""),
            "object_count": bucket.get("ObjectCount", "N/A"),
            "total_size_gb": bucket.get("TotalSizeGB", "N/A"),
            "tags": tags,
            "security_score": score,
            "max_score": MAX_SCORE,
            "score_pct": pct,
            "grade": grade,
            "checks": checks,
            "finding_count": len(findings),
            "findings": findings,
            "is_public": has_public_acl or has_public_policy,
        }

        # Track stats
        self.overall_stats["total"] += 1
        self.overall_stats[f"grade_{grade}"] += 1
        if has_public_acl or has_public_policy:
            self.overall_stats["public_buckets"] += 1
        if not enc:
            self.overall_stats["unencrypted"] += 1

        return report

    # ------------------------------------------------------------------
    # Live mode helpers
    # ------------------------------------------------------------------
    def _fetch_all_buckets(self, s3):
        """Fetch and enrich all bucket configurations from a live account."""
        result = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            info = {
                "Name": name,
                "CreationDate": b["CreationDate"].isoformat() if hasattr(b["CreationDate"], "isoformat") else str(b["CreationDate"]),
                "BlockPublicAccess": {},
                "ACL": {"Grants": []},
                "Policy": None,
                "Encryption": None,
                "Versioning": {},
                "Logging": None,
                "LifecycleRules": [],
                "CORS": None,
                "Tags": {},
            }

            # Region
            try:
                loc = s3.get_bucket_location(Bucket=name)
                info["Region"] = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                info["Region"] = "unknown"

            # Block Public Access
            try:
                pab = s3.get_public_access_block(Bucket=name)
                info["BlockPublicAccess"] = pab.get("PublicAccessBlockConfiguration", {})
            except ClientError:
                info["BlockPublicAccess"] = {
                    "BlockPublicAcls": False, "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
                }

            # ACL
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                info["ACL"] = {"Grants": acl.get("Grants", [])}
            except ClientError:
                pass

            # Bucket Policy
            try:
                pol = s3.get_bucket_policy(Bucket=name)
                info["Policy"] = json.loads(pol["Policy"])
            except ClientError:
                pass

            # Encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                info["Encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
            except ClientError:
                pass

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                info["Versioning"] = {"Status": ver.get("Status")}
            except ClientError:
                pass

            # Logging
            try:
                log = s3.get_bucket_logging(Bucket=name)
                le = log.get("LoggingEnabled")
                info["Logging"] = le if le else None
            except ClientError:
                pass

            # Lifecycle
            try:
                lc = s3.get_bucket_lifecycle_configuration(Bucket=name)
                info["LifecycleRules"] = lc.get("Rules", [])
            except ClientError:
                pass

            # CORS
            try:
                cors = s3.get_bucket_cors(Bucket=name)
                info["CORS"] = {"CORSRules": cors.get("CORSRules", [])}
            except ClientError:
                pass

            # Tags
            try:
                tag_resp = s3.get_bucket_tagging(Bucket=name)
                info["Tags"] = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}
            except ClientError:
                pass

            result.append(info)
        return result

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def print_report(self):
        """Print human-readable scan results."""
        print("\n" + "=" * 76)
        print("  S3 BUCKET SECURITY SCAN RESULTS")
        print("=" * 76)
        print(f"  Timestamp   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Mode        : {'Demo (mock data)' if self.demo else 'Live'}")
        print(f"  Buckets     : {self.overall_stats.get('total', 0)}")
        print(f"  Public      : {self.overall_stats.get('public_buckets', 0)}")
        print(f"  Unencrypted : {self.overall_stats.get('unencrypted', 0)}")

        # Grade distribution
        print("\n  Grade Distribution:")
        for grade in ["A", "B", "C", "D", "F"]:
            count = self.overall_stats.get(f"grade_{grade}", 0)
            bar = "#" * count
            print(f"    {grade}: {count:3d}  {bar}")

        # Scorecard table
        print("\n" + "-" * 76)
        print("  BUCKET SECURITY SCORECARD")
        print("-" * 76)
        print(f"  {'Bucket':<30s} {'Region':<12s} {'Score':<8s} {'Grade':<6s} {'Public':<8s} {'Issues':<6s}")
        print(f"  {'-'*29:<30s} {'-'*11:<12s} {'-'*7:<8s} {'-'*5:<6s} {'-'*7:<8s} {'-'*5:<6s}")

        for r in self.bucket_reports:
            pub = "YES" if r["is_public"] else "no"
            score_str = f"{r['security_score']}/{r['max_score']}"
            print(f"  {r['bucket_name']:<30s} {r['region']:<12s} "
                  f"{score_str:<8s} {r['grade']:<6s} "
                  f"{pub:<8s} {r['finding_count']:<6d}")

        # Detailed per-bucket findings
        print("\n" + "-" * 76)
        print("  DETAILED FINDINGS")
        print("-" * 76)

        for r in self.bucket_reports:
            if not r["findings"]:
                continue

            print(f"\n  Bucket: {r['bucket_name']}")
            print(f"  ARN:    {r['arn']}")
            print(f"  Region: {r['region']} | Score: {r['security_score']}/{r['max_score']} ({r['score_pct']}%) | Grade: {r['grade']}")
            if r.get("object_count") != "N/A":
                print(f"  Size:   ~{r['total_size_gb']} GB ({r['object_count']:,} objects)")
            if r.get("tags"):
                tag_str = ", ".join(f"{k}={v}" for k, v in r["tags"].items())
                print(f"  Tags:   {tag_str}")
            print()

            # Check results
            print(f"  {'Check':<28s} {'Status':<8s} {'Points':<8s}")
            print(f"  {'-'*27:<28s} {'-'*7:<8s} {'-'*7:<8s}")
            for check_name, check_result in r["checks"].items():
                status = check_result["status"]
                points = check_result["points"]
                max_pts = SCORE_WEIGHTS.get(check_name, "?")
                print(f"  {check_name:<28s} {status:<8s} {points}/{max_pts}")

            print()
            for f in r["findings"]:
                marker = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "* ", "LOW": "- "}.get(f["severity"], "  ")
                print(f"    [{marker}] [{f['severity']}] {f['title']}")
                print(f"         {f['detail']}")
                if f.get("cis_ref"):
                    print(f"         CIS: {f['cis_ref']}")
                print(f"         Fix: {f['remediation']}")

        # Public bucket warning
        public = [r for r in self.bucket_reports if r["is_public"]]
        if public:
            print("\n" + "!" * 76)
            print(f"  WARNING: {len(public)} PUBLICLY ACCESSIBLE BUCKET(S) DETECTED")
            for r in public:
                print(f"    - {r['bucket_name']} (grade: {r['grade']})")
            print("!" * 76)

        print("\n" + "=" * 76)

    def save_report(self, output_prefix):
        """Save JSON report."""
        report = {
            "metadata": {
                "tool": "S3 Bucket Security Scanner",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": "demo" if self.demo else "live",
            },
            "summary": {
                "total_buckets": self.overall_stats.get("total", 0),
                "public_buckets": self.overall_stats.get("public_buckets", 0),
                "unencrypted_buckets": self.overall_stats.get("unencrypted", 0),
                "grade_distribution": {
                    g: self.overall_stats.get(f"grade_{g}", 0)
                    for g in ["A", "B", "C", "D", "F"]
                },
                "average_score_pct": round(
                    sum(r["score_pct"] for r in self.bucket_reports) / len(self.bucket_reports)
                ) if self.bucket_reports else 0,
            },
            "bucket_reports": self.bucket_reports,
        }

        path = f"{output_prefix}-s3-scan.json"
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\n[+] Report saved to {path}")


# ===================================================================
# Main
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description="S3 Bucket Security Scanner - Per-bucket security scoring and assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo                          Scan mock buckets
  %(prog)s --demo -o /tmp/audit            Save to /tmp/audit-s3-scan.json
  %(prog)s --profile prod                  Scan a live AWS account
        """,
    )
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--output", "-o", help="Output file prefix for JSON report")
    parser.add_argument("--demo", action="store_true",
                        help="Run with mock data (no AWS credentials needed)")
    args = parser.parse_args()

    print("=" * 76)
    print("  S3 Bucket Security Scanner v1.0")
    print("  Comprehensive S3 Security Assessment")
    print("=" * 76)

    session = None
    if not args.demo:
        if not BOTO3_AVAILABLE:
            print("\n[!] boto3 is not installed. Install with: pip install boto3")
            print("    Or run with --demo for mock data.")
            sys.exit(1)
        try:
            kwargs = {}
            if args.profile:
                kwargs["profile_name"] = args.profile
            if args.region:
                kwargs["region_name"] = args.region
            session = boto3.Session(**kwargs)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            print(f"\n[*] Account: {identity['Account']} | Identity: {identity['Arn']}")
        except Exception as e:
            print(f"\n[!] AWS error: {e}")
            print("    Run with --demo for mock data.")
            sys.exit(1)
    else:
        print("\n[*] Running in DEMO mode with mock data")

    scanner = S3BucketScanner(session=session, demo=args.demo)
    scanner.scan()
    scanner.print_report()

    if args.output:
        scanner.save_report(args.output)
    elif args.demo:
        scanner.save_report("demo")


if __name__ == "__main__":
    main()
