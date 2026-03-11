#!/usr/bin/env python3
"""
IAM Analyzer - Focused AWS IAM Security Analysis Tool

Performs deep analysis of IAM users, policies, and access patterns. Generates
a risk-scored report identifying overly permissive access, stale credentials,
missing MFA, and policy governance issues.

Usage:
    python3 iam_analyzer.py --demo                    # Run with mock data
    python3 iam_analyzer.py --profile prod -o report   # Live analysis, save report

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
# Risk scoring weights
# ---------------------------------------------------------------------------
RISK_WEIGHTS = {
    "no_mfa_console_user": 30,
    "admin_access": 25,
    "power_user_access": 15,
    "wildcard_action_policy": 20,
    "no_policy_condition": 5,
    "access_key_over_90d": 15,
    "access_key_over_365d": 30,
    "multiple_active_keys": 10,
    "no_recent_login_90d": 10,
    "inline_policy_present": 5,
    "not_in_any_group": 10,
    "service_account_with_admin": 35,
    "service_account_no_boundary": 10,
}

RISK_THRESHOLDS = {
    "CRITICAL": 60,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 1,
    "PASS": 0,
}


# ---------------------------------------------------------------------------
# Mock data for demo mode
# ---------------------------------------------------------------------------
def generate_mock_iam_data():
    """Generate realistic mock IAM environment data."""
    now = datetime.now(timezone.utc)

    def ago(days):
        return (now - timedelta(days=days)).isoformat()

    return {
        "account_id": "123456789012",
        "account_alias": "acme-production",
        "password_policy": {
            "MinimumPasswordLength": 8,
            "RequireSymbols": False,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": False,
            "RequireLowercaseCharacters": True,
            "AllowUsersToChangePassword": True,
            "MaxPasswordAge": 0,
            "PasswordReusePrevention": 0,
            "HardExpiry": False,
        },
        "users": [
            {
                "UserName": "admin-jsmith",
                "Arn": "arn:aws:iam::123456789012:user/admin-jsmith",
                "CreateDate": ago(450),
                "PasswordLastUsed": ago(2),
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/admin-jsmith", "EnableDate": ago(400)}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active", "CreateDate": ago(120), "LastUsedDate": ago(1), "LastUsedService": "ec2", "LastUsedRegion": "us-east-1"},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                ],
                "InlinePolicies": [],
                "Groups": [{"GroupName": "Administrators"}],
                "PermissionsBoundary": None,
                "Tags": [{"Key": "Department", "Value": "Engineering"}, {"Key": "AccountType", "Value": "human"}],
            },
            {
                "UserName": "dev-mwilliams",
                "Arn": "arn:aws:iam::123456789012:user/dev-mwilliams",
                "CreateDate": ago(300),
                "PasswordLastUsed": ago(5),
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIAI44QH8DHBEXAMPLE", "Status": "Active", "CreateDate": ago(300), "LastUsedDate": ago(3), "LastUsedService": "s3", "LastUsedRegion": "us-east-1"},
                    {"AccessKeyId": "AKIAI55QH9DHCEXAMPLE", "Status": "Active", "CreateDate": ago(100), "LastUsedDate": ago(60), "LastUsedService": "codecommit", "LastUsedRegion": "us-east-1"},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "PowerUserAccess", "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"},
                ],
                "InlinePolicies": [
                    {
                        "PolicyName": "dev-full-s3",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                            ],
                        },
                    },
                ],
                "Groups": [{"GroupName": "Developers"}],
                "PermissionsBoundary": None,
                "Tags": [{"Key": "Department", "Value": "Engineering"}, {"Key": "AccountType", "Value": "human"}],
            },
            {
                "UserName": "svc-deploy-pipeline",
                "Arn": "arn:aws:iam::123456789012:user/svc-deploy-pipeline",
                "CreateDate": ago(500),
                "PasswordLastUsed": None,
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIAI66QH0DHDEXAMPLE", "Status": "Active", "CreateDate": ago(500), "LastUsedDate": ago(1), "LastUsedService": "sts", "LastUsedRegion": "us-east-1"},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                ],
                "InlinePolicies": [],
                "Groups": [],
                "PermissionsBoundary": None,
                "Tags": [{"Key": "AccountType", "Value": "service"}],
            },
            {
                "UserName": "svc-monitoring",
                "Arn": "arn:aws:iam::123456789012:user/svc-monitoring",
                "CreateDate": ago(200),
                "PasswordLastUsed": None,
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIAI88QH2DHFEXAMPLE", "Status": "Active", "CreateDate": ago(200), "LastUsedDate": ago(0), "LastUsedService": "cloudwatch", "LastUsedRegion": "us-east-1"},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "CloudWatchReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"},
                ],
                "InlinePolicies": [],
                "Groups": [{"GroupName": "MonitoringServices"}],
                "PermissionsBoundary": {"PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/ServiceBoundary"},
                "Tags": [{"Key": "AccountType", "Value": "service"}],
            },
            {
                "UserName": "analyst-klee",
                "Arn": "arn:aws:iam::123456789012:user/analyst-klee",
                "CreateDate": ago(30),
                "PasswordLastUsed": ago(1),
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/analyst-klee", "EnableDate": ago(30)}],
                "AccessKeys": [],
                "AttachedPolicies": [
                    {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
                    {"PolicyName": "SecurityAudit", "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"},
                ],
                "InlinePolicies": [],
                "Groups": [{"GroupName": "SecurityAuditors"}],
                "PermissionsBoundary": None,
                "Tags": [{"Key": "Department", "Value": "Security"}, {"Key": "AccountType", "Value": "human"}],
            },
            {
                "UserName": "former-contractor",
                "Arn": "arn:aws:iam::123456789012:user/former-contractor",
                "CreateDate": ago(400),
                "PasswordLastUsed": ago(180),
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIAI77QH1DHEEXAMPLE", "Status": "Active", "CreateDate": ago(400), "LastUsedDate": ago(150), "LastUsedService": "ec2", "LastUsedRegion": "us-west-2"},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "AmazonEC2FullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"},
                    {"PolicyName": "AmazonS3FullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"},
                ],
                "InlinePolicies": [
                    {
                        "PolicyName": "legacy-rds-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "rds:*", "Resource": "*"},
                            ],
                        },
                    },
                ],
                "Groups": [{"GroupName": "Developers"}],
                "PermissionsBoundary": None,
                "Tags": [{"Key": "Department", "Value": "Contractor"}, {"Key": "AccountType", "Value": "human"}],
            },
            {
                "UserName": "ops-rjohnson",
                "Arn": "arn:aws:iam::123456789012:user/ops-rjohnson",
                "CreateDate": ago(250),
                "PasswordLastUsed": ago(8),
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/ops-rjohnson", "EnableDate": ago(250)}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIAI99QH3DHGEXAMPLE", "Status": "Active", "CreateDate": ago(80), "LastUsedDate": ago(2), "LastUsedService": "ec2", "LastUsedRegion": "us-east-1"},
                ],
                "AttachedPolicies": [],
                "InlinePolicies": [
                    {
                        "PolicyName": "ops-full-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ec2:*", "rds:*", "elasticloadbalancing:*",
                                        "autoscaling:*", "cloudwatch:*",
                                    ],
                                    "Resource": "*",
                                },
                            ],
                        },
                    },
                ],
                "Groups": [{"GroupName": "Operations"}],
                "PermissionsBoundary": None,
                "Tags": [{"Key": "Department", "Value": "Operations"}, {"Key": "AccountType", "Value": "human"}],
            },
        ],
        "customer_managed_policies": [
            {
                "PolicyName": "LegacyFullAccess",
                "PolicyArn": "arn:aws:iam::123456789012:policy/LegacyFullAccess",
                "AttachmentCount": 0,
                "DefaultVersionId": "v1",
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    ],
                },
            },
            {
                "PolicyName": "DataEngineering",
                "PolicyArn": "arn:aws:iam::123456789012:policy/DataEngineering",
                "AttachmentCount": 3,
                "DefaultVersionId": "v2",
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:*", "glue:*", "athena:*", "redshift:*"], "Resource": "*"},
                        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::123456789012:role/DataPipeline*"},
                    ],
                },
            },
        ],
    }


# ---------------------------------------------------------------------------
# IAM Analyzer
# ---------------------------------------------------------------------------
class IAMAnalyzer:
    """Analyzes IAM users and policies, producing a risk-scored report."""

    def __init__(self, session=None, demo=False):
        self.session = session
        self.demo = demo
        self.data = generate_mock_iam_data() if demo else None
        self.user_reports = []
        self.policy_findings = []
        self.summary_stats = defaultdict(int)

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_risk(score):
        for label, threshold in sorted(RISK_THRESHOLDS.items(),
                                       key=lambda x: -x[1]):
            if score >= threshold:
                return label
        return "PASS"

    @staticmethod
    def _days_since(iso_str):
        if not iso_str:
            return None
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
        return (datetime.now(timezone.utc) - dt).days

    @staticmethod
    def _is_service_account(user):
        """Heuristic: service account if username starts with svc- or no password."""
        name = user.get("UserName", "").lower()
        tags = {t["Key"]: t["Value"] for t in user.get("Tags", [])}
        if name.startswith("svc-") or name.startswith("service-"):
            return True
        if tags.get("AccountType", "").lower() == "service":
            return True
        if user.get("PasswordLastUsed") is None and not user.get("MFADevices"):
            return True
        return False

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def analyze(self):
        """Run the full IAM analysis."""
        print("\n[*] Starting IAM security analysis...")

        if self.demo:
            users = self.data["users"]
            policies = self.data.get("customer_managed_policies", [])
        else:
            iam = self.session.client("iam")
            users = self._fetch_all_users(iam)
            policies = self._fetch_managed_policies(iam)

        for user in users:
            report = self._analyze_user(user)
            self.user_reports.append(report)
            risk = self._classify_risk(report["risk_score"])
            self.summary_stats[risk] += 1

        for policy in policies:
            self._analyze_managed_policy(policy)

        self.user_reports.sort(key=lambda r: -r["risk_score"])
        print(f"[+] Analyzed {len(users)} users and {len(policies)} customer-managed policies")

    def _analyze_user(self, user):
        """Analyze a single IAM user and return a risk report."""
        username = user["UserName"]
        risk_score = 0
        findings = []
        is_svc = self._is_service_account(user)
        has_console = user.get("PasswordLastUsed") is not None

        # --- MFA ---
        mfa_enabled = len(user.get("MFADevices", [])) > 0
        if has_console and not mfa_enabled:
            risk_score += RISK_WEIGHTS["no_mfa_console_user"]
            findings.append({
                "check": "MFA_MISSING",
                "severity": "HIGH",
                "detail": "Console user without MFA enabled",
                "weight": RISK_WEIGHTS["no_mfa_console_user"],
            })

        # --- Attached policies ---
        admin_policies = {"AdministratorAccess"}
        power_policies = {"PowerUserAccess"}

        for pol in user.get("AttachedPolicies", []):
            pname = pol["PolicyName"]
            if pname in admin_policies:
                w = RISK_WEIGHTS["service_account_with_admin"] if is_svc else RISK_WEIGHTS["admin_access"]
                risk_score += w
                findings.append({
                    "check": "ADMIN_ACCESS",
                    "severity": "CRITICAL" if is_svc else "HIGH",
                    "detail": f"{'Service account' if is_svc else 'User'} has {pname} attached",
                    "weight": w,
                })
            elif pname in power_policies:
                risk_score += RISK_WEIGHTS["power_user_access"]
                findings.append({
                    "check": "POWER_USER",
                    "severity": "MEDIUM",
                    "detail": f"{pname} attached (broad permissions excluding IAM)",
                    "weight": RISK_WEIGHTS["power_user_access"],
                })

        # --- Inline policies ---
        for inline in user.get("InlinePolicies", []):
            risk_score += RISK_WEIGHTS["inline_policy_present"]
            findings.append({
                "check": "INLINE_POLICY",
                "severity": "LOW",
                "detail": f"Inline policy '{inline['PolicyName']}' present (harder to govern)",
                "weight": RISK_WEIGHTS["inline_policy_present"],
            })
            doc = inline.get("PolicyDocument", {})
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    action = stmt.get("Action", "")
                    actions_list = action if isinstance(action, list) else [action]
                    for a in actions_list:
                        if a == "*" or (isinstance(a, str) and a.endswith(":*")):
                            risk_score += RISK_WEIGHTS["wildcard_action_policy"]
                            findings.append({
                                "check": "WILDCARD_ACTION",
                                "severity": "HIGH",
                                "detail": f"Inline policy '{inline['PolicyName']}' grants '{a}' on Resource={stmt.get('Resource', '*')}",
                                "weight": RISK_WEIGHTS["wildcard_action_policy"],
                            })
                    # Check for missing Condition
                    if "Condition" not in stmt and stmt.get("Resource") == "*":
                        risk_score += RISK_WEIGHTS["no_policy_condition"]
                        findings.append({
                            "check": "NO_CONDITION",
                            "severity": "LOW",
                            "detail": f"Statement in '{inline['PolicyName']}' has no Condition key with Resource=*",
                            "weight": RISK_WEIGHTS["no_policy_condition"],
                        })

        # --- Access keys ---
        for key in user.get("AccessKeys", []):
            if key["Status"] != "Active":
                continue
            age = self._days_since(key["CreateDate"])
            if age and age > 365:
                risk_score += RISK_WEIGHTS["access_key_over_365d"]
                findings.append({
                    "check": "KEY_AGE_CRITICAL",
                    "severity": "CRITICAL",
                    "detail": f"Access key {key['AccessKeyId']} is {age} days old (> 365 days)",
                    "weight": RISK_WEIGHTS["access_key_over_365d"],
                })
            elif age and age > 90:
                risk_score += RISK_WEIGHTS["access_key_over_90d"]
                findings.append({
                    "check": "KEY_AGE_HIGH",
                    "severity": "HIGH",
                    "detail": f"Access key {key['AccessKeyId']} is {age} days old (> 90 days)",
                    "weight": RISK_WEIGHTS["access_key_over_90d"],
                })

        active_keys = [k for k in user.get("AccessKeys", []) if k["Status"] == "Active"]
        if len(active_keys) > 1:
            risk_score += RISK_WEIGHTS["multiple_active_keys"]
            findings.append({
                "check": "MULTIPLE_KEYS",
                "severity": "MEDIUM",
                "detail": f"User has {len(active_keys)} active access keys",
                "weight": RISK_WEIGHTS["multiple_active_keys"],
            })

        # --- Last login staleness ---
        if has_console:
            days_since_login = self._days_since(user.get("PasswordLastUsed"))
            if days_since_login and days_since_login > 90:
                risk_score += RISK_WEIGHTS["no_recent_login_90d"]
                findings.append({
                    "check": "STALE_LOGIN",
                    "severity": "MEDIUM",
                    "detail": f"Last console login was {days_since_login} days ago",
                    "weight": RISK_WEIGHTS["no_recent_login_90d"],
                })

        # --- Group membership ---
        groups = user.get("Groups", [])
        if not groups:
            risk_score += RISK_WEIGHTS["not_in_any_group"]
            findings.append({
                "check": "NO_GROUP",
                "severity": "MEDIUM",
                "detail": "User is not a member of any IAM group (policies attached directly)",
                "weight": RISK_WEIGHTS["not_in_any_group"],
            })

        # --- Permissions boundary for service accounts ---
        if is_svc and not user.get("PermissionsBoundary"):
            risk_score += RISK_WEIGHTS["service_account_no_boundary"]
            findings.append({
                "check": "NO_BOUNDARY",
                "severity": "MEDIUM",
                "detail": "Service account has no permissions boundary set",
                "weight": RISK_WEIGHTS["service_account_no_boundary"],
            })

        # Build user report
        tags = {t["Key"]: t["Value"] for t in user.get("Tags", [])}
        report = {
            "username": username,
            "arn": user.get("Arn", ""),
            "account_type": "service" if is_svc else "human",
            "department": tags.get("Department", "Unknown"),
            "create_date": user.get("CreateDate", ""),
            "password_last_used": user.get("PasswordLastUsed"),
            "mfa_enabled": mfa_enabled,
            "access_key_count": len(active_keys),
            "access_keys": [
                {
                    "key_id": k["AccessKeyId"],
                    "age_days": self._days_since(k["CreateDate"]),
                    "last_used": k.get("LastUsedDate", "Never"),
                    "last_service": k.get("LastUsedService", "N/A"),
                }
                for k in active_keys
            ],
            "groups": [g["GroupName"] for g in groups],
            "attached_policies": [p["PolicyName"] for p in user.get("AttachedPolicies", [])],
            "inline_policy_count": len(user.get("InlinePolicies", [])),
            "permissions_boundary": user.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") if user.get("PermissionsBoundary") else None,
            "risk_score": risk_score,
            "risk_rating": self._classify_risk(risk_score),
            "findings": findings,
        }
        return report

    def _analyze_managed_policy(self, policy):
        """Check customer-managed policies for issues."""
        doc = policy.get("Document", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                action = stmt.get("Action", "")
                resource = stmt.get("Resource", "")
                actions_list = action if isinstance(action, list) else [action]
                for a in actions_list:
                    if a == "*":
                        self.policy_findings.append({
                            "policy_name": policy["PolicyName"],
                            "policy_arn": policy["PolicyArn"],
                            "severity": "HIGH",
                            "issue": f"Grants Action='*' on Resource='{resource}' (equivalent to full admin)",
                            "attachment_count": policy.get("AttachmentCount", 0),
                        })
                    elif a.endswith(":*"):
                        service = a.split(":")[0]
                        self.policy_findings.append({
                            "policy_name": policy["PolicyName"],
                            "policy_arn": policy["PolicyArn"],
                            "severity": "MEDIUM",
                            "issue": f"Grants all actions on service '{service}' (Action='{a}')",
                            "attachment_count": policy.get("AttachmentCount", 0),
                        })

    # ------------------------------------------------------------------
    # Live mode helpers
    # ------------------------------------------------------------------
    def _fetch_all_users(self, iam):
        """Fetch complete user details from live AWS account."""
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                users.append(self._enrich_user(iam, u))
        return users

    def _enrich_user(self, iam, raw_user):
        """Gather all relevant details for a single IAM user."""
        username = raw_user["UserName"]
        user = {
            "UserName": username,
            "Arn": raw_user["Arn"],
            "CreateDate": raw_user["CreateDate"].isoformat() if hasattr(raw_user["CreateDate"], "isoformat") else str(raw_user["CreateDate"]),
            "PasswordLastUsed": (
                raw_user["PasswordLastUsed"].isoformat()
                if raw_user.get("PasswordLastUsed") and hasattr(raw_user["PasswordLastUsed"], "isoformat")
                else raw_user.get("PasswordLastUsed")
            ),
            "MFADevices": [],
            "AccessKeys": [],
            "AttachedPolicies": [],
            "InlinePolicies": [],
            "Groups": [],
            "PermissionsBoundary": raw_user.get("PermissionsBoundary"),
            "Tags": [],
        }

        # MFA
        try:
            mfa_resp = iam.list_mfa_devices(UserName=username)
            user["MFADevices"] = [
                {"SerialNumber": d["SerialNumber"],
                 "EnableDate": d["EnableDate"].isoformat() if hasattr(d["EnableDate"], "isoformat") else str(d["EnableDate"])}
                for d in mfa_resp.get("MFADevices", [])
            ]
        except ClientError:
            pass

        # Access keys with last used info
        try:
            keys_resp = iam.list_access_keys(UserName=username)
            for k in keys_resp.get("AccessKeyMetadata", []):
                key_info = {
                    "AccessKeyId": k["AccessKeyId"],
                    "Status": k["Status"],
                    "CreateDate": k["CreateDate"].isoformat() if hasattr(k["CreateDate"], "isoformat") else str(k["CreateDate"]),
                    "LastUsedDate": None,
                    "LastUsedService": None,
                    "LastUsedRegion": None,
                }
                try:
                    lu = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                    info = lu.get("AccessKeyLastUsed", {})
                    if "LastUsedDate" in info:
                        key_info["LastUsedDate"] = info["LastUsedDate"].isoformat() if hasattr(info["LastUsedDate"], "isoformat") else str(info["LastUsedDate"])
                        key_info["LastUsedService"] = info.get("ServiceName")
                        key_info["LastUsedRegion"] = info.get("Region")
                except ClientError:
                    pass
                user["AccessKeys"].append(key_info)
        except ClientError:
            pass

        # Attached policies
        try:
            user["AttachedPolicies"] = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
        except ClientError:
            pass

        # Inline policies
        try:
            inline_names = iam.list_user_policies(UserName=username).get("PolicyNames", [])
            for pname in inline_names:
                try:
                    pdoc = iam.get_user_policy(UserName=username, PolicyName=pname)
                    user["InlinePolicies"].append({
                        "PolicyName": pname,
                        "PolicyDocument": pdoc["PolicyDocument"],
                    })
                except ClientError:
                    pass
        except ClientError:
            pass

        # Groups
        try:
            user["Groups"] = [
                {"GroupName": g["GroupName"]}
                for g in iam.list_groups_for_user(UserName=username).get("Groups", [])
            ]
        except ClientError:
            pass

        # Tags
        try:
            user["Tags"] = iam.list_user_tags(UserName=username).get("Tags", [])
        except ClientError:
            pass

        return user

    def _fetch_managed_policies(self, iam):
        """Fetch customer-managed policies and their documents."""
        policies = []
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for pol in page["Policies"]:
                try:
                    ver = iam.get_policy_version(
                        PolicyArn=pol["Arn"],
                        VersionId=pol["DefaultVersionId"],
                    )
                    policies.append({
                        "PolicyName": pol["PolicyName"],
                        "PolicyArn": pol["Arn"],
                        "AttachmentCount": pol.get("AttachmentCount", 0),
                        "DefaultVersionId": pol["DefaultVersionId"],
                        "Document": ver["PolicyVersion"]["Document"],
                    })
                except ClientError:
                    pass
        return policies

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    def print_report(self):
        """Print a human-readable report to stdout."""
        print("\n" + "=" * 76)
        print("  IAM SECURITY ANALYSIS REPORT")
        print("=" * 76)
        print(f"  Timestamp : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Mode      : {'Demo (mock data)' if self.demo else 'Live'}")
        if self.demo:
            print(f"  Account   : {self.data['account_id']} ({self.data['account_alias']})")
        print(f"  Users     : {len(self.user_reports)}")
        print()

        # Summary table
        print("  Risk Distribution:")
        for rating in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"]:
            count = self.summary_stats.get(rating, 0)
            bar = "#" * count
            print(f"    {rating:10s}: {count:3d}  {bar}")

        print("\n" + "-" * 76)
        print("  USER RISK SCORES (sorted highest to lowest)")
        print("-" * 76)
        print(f"  {'Username':<25s} {'Type':<10s} {'MFA':<5s} {'Keys':<5s} {'Score':<7s} {'Rating':<10s}")
        print(f"  {'-'*24:<25s} {'-'*9:<10s} {'-'*4:<5s} {'-'*4:<5s} {'-'*6:<7s} {'-'*9:<10s}")

        for r in self.user_reports:
            mfa_str = "Yes" if r["mfa_enabled"] else "NO"
            print(f"  {r['username']:<25s} {r['account_type']:<10s} {mfa_str:<5s} "
                  f"{r['access_key_count']:<5d} {r['risk_score']:<7d} {r['risk_rating']:<10s}")

        # Detailed findings per user
        print("\n" + "-" * 76)
        print("  DETAILED FINDINGS PER USER")
        print("-" * 76)

        for r in self.user_reports:
            if not r["findings"]:
                continue
            print(f"\n  User: {r['username']} (Risk Score: {r['risk_score']} - {r['risk_rating']})")
            print(f"  ARN:  {r['arn']}")
            print(f"  Type: {r['account_type']} | Dept: {r['department']} | Groups: {', '.join(r['groups']) or 'None'}")
            if r["access_keys"]:
                for ak in r["access_keys"]:
                    print(f"  Key:  {ak['key_id']} (age: {ak['age_days']}d, last used: {ak['last_used']}, service: {ak['last_service']})")
            print(f"  Policies: {', '.join(r['attached_policies']) or 'None attached'}")
            if r.get("permissions_boundary"):
                print(f"  Boundary: {r['permissions_boundary']}")
            print()
            for f in r["findings"]:
                marker = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "* ", "LOW": "- "}.get(f["severity"], "  ")
                print(f"    [{marker}] [{f['severity']}] {f['detail']} (+{f['weight']} pts)")

        # Managed policy findings
        if self.policy_findings:
            print("\n" + "-" * 76)
            print("  CUSTOMER-MANAGED POLICY FINDINGS")
            print("-" * 76)
            for pf in self.policy_findings:
                print(f"\n  Policy: {pf['policy_name']}")
                print(f"  ARN:    {pf['policy_arn']}")
                print(f"  Attached to: {pf['attachment_count']} entities")
                print(f"  [{pf['severity']}] {pf['issue']}")

        print("\n" + "=" * 76)

    def save_report(self, output_prefix):
        """Save JSON report to file."""
        report = {
            "metadata": {
                "tool": "IAM Analyzer",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": "demo" if self.demo else "live",
            },
            "summary": {
                "total_users": len(self.user_reports),
                "risk_distribution": dict(self.summary_stats),
            },
            "user_reports": self.user_reports,
            "policy_findings": self.policy_findings,
        }

        path = f"{output_prefix}-iam-analysis.json"
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\n[+] Report saved to {path}")


# ===================================================================
# Main
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description="IAM Analyzer - Deep AWS IAM security analysis with risk scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo                           Analyze mock IAM data
  %(prog)s --demo -o /tmp/audit             Save report to /tmp/audit-iam-analysis.json
  %(prog)s --profile production             Analyze a live AWS account
        """,
    )
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--output", "-o", help="Output file prefix for JSON report")
    parser.add_argument("--demo", action="store_true",
                        help="Run with mock data (no AWS credentials needed)")
    args = parser.parse_args()

    print("=" * 76)
    print("  IAM Analyzer v1.0")
    print("  AWS IAM Security Analysis & Risk Scoring")
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

    analyzer = IAMAnalyzer(session=session, demo=args.demo)
    analyzer.analyze()
    analyzer.print_report()

    if args.output:
        analyzer.save_report(args.output)
    elif args.demo:
        analyzer.save_report("demo")


if __name__ == "__main__":
    main()
