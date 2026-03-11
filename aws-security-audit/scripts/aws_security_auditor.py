#!/usr/bin/env python3
"""
AWS Security Auditor - Comprehensive AWS Security Configuration Audit Tool

Performs automated security checks across IAM, S3, EC2, CloudTrail, and RDS
services. Identifies misconfigurations, policy violations, and deviations from
AWS security best practices aligned with the CIS AWS Foundations Benchmark.

Usage:
    # Run against a live AWS account (requires configured credentials)
    python3 aws_security_auditor.py --profile myprofile --region us-east-1

    # Run in demo mode with mock data (no AWS credentials required)
    python3 aws_security_auditor.py --demo

    # Save report to a specific output file
    python3 aws_security_auditor.py --demo --output audit-report.json

Dependencies:
    - boto3 (only external dependency; install via: pip install boto3)
    - Standard library: json, datetime, argparse, sys, os

Author: Security Portfolio Project
"""

import argparse
import json
import sys
import os
from datetime import datetime, timedelta, timezone
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# Sensitive ports that should never be open to 0.0.0.0/0
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
}


# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------
class Finding:
    """Represents a single audit finding."""

    def __init__(self, service, check_id, title, severity, resource_arn,
                 description, evidence, remediation, cis_ref=None):
        self.service = service
        self.check_id = check_id
        self.title = title
        self.severity = severity
        self.resource_arn = resource_arn
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.cis_ref = cis_ref
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "service": self.service,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "resource_arn": self.resource_arn,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cis_benchmark_ref": self.cis_ref,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Mock data for --demo mode
# ---------------------------------------------------------------------------
def generate_mock_data():
    """Return realistic mock AWS resource data for demonstration purposes."""
    now = datetime.now(timezone.utc)
    old_date = (now - timedelta(days=120)).isoformat()
    recent_date = (now - timedelta(days=5)).isoformat()
    very_old_date = (now - timedelta(days=400)).isoformat()

    return {
        "account_id": "123456789012",
        "account_alias": "acme-production",
        "region": "us-east-1",
        "iam": {
            "password_policy": {
                "MinimumPasswordLength": 8,
                "RequireSymbols": False,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": False,
                "RequireLowercaseCharacters": True,
                "AllowUsersToChangePassword": True,
                "MaxPasswordAge": 0,         # No expiration
                "PasswordReusePrevention": 0, # No reuse prevention
                "HardExpiry": False,
            },
            "users": [
                {
                    "UserName": "admin-jsmith",
                    "Arn": "arn:aws:iam::123456789012:user/admin-jsmith",
                    "CreateDate": very_old_date,
                    "PasswordLastUsed": recent_date,
                    "MFAEnabled": True,
                    "AccessKeys": [
                        {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active",
                         "CreateDate": old_date},
                    ],
                    "AttachedPolicies": [
                        {"PolicyName": "AdministratorAccess",
                         "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                    ],
                    "InlinePolicies": [],
                    "Groups": ["Administrators"],
                },
                {
                    "UserName": "dev-mwilliams",
                    "Arn": "arn:aws:iam::123456789012:user/dev-mwilliams",
                    "CreateDate": old_date,
                    "PasswordLastUsed": recent_date,
                    "MFAEnabled": False,
                    "AccessKeys": [
                        {"AccessKeyId": "AKIAI44QH8DHBEXAMPLE", "Status": "Active",
                         "CreateDate": very_old_date},
                        {"AccessKeyId": "AKIAI55QH9DHCEXAMPLE", "Status": "Active",
                         "CreateDate": old_date},
                    ],
                    "AttachedPolicies": [
                        {"PolicyName": "PowerUserAccess",
                         "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"},
                    ],
                    "InlinePolicies": [
                        {
                            "PolicyName": "dev-full-s3",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [{
                                    "Effect": "Allow",
                                    "Action": "s3:*",
                                    "Resource": "*",
                                }],
                            },
                        },
                    ],
                    "Groups": ["Developers"],
                },
                {
                    "UserName": "svc-deploy-pipeline",
                    "Arn": "arn:aws:iam::123456789012:user/svc-deploy-pipeline",
                    "CreateDate": very_old_date,
                    "PasswordLastUsed": None,
                    "MFAEnabled": False,
                    "AccessKeys": [
                        {"AccessKeyId": "AKIAI66QH0DHDEXAMPLE", "Status": "Active",
                         "CreateDate": very_old_date},
                    ],
                    "AttachedPolicies": [
                        {"PolicyName": "AdministratorAccess",
                         "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                    ],
                    "InlinePolicies": [],
                    "Groups": [],
                },
                {
                    "UserName": "analyst-klee",
                    "Arn": "arn:aws:iam::123456789012:user/analyst-klee",
                    "CreateDate": recent_date,
                    "PasswordLastUsed": recent_date,
                    "MFAEnabled": True,
                    "AccessKeys": [],
                    "AttachedPolicies": [
                        {"PolicyName": "ReadOnlyAccess",
                         "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
                    ],
                    "InlinePolicies": [],
                    "Groups": ["SecurityAuditors"],
                },
                {
                    "UserName": "former-contractor",
                    "Arn": "arn:aws:iam::123456789012:user/former-contractor",
                    "CreateDate": very_old_date,
                    "PasswordLastUsed": very_old_date,
                    "MFAEnabled": False,
                    "AccessKeys": [
                        {"AccessKeyId": "AKIAI77QH1DHEEXAMPLE", "Status": "Active",
                         "CreateDate": very_old_date},
                    ],
                    "AttachedPolicies": [
                        {"PolicyName": "AmazonEC2FullAccess",
                         "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"},
                        {"PolicyName": "AmazonS3FullAccess",
                         "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"},
                    ],
                    "InlinePolicies": [],
                    "Groups": ["Developers"],
                },
            ],
            "root_account": {
                "MFAEnabled": False,
                "AccessKeysPresent": True,
                "LastUsed": recent_date,
            },
            "managed_policies_with_star": [
                {
                    "PolicyName": "LegacyFullAccess",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/LegacyFullAccess",
                    "Document": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }],
                    },
                },
            ],
        },
        "s3": {
            "buckets": [
                {
                    "Name": "acme-prod-data-lake",
                    "CreationDate": old_date,
                    "Region": "us-east-1",
                    "PublicAccessBlock": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "Encryption": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "alias/acme-data-key"},
                    "Versioning": "Enabled",
                    "Logging": True,
                    "PublicACL": False,
                    "PublicPolicy": False,
                    "LifecycleRules": True,
                },
                {
                    "Name": "acme-website-assets",
                    "CreationDate": very_old_date,
                    "Region": "us-east-1",
                    "PublicAccessBlock": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "Encryption": None,
                    "Versioning": "Suspended",
                    "Logging": False,
                    "PublicACL": True,
                    "PublicPolicy": True,
                    "LifecycleRules": False,
                },
                {
                    "Name": "acme-cloudtrail-logs",
                    "CreationDate": old_date,
                    "Region": "us-east-1",
                    "PublicAccessBlock": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "Encryption": {"SSEAlgorithm": "AES256"},
                    "Versioning": "Enabled",
                    "Logging": True,
                    "PublicACL": False,
                    "PublicPolicy": False,
                    "LifecycleRules": True,
                },
                {
                    "Name": "acme-dev-scratch",
                    "CreationDate": recent_date,
                    "Region": "us-east-1",
                    "PublicAccessBlock": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "Encryption": None,
                    "Versioning": "Disabled",
                    "Logging": False,
                    "PublicACL": False,
                    "PublicPolicy": True,
                    "LifecycleRules": False,
                },
                {
                    "Name": "acme-backup-vault",
                    "CreationDate": very_old_date,
                    "Region": "us-west-2",
                    "PublicAccessBlock": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "Encryption": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "alias/backup-key"},
                    "Versioning": "Enabled",
                    "Logging": False,
                    "PublicACL": False,
                    "PublicPolicy": False,
                    "LifecycleRules": True,
                },
            ],
        },
        "ec2": {
            "security_groups": [
                {
                    "GroupId": "sg-0a1b2c3d4e5f00001",
                    "GroupName": "web-servers-prod",
                    "Description": "Production web server security group",
                    "VpcId": "vpc-0abc123def456789",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                },
                {
                    "GroupId": "sg-0a1b2c3d4e5f00002",
                    "GroupName": "ssh-management",
                    "Description": "SSH access for management",
                    "VpcId": "vpc-0abc123def456789",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                },
                {
                    "GroupId": "sg-0a1b2c3d4e5f00003",
                    "GroupName": "database-sg",
                    "Description": "Database tier security group",
                    "VpcId": "vpc-0abc123def456789",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
                         "IpRanges": [{"CidrIp": "10.0.0.0/16"}]},
                    ],
                },
                {
                    "GroupId": "sg-0a1b2c3d4e5f00004",
                    "GroupName": "rdp-windows",
                    "Description": "RDP access for Windows servers",
                    "VpcId": "vpc-0abc123def456789",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                },
                {
                    "GroupId": "sg-0a1b2c3d4e5f00005",
                    "GroupName": "internal-app",
                    "Description": "Internal application tier",
                    "VpcId": "vpc-0abc123def456789",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
                         "IpRanges": [{"CidrIp": "10.0.0.0/16"}]},
                    ],
                },
            ],
            "instances": [
                {
                    "InstanceId": "i-0abc123def4567890",
                    "InstanceType": "t3.large",
                    "State": "running",
                    "PublicIpAddress": "54.210.167.99",
                    "PrivateIpAddress": "10.0.1.25",
                    "SubnetId": "subnet-private-01",
                    "SubnetType": "private",
                    "SecurityGroups": [{"GroupId": "sg-0a1b2c3d4e5f00001"}],
                    "Tags": [{"Key": "Name", "Value": "prod-web-01"}],
                },
                {
                    "InstanceId": "i-0abc123def4567891",
                    "InstanceType": "m5.xlarge",
                    "State": "running",
                    "PublicIpAddress": None,
                    "PrivateIpAddress": "10.0.2.50",
                    "SubnetId": "subnet-private-02",
                    "SubnetType": "private",
                    "SecurityGroups": [{"GroupId": "sg-0a1b2c3d4e5f00003"}],
                    "Tags": [{"Key": "Name", "Value": "prod-db-01"}],
                },
                {
                    "InstanceId": "i-0abc123def4567892",
                    "InstanceType": "t3.medium",
                    "State": "running",
                    "PublicIpAddress": "3.95.22.178",
                    "PrivateIpAddress": "10.0.3.10",
                    "SubnetId": "subnet-public-01",
                    "SubnetType": "public",
                    "SecurityGroups": [{"GroupId": "sg-0a1b2c3d4e5f00002"}],
                    "Tags": [{"Key": "Name", "Value": "bastion-host"}],
                },
            ],
            "ebs_volumes": [
                {
                    "VolumeId": "vol-0abc123def4567890",
                    "Size": 100,
                    "State": "in-use",
                    "Encrypted": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
                    "Attachments": [{"InstanceId": "i-0abc123def4567890"}],
                    "Tags": [{"Key": "Name", "Value": "prod-web-01-root"}],
                },
                {
                    "VolumeId": "vol-0abc123def4567891",
                    "Size": 500,
                    "State": "in-use",
                    "Encrypted": False,
                    "KmsKeyId": None,
                    "Attachments": [{"InstanceId": "i-0abc123def4567891"}],
                    "Tags": [{"Key": "Name", "Value": "prod-db-01-data"}],
                },
                {
                    "VolumeId": "vol-0abc123def4567892",
                    "Size": 50,
                    "State": "in-use",
                    "Encrypted": False,
                    "KmsKeyId": None,
                    "Attachments": [{"InstanceId": "i-0abc123def4567892"}],
                    "Tags": [{"Key": "Name", "Value": "bastion-root"}],
                },
                {
                    "VolumeId": "vol-0abc123def4567893",
                    "Size": 200,
                    "State": "available",
                    "Encrypted": False,
                    "KmsKeyId": None,
                    "Attachments": [],
                    "Tags": [{"Key": "Name", "Value": "orphaned-volume"}],
                },
            ],
        },
        "cloudtrail": {
            "trails": [
                {
                    "Name": "acme-org-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/acme-org-trail",
                    "S3BucketName": "acme-cloudtrail-logs",
                    "IsMultiRegionTrail": False,
                    "IsLogging": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": None,
                    "HasCustomEventSelectors": False,
                    "IncludeGlobalServiceEvents": True,
                },
            ],
        },
        "rds": {
            "instances": [
                {
                    "DBInstanceIdentifier": "acme-prod-mysql",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:acme-prod-mysql",
                    "Engine": "mysql",
                    "EngineVersion": "8.0.28",
                    "DBInstanceClass": "db.r5.large",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/efgh-5678",
                    "BackupRetentionPeriod": 7,
                    "MultiAZ": True,
                    "AutoMinorVersionUpgrade": True,
                    "DeletionProtection": True,
                    "IAMDatabaseAuthenticationEnabled": False,
                    "PerformanceInsightsEnabled": True,
                },
                {
                    "DBInstanceIdentifier": "acme-dev-postgres",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:acme-dev-postgres",
                    "Engine": "postgres",
                    "EngineVersion": "14.5",
                    "DBInstanceClass": "db.t3.medium",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": False,
                    "KmsKeyId": None,
                    "BackupRetentionPeriod": 0,
                    "MultiAZ": False,
                    "AutoMinorVersionUpgrade": False,
                    "DeletionProtection": False,
                    "IAMDatabaseAuthenticationEnabled": False,
                    "PerformanceInsightsEnabled": False,
                },
                {
                    "DBInstanceIdentifier": "acme-staging-mysql",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:acme-staging-mysql",
                    "Engine": "mysql",
                    "EngineVersion": "5.7.38",
                    "DBInstanceClass": "db.t3.small",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": False,
                    "KmsKeyId": None,
                    "BackupRetentionPeriod": 1,
                    "MultiAZ": False,
                    "AutoMinorVersionUpgrade": True,
                    "DeletionProtection": False,
                    "IAMDatabaseAuthenticationEnabled": False,
                    "PerformanceInsightsEnabled": False,
                },
            ],
        },
    }


# ===================================================================
# Audit check functions
# ===================================================================

class AWSSecurityAuditor:
    """Orchestrates all security audit checks and collects findings."""

    def __init__(self, session=None, region="us-east-1", demo=False):
        self.findings = []
        self.demo = demo
        self.region = region
        self.session = session
        self.mock_data = generate_mock_data() if demo else None
        self.stats = defaultdict(int)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _add(self, finding):
        self.findings.append(finding)
        self.stats[finding.severity] += 1

    @staticmethod
    def _key_age_days(create_date_str):
        if not create_date_str:
            return 0
        try:
            dt = datetime.fromisoformat(create_date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            dt = create_date_str if isinstance(create_date_str, datetime) else datetime.now(timezone.utc)
        return (datetime.now(timezone.utc) - dt).days

    # ------------------------------------------------------------------
    # IAM Checks
    # ------------------------------------------------------------------
    def audit_iam(self):
        """Run all IAM-related security checks."""
        print("\n[*] Auditing IAM configuration...")

        if self.demo:
            data = self.mock_data["iam"]
            self._check_root_account(data["root_account"])
            self._check_password_policy(data["password_policy"])
            for user in data["users"]:
                self._check_iam_user(user)
            for policy in data.get("managed_policies_with_star", []):
                self._check_managed_policy(policy)
        else:
            iam = self.session.client("iam")
            # Root account
            summary = iam.get_account_summary()["SummaryMap"]
            root_info = {
                "MFAEnabled": summary.get("AccountMFAEnabled", 0) == 1,
                "AccessKeysPresent": summary.get("AccountAccessKeysPresent", 0) == 1,
            }
            self._check_root_account(root_info)

            # Password policy
            try:
                pp = iam.get_account_password_policy()["PasswordPolicy"]
                self._check_password_policy(pp)
            except ClientError:
                self._add(Finding(
                    "IAM", "IAM-PP-01", "No account password policy configured",
                    CRITICAL,
                    f"arn:aws:iam::{self._get_account_id()}:account",
                    "The AWS account does not have a custom password policy. "
                    "The default policy allows weak passwords.",
                    "get_account_password_policy returned NoSuchEntity",
                    "aws iam update-account-password-policy --minimum-password-length 14 "
                    "--require-symbols --require-numbers --require-uppercase-characters "
                    "--require-lowercase-characters --max-password-age 90 "
                    "--password-reuse-prevention 24",
                    cis_ref="CIS 1.8-1.11",
                ))

            # Users
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    user_detail = self._enrich_iam_user(iam, user)
                    self._check_iam_user(user_detail)

    def _check_root_account(self, root):
        if not root.get("MFAEnabled"):
            self._add(Finding(
                "IAM", "IAM-ROOT-01", "Root account MFA not enabled",
                CRITICAL,
                "arn:aws:iam::root",
                "The root account does not have multi-factor authentication enabled. "
                "The root account has unrestricted access to all resources and cannot "
                "be limited by IAM policies.",
                "AccountMFAEnabled = False",
                "Enable hardware MFA on the root account via the IAM console. "
                "Use a hardware token (e.g., YubiKey) rather than a virtual MFA device.",
                cis_ref="CIS 1.5",
            ))

        if root.get("AccessKeysPresent"):
            self._add(Finding(
                "IAM", "IAM-ROOT-02", "Root account has active access keys",
                CRITICAL,
                "arn:aws:iam::root",
                "The root account has programmatic access keys. Root access keys provide "
                "unrestricted access and cannot be scoped with IAM policies. If compromised, "
                "an attacker gains full control of the account.",
                "AccountAccessKeysPresent = True",
                "Delete root access keys: aws iam delete-access-key --access-key-id <key-id> "
                "(must be run as root). Use IAM users or roles for programmatic access.",
                cis_ref="CIS 1.4",
            ))

    def _check_password_policy(self, pp):
        issues = []
        if pp.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"MinimumPasswordLength={pp.get('MinimumPasswordLength', 'not set')} (should be >= 14)")
        if not pp.get("RequireSymbols"):
            issues.append("RequireSymbols=False")
        if not pp.get("RequireNumbers"):
            issues.append("RequireNumbers=False")
        if not pp.get("RequireUppercaseCharacters"):
            issues.append("RequireUppercaseCharacters=False")
        if not pp.get("RequireLowercaseCharacters"):
            issues.append("RequireLowercaseCharacters=False")
        if not pp.get("MaxPasswordAge") or pp.get("MaxPasswordAge", 0) > 90:
            issues.append(f"MaxPasswordAge={pp.get('MaxPasswordAge', 0)} (should be <= 90)")
        if not pp.get("PasswordReusePrevention") or pp.get("PasswordReusePrevention", 0) < 24:
            issues.append(f"PasswordReusePrevention={pp.get('PasswordReusePrevention', 0)} (should be >= 24)")

        if issues:
            self._add(Finding(
                "IAM", "IAM-PP-02", "Password policy does not meet CIS benchmarks",
                MEDIUM,
                f"arn:aws:iam::{self.mock_data['account_id'] if self.demo else 'ACCOUNT'}:account",
                "The account password policy has one or more settings that do not meet "
                "CIS AWS Foundations Benchmark recommendations.",
                "; ".join(issues),
                "aws iam update-account-password-policy --minimum-password-length 14 "
                "--require-symbols --require-numbers --require-uppercase-characters "
                "--require-lowercase-characters --max-password-age 90 "
                "--password-reuse-prevention 24",
                cis_ref="CIS 1.8-1.11",
            ))

    def _check_iam_user(self, user):
        username = user["UserName"]
        arn = user.get("Arn", f"arn:aws:iam::ACCOUNT:user/{username}")

        # MFA check (console users only)
        has_password = user.get("PasswordLastUsed") is not None
        if has_password and not user.get("MFAEnabled"):
            self._add(Finding(
                "IAM", "IAM-MFA-01", f"User '{username}' has console access without MFA",
                HIGH, arn,
                f"IAM user '{username}' has a console password but no MFA device configured. "
                "Without MFA, the account is vulnerable to credential stuffing and phishing attacks.",
                f"MFAEnabled=False, PasswordLastUsed={user.get('PasswordLastUsed', 'N/A')}",
                f"aws iam enable-mfa-device --user-name {username} --serial-number "
                f"<mfa-device-arn> --authentication-code1 <code1> --authentication-code2 <code2>",
                cis_ref="CIS 1.10",
            ))

        # Access key age check
        for key in user.get("AccessKeys", []):
            if key["Status"] != "Active":
                continue
            age = self._key_age_days(key["CreateDate"])
            if age > 90:
                severity = CRITICAL if age > 365 else HIGH
                self._add(Finding(
                    "IAM", "IAM-KEY-01",
                    f"User '{username}' has an access key older than {age} days",
                    severity, arn,
                    f"Access key {key['AccessKeyId']} for user '{username}' was created "
                    f"{age} days ago and has not been rotated. Long-lived credentials "
                    "increase the window of exposure if compromised.",
                    f"AccessKeyId={key['AccessKeyId']}, CreateDate={key['CreateDate']}, Age={age}d",
                    f"Rotate the key: aws iam create-access-key --user-name {username} && "
                    f"aws iam delete-access-key --user-name {username} "
                    f"--access-key-id {key['AccessKeyId']}",
                    cis_ref="CIS 1.14",
                ))

        # Multiple active keys
        active_keys = [k for k in user.get("AccessKeys", []) if k["Status"] == "Active"]
        if len(active_keys) > 1:
            self._add(Finding(
                "IAM", "IAM-KEY-02",
                f"User '{username}' has {len(active_keys)} active access keys",
                MEDIUM, arn,
                f"User '{username}' has multiple active access keys. Best practice is to "
                "have at most one active key per user to limit the attack surface.",
                f"Active keys: {', '.join(k['AccessKeyId'] for k in active_keys)}",
                f"Deactivate unused keys: aws iam update-access-key --user-name {username} "
                f"--access-key-id <key-id> --status Inactive",
                cis_ref="CIS 1.13",
            ))

        # Overly permissive attached policies
        admin_policies = {"AdministratorAccess", "PowerUserAccess"}
        for pol in user.get("AttachedPolicies", []):
            if pol["PolicyName"] in admin_policies:
                # Service accounts with admin = critical
                is_svc = username.startswith("svc-") or user.get("PasswordLastUsed") is None
                self._add(Finding(
                    "IAM", "IAM-POL-01",
                    f"User '{username}' has '{pol['PolicyName']}' attached directly",
                    CRITICAL if (pol["PolicyName"] == "AdministratorAccess" and is_svc) else HIGH,
                    arn,
                    f"The managed policy '{pol['PolicyName']}' is attached directly to user "
                    f"'{username}'. Direct policy attachment is harder to audit than "
                    "group-based access. AdministratorAccess grants unrestricted permissions.",
                    f"AttachedPolicy={pol['PolicyArn']}",
                    f"Detach the policy and use a group with least-privilege permissions: "
                    f"aws iam detach-user-policy --user-name {username} "
                    f"--policy-arn {pol['PolicyArn']}",
                    cis_ref="CIS 1.15",
                ))

        # Overly permissive inline policies
        for inline in user.get("InlinePolicies", []):
            doc = inline.get("PolicyDocument", {})
            for stmt in doc.get("Statement", []):
                if stmt.get("Effect") == "Allow":
                    action = stmt.get("Action", "")
                    resource = stmt.get("Resource", "")
                    if action in ("*", ["*"]) or (isinstance(action, str) and action.endswith(":*")):
                        self._add(Finding(
                            "IAM", "IAM-POL-02",
                            f"User '{username}' has overly permissive inline policy '{inline['PolicyName']}'",
                            HIGH, arn,
                            f"Inline policy '{inline['PolicyName']}' grants broad permissions "
                            f"(Action={action}, Resource={resource}). Inline policies bypass "
                            "group-level governance and are harder to manage at scale.",
                            f"PolicyName={inline['PolicyName']}, Action={action}, Resource={resource}",
                            f"Replace the inline policy with a scoped managed policy attached via a group.",
                        ))

    def _check_managed_policy(self, policy):
        doc = policy.get("Document", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow" and stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                self._add(Finding(
                    "IAM", "IAM-POL-03",
                    f"Custom managed policy '{policy['PolicyName']}' grants Action:* on Resource:*",
                    HIGH, policy["PolicyArn"],
                    f"The customer-managed policy '{policy['PolicyName']}' allows all actions on "
                    "all resources. This is equivalent to AdministratorAccess and violates "
                    "the principle of least privilege.",
                    f"Statement: Effect=Allow, Action=*, Resource=*",
                    f"Review and scope down the policy: aws iam get-policy-version "
                    f"--policy-arn {policy['PolicyArn']} --version-id v1",
                ))

    def _enrich_iam_user(self, iam, user):
        """Fetch additional details for a live IAM user."""
        username = user["UserName"]
        detail = {
            "UserName": username,
            "Arn": user["Arn"],
            "CreateDate": user["CreateDate"].isoformat() if hasattr(user["CreateDate"], "isoformat") else str(user["CreateDate"]),
            "PasswordLastUsed": (
                user["PasswordLastUsed"].isoformat()
                if user.get("PasswordLastUsed") and hasattr(user["PasswordLastUsed"], "isoformat")
                else user.get("PasswordLastUsed")
            ),
            "AccessKeys": [],
            "MFAEnabled": False,
            "AttachedPolicies": [],
            "InlinePolicies": [],
            "Groups": [],
        }
        # MFA
        mfa = iam.list_mfa_devices(UserName=username)
        detail["MFAEnabled"] = len(mfa.get("MFADevices", [])) > 0
        # Access keys
        keys = iam.list_access_keys(UserName=username)
        for k in keys.get("AccessKeyMetadata", []):
            detail["AccessKeys"].append({
                "AccessKeyId": k["AccessKeyId"],
                "Status": k["Status"],
                "CreateDate": k["CreateDate"].isoformat() if hasattr(k["CreateDate"], "isoformat") else str(k["CreateDate"]),
            })
        # Attached policies
        pols = iam.list_attached_user_policies(UserName=username)
        detail["AttachedPolicies"] = pols.get("AttachedPolicies", [])
        # Inline policies
        inline_names = iam.list_user_policies(UserName=username).get("PolicyNames", [])
        for pname in inline_names:
            pdoc = iam.get_user_policy(UserName=username, PolicyName=pname)
            detail["InlinePolicies"].append({
                "PolicyName": pname,
                "PolicyDocument": pdoc["PolicyDocument"],
            })
        return detail

    # ------------------------------------------------------------------
    # S3 Checks
    # ------------------------------------------------------------------
    def audit_s3(self):
        """Run all S3 bucket security checks."""
        print("[*] Auditing S3 bucket configurations...")

        if self.demo:
            buckets = self.mock_data["s3"]["buckets"]
        else:
            s3 = self.session.client("s3")
            buckets = self._list_s3_buckets(s3)

        for bucket in buckets:
            self._check_s3_bucket(bucket)

    def _list_s3_buckets(self, s3):
        """Enumerate S3 buckets and gather their configurations (live mode)."""
        result = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            info = {
                "Name": name,
                "CreationDate": b["CreationDate"].isoformat(),
                "Encryption": None,
                "Versioning": "Disabled",
                "Logging": False,
                "PublicACL": False,
                "PublicPolicy": False,
                "PublicAccessBlock": {},
                "LifecycleRules": False,
            }
            try:
                loc = s3.get_bucket_location(Bucket=name)
                info["Region"] = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                info["Region"] = "unknown"

            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                if rules:
                    info["Encryption"] = {
                        "SSEAlgorithm": rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                    }
            except ClientError:
                pass

            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                info["Versioning"] = ver.get("Status", "Disabled")
            except ClientError:
                pass

            try:
                s3.get_bucket_logging(Bucket=name)
                info["Logging"] = True
            except ClientError:
                pass

            try:
                pab = s3.get_public_access_block(Bucket=name)
                info["PublicAccessBlock"] = pab["PublicAccessBlockConfiguration"]
            except ClientError:
                info["PublicAccessBlock"] = {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }

            result.append(info)
        return result

    def _check_s3_bucket(self, bucket):
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"
        pab = bucket.get("PublicAccessBlock", {})

        # Public access block not fully enabled
        all_blocked = all([
            pab.get("BlockPublicAcls"),
            pab.get("IgnorePublicAcls"),
            pab.get("BlockPublicPolicy"),
            pab.get("RestrictPublicBuckets"),
        ])
        if not all_blocked:
            disabled = [k for k, v in pab.items() if not v]
            self._add(Finding(
                "S3", "S3-PAB-01",
                f"Bucket '{name}' does not have all S3 Block Public Access settings enabled",
                HIGH, arn,
                f"Not all four Block Public Access settings are enabled for bucket '{name}'. "
                "This leaves the bucket potentially exposed to public access via ACLs or "
                "bucket policies.",
                f"Disabled settings: {', '.join(disabled)}",
                f"aws s3api put-public-access-block --bucket {name} "
                "--public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,"
                "BlockPublicPolicy=true,RestrictPublicBuckets=true",
                cis_ref="CIS 2.1.5",
            ))

        # Public ACL
        if bucket.get("PublicACL"):
            self._add(Finding(
                "S3", "S3-ACL-01",
                f"Bucket '{name}' has a public ACL",
                CRITICAL, arn,
                f"Bucket '{name}' has an ACL that grants access to the public. "
                "This means anyone on the internet can read or list objects.",
                "PublicACL=True",
                f"aws s3api put-bucket-acl --bucket {name} --acl private",
                cis_ref="CIS 2.1.5",
            ))

        # Public bucket policy
        if bucket.get("PublicPolicy"):
            self._add(Finding(
                "S3", "S3-POL-01",
                f"Bucket '{name}' has a public bucket policy",
                CRITICAL if not name.endswith("-assets") else MEDIUM,
                arn,
                f"Bucket '{name}' has a bucket policy that allows public access. "
                "Review the policy to ensure it is intentional and scoped correctly.",
                "PublicPolicy=True",
                f"aws s3api get-bucket-policy --bucket {name} --output json",
            ))

        # Encryption not enabled
        if not bucket.get("Encryption"):
            self._add(Finding(
                "S3", "S3-ENC-01",
                f"Bucket '{name}' does not have default encryption enabled",
                HIGH, arn,
                f"Bucket '{name}' does not have server-side encryption configured as "
                "default. Objects uploaded without explicit encryption headers will be "
                "stored unencrypted.",
                "Encryption=None",
                f"aws s3api put-bucket-encryption --bucket {name} "
                "--server-side-encryption-configuration "
                "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
                cis_ref="CIS 2.1.1",
            ))

        # Versioning not enabled
        if bucket.get("Versioning") != "Enabled":
            self._add(Finding(
                "S3", "S3-VER-01",
                f"Bucket '{name}' does not have versioning enabled",
                MEDIUM, arn,
                f"Bucket '{name}' versioning status is '{bucket.get('Versioning', 'Disabled')}'. "
                "Without versioning, accidental deletions and overwrites are permanent.",
                f"Versioning={bucket.get('Versioning', 'Disabled')}",
                f"aws s3api put-bucket-versioning --bucket {name} "
                "--versioning-configuration Status=Enabled",
            ))

        # Logging not enabled
        if not bucket.get("Logging"):
            self._add(Finding(
                "S3", "S3-LOG-01",
                f"Bucket '{name}' does not have access logging enabled",
                LOW, arn,
                f"Bucket '{name}' does not have server access logging configured. "
                "Without logging, there is no audit trail of who accessed or modified "
                "objects in the bucket.",
                "Logging=False",
                f"aws s3api put-bucket-logging --bucket {name} "
                f"--bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"{name}/\"}}}}'",
                cis_ref="CIS 2.1.3 (related)",
            ))

    # ------------------------------------------------------------------
    # EC2 Checks
    # ------------------------------------------------------------------
    def audit_ec2(self):
        """Run all EC2 and VPC security checks."""
        print("[*] Auditing EC2 and VPC configurations...")

        if self.demo:
            data = self.mock_data["ec2"]
            for sg in data["security_groups"]:
                self._check_security_group(sg)
            for vol in data["ebs_volumes"]:
                self._check_ebs_volume(vol)
            for inst in data["instances"]:
                self._check_instance(inst)
        else:
            ec2 = self.session.client("ec2", region_name=self.region)
            # Security groups
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                self._check_security_group(sg)
            # EBS volumes
            vols = ec2.describe_volumes()["Volumes"]
            for vol in vols:
                vol_info = {
                    "VolumeId": vol["VolumeId"],
                    "Size": vol["Size"],
                    "State": vol["State"],
                    "Encrypted": vol["Encrypted"],
                    "KmsKeyId": vol.get("KmsKeyId"),
                    "Attachments": vol.get("Attachments", []),
                    "Tags": vol.get("Tags", []),
                }
                self._check_ebs_volume(vol_info)

    def _check_security_group(self, sg):
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "")
        arn = f"arn:aws:ec2:{self.region}:ACCOUNT:security-group/{sg_id}"

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    # Check if any sensitive port falls in range
                    for port, service in SENSITIVE_PORTS.items():
                        if from_port <= port <= to_port:
                            sev = CRITICAL if port in (22, 3389, 3306, 5432) else HIGH
                            self._add(Finding(
                                "EC2", "EC2-SG-01",
                                f"Security group '{sg_name}' ({sg_id}) allows {service} "
                                f"(port {port}) from 0.0.0.0/0",
                                sev, arn,
                                f"Security group '{sg_name}' has an inbound rule allowing "
                                f"traffic on port {port} ({service}) from any IP address. "
                                f"This exposes the service to the entire internet.",
                                f"IpProtocol={rule.get('IpProtocol')}, Port={port}, "
                                f"Source=0.0.0.0/0",
                                f"Restrict access to known IPs: aws ec2 revoke-security-group-ingress "
                                f"--group-id {sg_id} --protocol tcp --port {port} --cidr 0.0.0.0/0 && "
                                f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
                                f"--protocol tcp --port {port} --cidr <trusted-cidr>/32",
                                cis_ref="CIS 5.2" if port == 22 else ("CIS 5.3" if port == 3389 else None),
                            ))

    def _check_ebs_volume(self, vol):
        vol_id = vol["VolumeId"]
        arn = f"arn:aws:ec2:{self.region}:ACCOUNT:volume/{vol_id}"
        name_tag = next((t["Value"] for t in vol.get("Tags", []) if t["Key"] == "Name"), vol_id)

        if not vol.get("Encrypted"):
            attached = vol.get("Attachments", [])
            inst_info = f" (attached to {attached[0]['InstanceId']})" if attached else " (unattached)"
            self._add(Finding(
                "EC2", "EC2-EBS-01",
                f"EBS volume '{name_tag}' ({vol_id}) is not encrypted",
                HIGH, arn,
                f"EBS volume {vol_id}{inst_info} is not encrypted. Data at rest on this "
                "volume is accessible if the underlying hardware is compromised or "
                "if a snapshot is shared.",
                f"Encrypted=False, Size={vol['Size']}GB",
                "Create an encrypted copy: aws ec2 create-snapshot --volume-id "
                f"{vol_id} && aws ec2 copy-snapshot --encrypted --source-snapshot-id "
                "<snap-id> && create new encrypted volume from snapshot.",
                cis_ref="CIS 2.2.1",
            ))

        # Orphaned volumes
        if vol.get("State") == "available" and not vol.get("Attachments"):
            self._add(Finding(
                "EC2", "EC2-EBS-02",
                f"EBS volume '{name_tag}' ({vol_id}) is unattached (orphaned)",
                LOW, arn,
                f"EBS volume {vol_id} is in 'available' state with no attachments. "
                "Orphaned volumes incur costs and may contain sensitive data.",
                f"State=available, Attachments=[]",
                f"Review and delete if unneeded: aws ec2 delete-volume --volume-id {vol_id}",
            ))

    def _check_instance(self, inst):
        inst_id = inst["InstanceId"]
        name_tag = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), inst_id)

        if inst.get("PublicIpAddress") and inst.get("SubnetType") == "private":
            self._add(Finding(
                "EC2", "EC2-NET-01",
                f"Instance '{name_tag}' ({inst_id}) has a public IP in a private subnet",
                HIGH,
                f"arn:aws:ec2:{self.region}:ACCOUNT:instance/{inst_id}",
                f"Instance {inst_id} in subnet '{inst.get('SubnetId')}' (labeled private) "
                f"has a public IP address ({inst['PublicIpAddress']}). This may indicate "
                "a misconfiguration that exposes an internal workload to the internet.",
                f"PublicIp={inst['PublicIpAddress']}, Subnet={inst.get('SubnetId')}",
                "Disassociate the public IP or move the instance to a public subnet "
                "behind a load balancer if it needs internet-facing access.",
            ))

    # ------------------------------------------------------------------
    # CloudTrail Checks
    # ------------------------------------------------------------------
    def audit_cloudtrail(self):
        """Run CloudTrail logging configuration checks."""
        print("[*] Auditing CloudTrail configuration...")

        if self.demo:
            trails = self.mock_data["cloudtrail"]["trails"]
        else:
            ct = self.session.client("cloudtrail", region_name=self.region)
            trails = ct.describe_trails().get("trailList", [])

        if not trails:
            self._add(Finding(
                "CloudTrail", "CT-01", "No CloudTrail trail configured",
                CRITICAL,
                f"arn:aws:cloudtrail:{self.region}:ACCOUNT",
                "No CloudTrail trail exists in this region. Without CloudTrail, API "
                "activity is not logged and security incidents cannot be investigated.",
                "describe_trails returned empty list",
                f"aws cloudtrail create-trail --name org-trail --s3-bucket-name "
                f"<log-bucket> --is-multi-region-trail --enable-log-file-validation && "
                f"aws cloudtrail start-logging --name org-trail",
                cis_ref="CIS 3.1",
            ))
            return

        for trail in trails:
            self._check_trail(trail)

    def _check_trail(self, trail):
        name = trail.get("Name", "unknown")
        arn = trail.get("TrailARN", f"arn:aws:cloudtrail:{self.region}:ACCOUNT:trail/{name}")

        if not trail.get("IsMultiRegionTrail"):
            self._add(Finding(
                "CloudTrail", "CT-MR-01",
                f"Trail '{name}' is not multi-region",
                HIGH, arn,
                f"CloudTrail trail '{name}' is not configured for multi-region logging. "
                "API calls in other regions will not be captured, creating blind spots "
                "for incident response.",
                f"IsMultiRegionTrail=False",
                f"aws cloudtrail update-trail --name {name} --is-multi-region-trail",
                cis_ref="CIS 3.1",
            ))

        if not trail.get("LogFileValidationEnabled"):
            self._add(Finding(
                "CloudTrail", "CT-LFV-01",
                f"Trail '{name}' does not have log file validation enabled",
                MEDIUM, arn,
                f"Log file validation is not enabled for trail '{name}'. Without validation, "
                "an attacker who gains access to the log bucket could modify or delete "
                "log files without detection.",
                f"LogFileValidationEnabled=False",
                f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
                cis_ref="CIS 3.2",
            ))

        if not trail.get("KmsKeyId"):
            self._add(Finding(
                "CloudTrail", "CT-ENC-01",
                f"Trail '{name}' logs are not encrypted with a customer-managed KMS key",
                MEDIUM, arn,
                f"CloudTrail logs for trail '{name}' are encrypted with the default S3 "
                "encryption (SSE-S3) rather than a customer-managed KMS key. Using a "
                "CMK provides additional access controls via KMS key policy.",
                f"KmsKeyId=None",
                f"aws cloudtrail update-trail --name {name} --kms-key-id <kms-key-arn>",
                cis_ref="CIS 3.7",
            ))

        if self.demo and not trail.get("IsLogging", True):
            self._add(Finding(
                "CloudTrail", "CT-LOG-01",
                f"Trail '{name}' is not actively logging",
                CRITICAL, arn,
                f"CloudTrail trail '{name}' exists but is not currently logging. "
                "No API activity is being recorded.",
                "IsLogging=False",
                f"aws cloudtrail start-logging --name {name}",
                cis_ref="CIS 3.1",
            ))

    # ------------------------------------------------------------------
    # RDS Checks
    # ------------------------------------------------------------------
    def audit_rds(self):
        """Run RDS database security checks."""
        print("[*] Auditing RDS configurations...")

        if self.demo:
            instances = self.mock_data["rds"]["instances"]
        else:
            rds = self.session.client("rds", region_name=self.region)
            instances = rds.describe_db_instances().get("DBInstances", [])

        for db in instances:
            self._check_rds_instance(db)

    def _check_rds_instance(self, db):
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn",
                     f"arn:aws:rds:{self.region}:ACCOUNT:db:{db_id}")
        engine = db.get("Engine", "unknown")

        if db.get("PubliclyAccessible"):
            self._add(Finding(
                "RDS", "RDS-PUB-01",
                f"RDS instance '{db_id}' is publicly accessible",
                CRITICAL, arn,
                f"RDS instance '{db_id}' ({engine}) is configured with "
                "PubliclyAccessible=True. Combined with a permissive security group, "
                "the database could be reachable from the internet.",
                f"PubliclyAccessible=True, Engine={engine}",
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--no-publicly-accessible --apply-immediately",
            ))

        if not db.get("StorageEncrypted"):
            self._add(Finding(
                "RDS", "RDS-ENC-01",
                f"RDS instance '{db_id}' storage is not encrypted",
                HIGH, arn,
                f"RDS instance '{db_id}' does not have storage encryption enabled. "
                "Data at rest, including backups and snapshots, is not encrypted.",
                f"StorageEncrypted=False",
                "Encryption cannot be enabled on an existing instance. Create an "
                f"encrypted snapshot and restore: aws rds create-db-snapshot "
                f"--db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-snap "
                f"&& aws rds copy-db-snapshot --source-db-snapshot-identifier {db_id}-snap "
                f"--target-db-snapshot-identifier {db_id}-snap-encrypted --kms-key-id <key>",
                cis_ref="CIS 2.3.1",
            ))

        if db.get("BackupRetentionPeriod", 0) == 0:
            self._add(Finding(
                "RDS", "RDS-BAK-01",
                f"RDS instance '{db_id}' has no automated backups (retention = 0)",
                HIGH, arn,
                f"RDS instance '{db_id}' has a backup retention period of 0 days, "
                "meaning automated backups are disabled. In the event of data loss "
                "or corruption, point-in-time recovery is not possible.",
                f"BackupRetentionPeriod=0",
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--backup-retention-period 7 --apply-immediately",
            ))
        elif db.get("BackupRetentionPeriod", 0) < 7:
            self._add(Finding(
                "RDS", "RDS-BAK-02",
                f"RDS instance '{db_id}' backup retention is only {db['BackupRetentionPeriod']} day(s)",
                MEDIUM, arn,
                f"RDS instance '{db_id}' has a backup retention of only "
                f"{db['BackupRetentionPeriod']} day(s). Best practice is at least 7 days.",
                f"BackupRetentionPeriod={db['BackupRetentionPeriod']}",
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--backup-retention-period 7 --apply-immediately",
            ))

        if not db.get("MultiAZ"):
            self._add(Finding(
                "RDS", "RDS-HA-01",
                f"RDS instance '{db_id}' is not configured for Multi-AZ",
                LOW, arn,
                f"RDS instance '{db_id}' is running in a single Availability Zone. "
                "Multi-AZ provides automatic failover for production workloads.",
                f"MultiAZ=False",
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--multi-az --apply-immediately",
            ))

        if not db.get("AutoMinorVersionUpgrade"):
            self._add(Finding(
                "RDS", "RDS-UPD-01",
                f"RDS instance '{db_id}' does not have auto minor version upgrade enabled",
                LOW, arn,
                f"RDS instance '{db_id}' has AutoMinorVersionUpgrade disabled. "
                "Security patches for the database engine will not be applied automatically.",
                f"AutoMinorVersionUpgrade=False",
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--auto-minor-version-upgrade --apply-immediately",
            ))

        if not db.get("DeletionProtection"):
            self._add(Finding(
                "RDS", "RDS-DEL-01",
                f"RDS instance '{db_id}' does not have deletion protection enabled",
                MEDIUM if "prod" in db_id else LOW,
                arn,
                f"RDS instance '{db_id}' can be deleted without extra confirmation. "
                "Deletion protection prevents accidental database removal.",
                f"DeletionProtection=False",
                f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                "--deletion-protection --apply-immediately",
            ))

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_report(self, output_path=None):
        """Generate JSON audit report."""
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        report = {
            "audit_metadata": {
                "tool": "AWS Security Auditor",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": "demo" if self.demo else "live",
                "region": self.region,
                "account_id": self.mock_data["account_id"] if self.demo else "N/A",
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": dict(self.stats),
                "by_service": dict(self._count_by_service()),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

        if output_path:
            with open(output_path, "w") as fh:
                json.dump(report, fh, indent=2, default=str)
            print(f"\n[+] Report saved to {output_path}")

        return report

    def _count_by_service(self):
        counts = defaultdict(int)
        for f in self.findings:
            counts[f.service] += 1
        return counts

    def print_summary(self):
        """Print a human-readable summary to stdout."""
        print("\n" + "=" * 72)
        print("  AWS SECURITY AUDIT RESULTS")
        print("=" * 72)

        total = len(self.findings)
        print(f"\n  Total findings: {total}")
        for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
            count = self.stats.get(sev, 0)
            if count:
                print(f"    {sev:10s}: {count}")

        svc_counts = self._count_by_service()
        print(f"\n  Findings by service:")
        for svc, cnt in sorted(svc_counts.items()):
            print(f"    {svc:12s}: {cnt}")

        print("\n" + "-" * 72)
        print("  FINDINGS DETAIL")
        print("-" * 72)

        for f in self.findings:
            sev_marker = {
                CRITICAL: "[!!]",
                HIGH: "[! ]",
                MEDIUM: "[* ]",
                LOW: "[- ]",
                INFO: "[i ]",
            }.get(f.severity, "[  ]")

            print(f"\n  {sev_marker} [{f.severity}] {f.title}")
            print(f"      Service  : {f.service}")
            print(f"      Resource : {f.resource_arn}")
            print(f"      Evidence : {f.evidence}")
            if f.cis_ref:
                print(f"      CIS Ref  : {f.cis_ref}")
            print(f"      Remediate: {f.remediation}")

        print("\n" + "=" * 72)


# ===================================================================
# Main
# ===================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AWS Security Auditor - Comprehensive AWS security configuration audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo                        Run with mock data (no AWS credentials needed)
  %(prog)s --demo --output report.json   Save demo report to file
  %(prog)s --profile prod --region us-east-1   Audit a live AWS account
        """,
    )
    parser.add_argument("--profile", help="AWS CLI profile name to use")
    parser.add_argument("--region", default="us-east-1",
                        help="AWS region to audit (default: us-east-1)")
    parser.add_argument("--output", "-o", help="Output file path for JSON report")
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with mock data (no AWS credentials required)")
    args = parser.parse_args()

    print("=" * 72)
    print("  AWS Security Auditor v1.0")
    print("  Comprehensive AWS Security Configuration Audit")
    print("=" * 72)

    if args.demo:
        print("\n[*] Running in DEMO mode with mock data")
        print("[*] No AWS credentials required")
        session = None
    else:
        if not BOTO3_AVAILABLE:
            print("\n[!] ERROR: boto3 is not installed.")
            print("    Install it with: pip install boto3")
            print("    Or run with --demo to use mock data.")
            sys.exit(1)
        try:
            session_kwargs = {}
            if args.profile:
                session_kwargs["profile_name"] = args.profile
            if args.region:
                session_kwargs["region_name"] = args.region
            session = boto3.Session(**session_kwargs)
            # Verify credentials
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            print(f"\n[*] Authenticated as: {identity['Arn']}")
            print(f"[*] Account ID: {identity['Account']}")
        except (NoCredentialsError, ProfileNotFound) as e:
            print(f"\n[!] AWS credential error: {e}")
            print("    Configure credentials or run with --demo flag.")
            sys.exit(1)

    auditor = AWSSecurityAuditor(
        session=session,
        region=args.region,
        demo=args.demo,
    )

    # Run all audit modules
    auditor.audit_iam()
    auditor.audit_s3()
    auditor.audit_ec2()
    auditor.audit_cloudtrail()
    auditor.audit_rds()

    # Output
    auditor.print_summary()

    output_path = args.output or (
        f"aws-audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    )
    auditor.generate_report(output_path)

    # Exit with non-zero if critical findings exist
    if auditor.stats.get(CRITICAL, 0) > 0:
        print(f"\n[!] {auditor.stats[CRITICAL]} CRITICAL finding(s) detected.")
        sys.exit(2)


if __name__ == "__main__":
    main()
