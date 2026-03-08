# AWS Security Audit Toolkit

A comprehensive AWS security auditing toolkit that performs automated security assessments across IAM, S3, EC2, CloudTrail, and RDS services. Findings are mapped to the CIS AWS Foundations Benchmark v2.0 and include actionable remediation guidance with AWS CLI commands.

All scripts include a `--demo` mode that runs against realistic mock data, allowing the tools to be demonstrated and evaluated without AWS credentials.

---

## Project Structure

```
08-aws-security-audit/
|-- README.md                              # This file
|-- scripts/
|   |-- aws_security_auditor.py            # Main comprehensive audit tool
|   |-- iam_analyzer.py                    # Focused IAM risk analysis
|   |-- s3_bucket_scanner.py               # S3 bucket security scoring
|-- reports/
|   |-- sample-aws-audit-report.md         # Professional audit report example
|-- docs/
|   |-- aws-security-checklist.md          # Service-by-service security checklist
|   |-- aws-security-overview.md           # AWS security concepts and breach analysis
```

---

## Tools Overview

### aws_security_auditor.py

The main audit script that performs a broad security assessment across five AWS service categories. It outputs findings with severity ratings, CIS benchmark references, and generates a JSON report.

```bash
# Demo mode (no AWS credentials needed):
python3 scripts/aws_security_auditor.py --demo

# Live mode (requires configured AWS credentials):
python3 scripts/aws_security_auditor.py --profile production --region us-east-1

# Save report to a specific file:
python3 scripts/aws_security_auditor.py --demo --output audit-report.json
```

### iam_analyzer.py

A focused IAM analysis tool that produces a risk-scored report for every IAM user. It differentiates between human users and service accounts, evaluates policy permissiveness, and identifies stale credentials.

```bash
python3 scripts/iam_analyzer.py --demo
python3 scripts/iam_analyzer.py --profile production -o /tmp/audit
```

### s3_bucket_scanner.py

An S3-specific scanner that evaluates every bucket against 9 security criteria and produces a letter grade (A-F) for each bucket. It checks public access controls, encryption, versioning, logging, lifecycle rules, and CORS configuration.

```bash
python3 scripts/s3_bucket_scanner.py --demo
python3 scripts/s3_bucket_scanner.py --profile production -o /tmp/audit
```

---

## Security Checks Performed

### IAM Checks

| Check ID | Description | Severity | CIS Ref |
|----------|-------------|----------|---------|
| IAM-ROOT-01 | Root account MFA not enabled | Critical | 1.5 |
| IAM-ROOT-02 | Root account has active access keys | Critical | 1.4 |
| IAM-PP-01 | No account password policy configured | Critical | 1.8-1.11 |
| IAM-PP-02 | Password policy does not meet CIS benchmarks | Medium | 1.8-1.11 |
| IAM-MFA-01 | Console user without MFA | High | 1.10 |
| IAM-KEY-01 | Access key older than 90 days | High/Critical | 1.14 |
| IAM-KEY-02 | Multiple active access keys | Medium | 1.13 |
| IAM-POL-01 | Admin/PowerUser policy attached directly to user | High/Critical | 1.15, 1.16 |
| IAM-POL-02 | Overly permissive inline policy | High | 1.16 |
| IAM-POL-03 | Custom policy grants Action:* on Resource:* | High | 1.16 |

### S3 Checks

| Check ID | Description | Severity | CIS Ref |
|----------|-------------|----------|---------|
| S3-PAB-01 | Block Public Access not fully enabled | High | 2.1.5 |
| S3-ACL-01 | Bucket has a public ACL | Critical | 2.1.5 |
| S3-POL-01 | Bucket policy allows public access | Critical/Medium | -- |
| S3-ENC-01 | Default encryption not enabled | High | 2.1.1 |
| S3-VER-01 | Versioning not enabled | Medium | -- |
| S3-LOG-01 | Server access logging not enabled | Low | 2.1.3 |
| S3-LCR-01 | No lifecycle rules configured | Low | -- |
| S3-CORS-01 | CORS allows wildcard origin | Medium | -- |

### EC2 / VPC Checks

| Check ID | Description | Severity | CIS Ref |
|----------|-------------|----------|---------|
| EC2-SG-01 | Security group allows sensitive port from 0.0.0.0/0 | Critical/High | 5.2, 5.3 |
| EC2-EBS-01 | EBS volume not encrypted | High | 2.2.1 |
| EC2-EBS-02 | Orphaned (unattached) EBS volume | Low | -- |
| EC2-NET-01 | Instance has public IP in private subnet | High | -- |

### CloudTrail Checks

| Check ID | Description | Severity | CIS Ref |
|----------|-------------|----------|---------|
| CT-01 | No CloudTrail trail configured | Critical | 3.1 |
| CT-MR-01 | Trail is not multi-region | High | 3.1 |
| CT-LFV-01 | Log file validation not enabled | Medium | 3.2 |
| CT-ENC-01 | Logs not encrypted with customer-managed KMS key | Medium | 3.7 |
| CT-LOG-01 | Trail exists but is not actively logging | Critical | 3.1 |

### RDS Checks

| Check ID | Description | Severity | CIS Ref |
|----------|-------------|----------|---------|
| RDS-PUB-01 | RDS instance is publicly accessible | Critical | -- |
| RDS-ENC-01 | RDS storage not encrypted | High | 2.3.1 |
| RDS-BAK-01 | No automated backups (retention = 0) | High | -- |
| RDS-BAK-02 | Backup retention less than 7 days | Medium | -- |
| RDS-HA-01 | Not configured for Multi-AZ | Low | -- |
| RDS-UPD-01 | Auto minor version upgrade disabled | Low | -- |
| RDS-DEL-01 | Deletion protection not enabled | Medium/Low | -- |

---

## Severity Ratings

| Rating | Definition |
|--------|-----------|
| **Critical** | Immediate risk of account compromise or data exposure. Requires action within 24 hours. |
| **High** | Significant security weakness that could be exploited. Remediate within 1 week. |
| **Medium** | Moderate risk that should be addressed within 30 days. |
| **Low** | Minor hardening recommendation or informational finding. |
| **Info** | Informational observation, no immediate action required. |

---

## Requirements

- **Python 3.8+**
- **boto3** (only external dependency)

```bash
pip install boto3
```

For `--demo` mode, boto3 is optional. The scripts check for its availability and fall back gracefully with a clear error message if it is not installed and live mode is requested.

---

## Usage

### Demo Mode (No AWS Account Required)

All three scripts support a `--demo` flag that populates the audit with realistic mock data representing a fictional company's AWS environment. This is the recommended way to evaluate the tools:

```bash
# Run the full audit with mock data:
python3 scripts/aws_security_auditor.py --demo

# Run IAM-focused analysis:
python3 scripts/iam_analyzer.py --demo

# Run S3 bucket scanner:
python3 scripts/s3_bucket_scanner.py --demo
```

### Live Mode (Requires AWS Credentials)

To audit a real AWS account, ensure credentials are configured via the AWS CLI, environment variables, or an IAM instance profile:

```bash
# Using a named profile:
python3 scripts/aws_security_auditor.py --profile my-audit-profile --region us-east-1

# Using default credentials:
python3 scripts/aws_security_auditor.py --region us-west-2 --output audit-report.json
```

**Required IAM permissions for live auditing:**

The auditing principal needs read-only access to the services being assessed. The following AWS managed policies provide sufficient access:

- `SecurityAudit` (arn:aws:iam::aws:policy/SecurityAudit)
- `ReadOnlyAccess` (arn:aws:iam::aws:policy/ReadOnlyAccess) -- broader alternative

Alternatively, use a custom policy with these specific actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListGroupsForUser",
        "iam:ListUserTags",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketCORS",
        "s3:GetBucketTagging",
        "s3:GetLifecycleConfiguration",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:GetEbsEncryptionByDefault",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "rds:DescribeDBInstances",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Command-Line Options

All three scripts share a consistent interface:

| Flag | Description |
|------|-------------|
| `--demo` | Run with mock data (no AWS credentials needed) |
| `--profile` | AWS CLI profile name to use for authentication |
| `--region` | AWS region to audit (default: us-east-1) |
| `--output` / `-o` | Output file path for the JSON report |

---

## Sample Output

Running `python3 scripts/aws_security_auditor.py --demo` produces output similar to:

```
========================================================================
  AWS Security Auditor v1.0
  Comprehensive AWS Security Configuration Audit
========================================================================

[*] Running in DEMO mode with mock data
[*] No AWS credentials required

[*] Auditing IAM configuration...
[*] Auditing S3 bucket configurations...
[*] Auditing EC2 and VPC configurations...
[*] Auditing CloudTrail configuration...
[*] Auditing RDS configurations...

========================================================================
  AWS SECURITY AUDIT RESULTS
========================================================================

  Total findings: 35
    CRITICAL  :  6
    HIGH      : 13
    MEDIUM    : 10
    LOW       :  6

  Findings by service:
    CloudTrail  :  3
    EC2         :  7
    IAM         : 11
    RDS         :  8
    S3          :  6
```

---

## Documentation

- **[AWS Security Checklist](docs/aws-security-checklist.md):** Service-by-service checklist with CLI verification commands and CIS benchmark references
- **[AWS Security Overview](docs/aws-security-overview.md):** Shared responsibility model, security services overview, common misconfigurations, and real-world breach analysis
- **[Sample Audit Report](reports/sample-aws-audit-report.md):** Professional security audit report for a fictional company with 15 findings, a risk matrix, and a remediation roadmap

---

## How This Fits Into a Security Program

This toolkit is designed to be used as part of a broader AWS security program:

1. **Initial assessment:** Run the full audit to establish a security baseline
2. **Continuous monitoring:** Schedule periodic runs (weekly or monthly) and diff the results
3. **Incident response:** Use IAM Analyzer and S3 Scanner during investigations to quickly identify overly permissive access
4. **Compliance:** Map findings to CIS AWS Foundations Benchmark for compliance reporting
5. **Remediation tracking:** Use the JSON output to track finding resolution over time

For continuous automated compliance, complement these tools with:
- **AWS Config** with managed rules for real-time detection
- **AWS Security Hub** for centralized finding aggregation
- **EventBridge + Lambda** for automated remediation of common misconfigurations
