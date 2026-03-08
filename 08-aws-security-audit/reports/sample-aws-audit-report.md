# AWS Security Audit Report

**Client:** Acme Corporation
**Audit Date:** 2025-11-15 through 2025-11-18
**Report Date:** 2025-11-20
**Auditor:** Security Engineering Team
**Classification:** Confidential

---

## Executive Summary

Acme Corporation engaged a security audit of its Amazon Web Services (AWS) infrastructure spanning three accounts (Production, Staging, Development) across two regions (us-east-1, us-west-2). The audit assessed configurations against the CIS AWS Foundations Benchmark v2.0 and AWS security best practices.

The audit identified **15 findings** across IAM, S3, EC2, CloudTrail, and RDS services. Of these, **3 are Critical**, **5 are High**, **4 are Medium**, and **3 are Low** severity. The most urgent issues involve the root account lacking MFA, a service account with unrestricted administrator privileges, and a publicly accessible RDS database containing customer data.

Immediate remediation is recommended for all Critical and High findings. A prioritized roadmap is provided at the end of this report.

### Risk Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 3     | Immediate risk of compromise or data exposure |
| High     | 5     | Significant security weakness requiring prompt action |
| Medium   | 4     | Moderate risk, should be addressed within 30 days |
| Low      | 3     | Minor issues or hardening recommendations |
| **Total** | **15** | |

---

## Scope

### Accounts Audited

| Account | Account ID | Environment | Primary Region |
|---------|-----------|-------------|----------------|
| acme-production | 123456789012 | Production | us-east-1 |
| acme-staging | 234567890123 | Staging | us-east-1 |
| acme-development | 345678901234 | Development | us-west-2 |

### Regions Assessed
- **us-east-1** (N. Virginia) - Primary production region
- **us-west-2** (Oregon) - DR and development region

### Services Assessed
- AWS Identity and Access Management (IAM)
- Amazon Simple Storage Service (S3)
- Amazon Elastic Compute Cloud (EC2) and VPC
- AWS CloudTrail
- Amazon Relational Database Service (RDS)

### Methodology
- Automated scanning using custom audit tooling with boto3
- Manual review of IAM policies and resource configurations
- Comparison against CIS AWS Foundations Benchmark v2.0
- Review of AWS Config rules and Security Hub findings where available

---

## Findings

### Finding 1: Root Account MFA Not Enabled

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL |
| **Service** | IAM |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:iam::123456789012:root` |
| **CIS Benchmark** | CIS 1.5 - Ensure MFA is enabled for the root user account |

**Description:**
The root account for the production AWS account (123456789012) does not have multi-factor authentication (MFA) enabled. The root user has unrestricted access to all AWS services and resources. Unlike IAM users, root account permissions cannot be limited through IAM policies. An attacker who obtains root credentials would have complete control of the account, including the ability to delete all resources, exfiltrate data, and lock out all other users.

**Evidence:**
```
aws iam get-account-summary (as root)
AccountMFAEnabled: 0
```

**Remediation:**
1. Sign in to the AWS Management Console as the root user
2. Navigate to IAM > Security credentials
3. In the Multi-factor authentication (MFA) section, choose Assign MFA device
4. Select a hardware MFA device (recommended) or virtual MFA application
5. Complete the MFA setup by entering two consecutive codes

```bash
# Verify MFA is enabled after setup:
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```

**Note:** AWS strongly recommends using a hardware TOTP token (e.g., YubiKey) for root MFA rather than a virtual MFA app on a mobile device.

---

### Finding 2: Root Account Has Active Access Keys

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL |
| **Service** | IAM |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:iam::123456789012:root` |
| **CIS Benchmark** | CIS 1.4 - Ensure no root user account access key exists |

**Description:**
The root account has active programmatic access keys. These keys provide the same unrestricted access as the root console login and cannot be scoped using IAM policies. Root access keys are a high-value target for attackers and have been involved in multiple public AWS breaches. If these keys are stored in application code, configuration files, or CI/CD pipelines, they represent a severe risk of credential exposure.

**Evidence:**
```
aws iam get-account-summary
AccountAccessKeysPresent: 1
```

**Remediation:**
```bash
# List root access keys (must be run as root):
aws iam list-access-keys

# Delete the root access key:
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE

# Create an IAM user or role for any workloads currently using root keys
```

---

### Finding 3: Service Account with Unrestricted Administrator Access

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL |
| **Service** | IAM |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:iam::123456789012:user/svc-deploy-pipeline` |
| **CIS Benchmark** | CIS 1.16 - Ensure IAM policies that allow full admin privileges are not attached |

**Description:**
The service account `svc-deploy-pipeline` has the `AdministratorAccess` AWS managed policy attached directly. This account is used by the CI/CD deployment pipeline and has programmatic access only (no console password). The access key for this account is 500 days old and has never been rotated. A compromised CI/CD pipeline or leaked access key would grant an attacker full administrative control of the entire AWS account.

**Evidence:**
```
User: svc-deploy-pipeline
AttachedPolicy: arn:aws:iam::aws:policy/AdministratorAccess
AccessKey: AKIAI66QH0DHDEXAMPLE (created 500 days ago, Status: Active)
PasswordLastUsed: N/A (programmatic only)
Groups: [] (no group membership)
PermissionsBoundary: None
```

**Remediation:**
1. Create a scoped IAM policy that grants only the permissions required by the deployment pipeline
2. Attach the scoped policy via an IAM group
3. Set a permissions boundary to prevent privilege escalation
4. Rotate the access key immediately

```bash
# Detach the admin policy:
aws iam detach-user-policy \
  --user-name svc-deploy-pipeline \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Consider migrating to an IAM role with OIDC federation for the CI/CD platform
# (e.g., GitHub Actions OIDC, GitLab CI OIDC) to eliminate long-lived credentials entirely
```

---

### Finding 4: IAM User Without MFA (dev-mwilliams)

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Service** | IAM |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:iam::123456789012:user/dev-mwilliams` |
| **CIS Benchmark** | CIS 1.10 - Ensure MFA is enabled for all IAM users with console access |

**Description:**
IAM user `dev-mwilliams` has console access (password enabled, last login 5 days ago) but no MFA device configured. This user also has the `PowerUserAccess` policy and an inline policy granting `s3:*` on all resources. Without MFA, a compromised password gives an attacker broad access to AWS services.

**Evidence:**
```
User: dev-mwilliams
PasswordLastUsed: 5 days ago
MFAEnabled: False
AttachedPolicies: PowerUserAccess
InlinePolicies: dev-full-s3 (Action: s3:*, Resource: *)
AccessKeys: 2 active (ages: 300d, 100d)
```

**Remediation:**
```bash
# Enable virtual MFA for the user:
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name dev-mwilliams \
  --outfile /tmp/mfa-qr.png \
  --bootstrap-method QRCodePNG

# After scanning the QR code, enable the device:
aws iam enable-mfa-device \
  --user-name dev-mwilliams \
  --serial-number arn:aws:iam::123456789012:mfa/dev-mwilliams \
  --authentication-code1 <code1> \
  --authentication-code2 <code2>
```

---

### Finding 5: Stale IAM User Account (former-contractor)

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Service** | IAM |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:iam::123456789012:user/former-contractor` |
| **CIS Benchmark** | CIS 1.12 - Ensure credentials unused for 45 days or greater are disabled |

**Description:**
IAM user `former-contractor` has not logged in via console for 180 days and the access key was last used 150 days ago. The account retains `AmazonEC2FullAccess`, `AmazonS3FullAccess`, and an inline policy granting `rds:*`. This appears to be a former contractor account that was never offboarded, representing both a security risk (stale credentials) and a compliance violation.

**Evidence:**
```
User: former-contractor
PasswordLastUsed: 180 days ago
AccessKey: AKIAI77QH1DHEEXAMPLE (400 days old, last used 150 days ago)
MFAEnabled: False
Policies: AmazonEC2FullAccess, AmazonS3FullAccess, inline rds:*
```

**Remediation:**
```bash
# Immediately disable the access key:
aws iam update-access-key \
  --user-name former-contractor \
  --access-key-id AKIAI77QH1DHEEXAMPLE \
  --status Inactive

# Remove console access:
aws iam delete-login-profile --user-name former-contractor

# After confirming no active workloads depend on this user, delete it:
aws iam delete-user --user-name former-contractor
```

---

### Finding 6: S3 Bucket Publicly Accessible via ACL and Policy (acme-website-assets)

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Service** | S3 |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:s3:::acme-website-assets` |
| **CIS Benchmark** | CIS 2.1.5 - Ensure S3 bucket access is restricted |

**Description:**
The bucket `acme-website-assets` has both a public ACL (AllUsers:READ) and a bucket policy allowing `s3:GetObject` to Principal `*`. All four S3 Block Public Access settings are disabled. While this bucket serves static website content and public read access may be intentional, the bucket also lacks encryption, versioning, and access logging.

**Evidence:**
```
BlockPublicAcls: False
IgnorePublicAcls: False
BlockPublicPolicy: False
RestrictPublicBuckets: False
ACL: AllUsers:READ
BucketPolicy: Principal=*, Action=s3:GetObject
Encryption: None
Versioning: Suspended
Logging: Disabled
```

**Remediation:**
If public access is intentional (static website hosting), migrate to CloudFront with an Origin Access Identity (OAI) to avoid direct public S3 access. At minimum:

```bash
# Enable default encryption:
aws s3api put-bucket-encryption --bucket acme-website-assets \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Enable versioning:
aws s3api put-bucket-versioning --bucket acme-website-assets \
  --versioning-configuration Status=Enabled

# Enable access logging:
aws s3api put-bucket-logging --bucket acme-website-assets \
  --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"acme-access-logs","TargetPrefix":"website-assets/"}}'
```

---

### Finding 7: S3 Bucket with Public Write Access (acme-dev-scratch)

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Service** | S3 |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:s3:::acme-dev-scratch` |

**Description:**
The bucket `acme-dev-scratch` has a bucket policy granting `s3:GetObject` AND `s3:PutObject` to Principal `*`. Any unauthenticated user on the internet can read from and write to this bucket. This is a severe misconfiguration that could lead to data exfiltration, malware hosting, or unauthorized data storage. The bucket has no encryption, no versioning, and no logging.

**Evidence:**
```
BucketPolicy Statement:
  Effect: Allow
  Principal: *
  Action: ["s3:GetObject", "s3:PutObject"]
  Resource: arn:aws:s3:::acme-dev-scratch/*
BlockPublicAccess: All disabled
Encryption: None
Versioning: Disabled
```

**Remediation:**
```bash
# Immediately restrict the bucket policy:
aws s3api delete-bucket-policy --bucket acme-dev-scratch

# Enable Block Public Access:
aws s3api put-public-access-block --bucket acme-dev-scratch \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable encryption:
aws s3api put-bucket-encryption --bucket acme-dev-scratch \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Review bucket contents for unauthorized objects:
aws s3 ls s3://acme-dev-scratch/ --recursive
```

---

### Finding 8: Security Group Allows SSH from 0.0.0.0/0

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Service** | EC2 |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f00002` |
| **CIS Benchmark** | CIS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 |

**Description:**
Security group `ssh-management` (sg-0a1b2c3d4e5f00002) allows inbound SSH (port 22) traffic from any IP address (0.0.0.0/0). This exposes SSH to the entire internet, making it a target for brute-force attacks and exploitation of SSH vulnerabilities. The bastion host instance (i-0abc123def4567892) uses this security group.

**Evidence:**
```
SecurityGroup: ssh-management (sg-0a1b2c3d4e5f00002)
IpPermissions:
  - IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0
Associated Instances: i-0abc123def4567892 (bastion-host)
```

**Remediation:**
```bash
# Revoke the open rule:
aws ec2 revoke-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f00002 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Allow SSH only from the corporate VPN CIDR:
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f00002 \
  --protocol tcp --port 22 --cidr 203.0.113.0/24

# Better alternative: Replace bastion host with AWS Systems Manager Session Manager
# to eliminate SSH exposure entirely.
```

---

### Finding 9: Security Group Allows MySQL from 0.0.0.0/0

| Field | Detail |
|-------|--------|
| **Severity** | HIGH |
| **Service** | EC2 |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f00003` |

**Description:**
Security group `database-sg` (sg-0a1b2c3d4e5f00003) allows inbound MySQL traffic (port 3306) from 0.0.0.0/0. Database ports should never be exposed to the public internet. Combined with the publicly accessible RDS finding (Finding 12), this creates a path for direct database access from the internet.

**Evidence:**
```
SecurityGroup: database-sg (sg-0a1b2c3d4e5f00003)
IpPermissions:
  - IpProtocol: tcp, FromPort: 3306, ToPort: 3306, CidrIp: 0.0.0.0/0
  - IpProtocol: tcp, FromPort: 5432, ToPort: 5432, CidrIp: 10.0.0.0/16 (OK)
```

**Remediation:**
```bash
aws ec2 revoke-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f00003 \
  --protocol tcp --port 3306 --cidr 0.0.0.0/0

# Allow only from the application tier:
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f00003 \
  --protocol tcp --port 3306 \
  --source-group sg-0a1b2c3d4e5f00001
```

---

### Finding 10: Unencrypted EBS Volumes

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **Service** | EC2 |
| **Account** | acme-production (123456789012) |
| **Resource ARNs** | `arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc123def4567891` (500 GB, attached to prod-db-01), `arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc123def4567892` (50 GB, attached to bastion), `arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc123def4567893` (200 GB, orphaned) |
| **CIS Benchmark** | CIS 2.2.1 - Ensure EBS volume encryption is enabled |

**Description:**
Three EBS volumes are not encrypted at rest. The most concerning is vol-0abc123def4567891 (500 GB), which is the data volume for the production database server (prod-db-01). Additionally, vol-0abc123def4567893 is a 200 GB orphaned volume in `available` state with no attachments, which may contain sensitive data from a previous workload.

**Evidence:**
```
vol-0abc123def4567891: 500GB, Encrypted=False, attached to i-0abc123def4567891 (prod-db-01)
vol-0abc123def4567892:  50GB, Encrypted=False, attached to i-0abc123def4567892 (bastion)
vol-0abc123def4567893: 200GB, Encrypted=False, State=available (orphaned)
```

**Remediation:**
EBS encryption cannot be toggled on an existing volume. The process requires creating an encrypted copy:

```bash
# Enable default EBS encryption for all new volumes in the region:
aws ec2 enable-ebs-encryption-by-default

# For existing volumes, create a snapshot, copy with encryption, create new volume:
aws ec2 create-snapshot --volume-id vol-0abc123def4567891 \
  --description "Pre-encryption snapshot"

aws ec2 copy-snapshot \
  --source-region us-east-1 \
  --source-snapshot-id snap-EXAMPLE \
  --encrypted \
  --kms-key-id alias/aws/ebs \
  --description "Encrypted copy"

# Delete the orphaned volume after review:
aws ec2 delete-volume --volume-id vol-0abc123def4567893
```

---

### Finding 11: CloudTrail Not Configured for Multi-Region

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **Service** | CloudTrail |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:cloudtrail:us-east-1:123456789012:trail/acme-org-trail` |
| **CIS Benchmark** | CIS 3.1 - Ensure CloudTrail is enabled in all regions |

**Description:**
The CloudTrail trail `acme-org-trail` is only configured for us-east-1. API calls made in other regions (including us-west-2, which hosts backup infrastructure) are not being logged. An attacker could operate in unmonitored regions to avoid detection. Additionally, CloudTrail logs are not encrypted with a customer-managed KMS key.

**Evidence:**
```
Trail: acme-org-trail
IsMultiRegionTrail: False
IsLogging: True
LogFileValidationEnabled: True
KmsKeyId: None (using default S3 encryption)
```

**Remediation:**
```bash
# Enable multi-region logging:
aws cloudtrail update-trail \
  --name acme-org-trail \
  --is-multi-region-trail

# Add KMS encryption:
aws cloudtrail update-trail \
  --name acme-org-trail \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/<key-id>
```

---

### Finding 12: Publicly Accessible RDS Instance (acme-dev-postgres)

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL (elevated from High due to combination with Finding 9) |
| **Service** | RDS |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:rds:us-east-1:123456789012:db:acme-dev-postgres` |

**Description:**
RDS instance `acme-dev-postgres` (PostgreSQL 14.5) is configured with `PubliclyAccessible=True`. The instance also has no storage encryption, no automated backups (retention period = 0), no deletion protection, and auto minor version upgrade is disabled. This combination of misconfigurations represents a severe risk: the database is directly accessible from the internet, unencrypted, and has no backup or recovery capability.

**Evidence:**
```
DBInstance: acme-dev-postgres
Engine: postgres 14.5
PubliclyAccessible: True
StorageEncrypted: False
BackupRetentionPeriod: 0
MultiAZ: False
DeletionProtection: False
AutoMinorVersionUpgrade: False
```

**Remediation:**
```bash
# Disable public access immediately:
aws rds modify-db-instance \
  --db-instance-identifier acme-dev-postgres \
  --no-publicly-accessible \
  --apply-immediately

# Enable backups:
aws rds modify-db-instance \
  --db-instance-identifier acme-dev-postgres \
  --backup-retention-period 7 \
  --apply-immediately

# Enable deletion protection:
aws rds modify-db-instance \
  --db-instance-identifier acme-dev-postgres \
  --deletion-protection \
  --apply-immediately

# Note: Encryption requires creating an encrypted snapshot and restoring.
```

---

### Finding 13: RDS Instances Without Storage Encryption

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **Service** | RDS |
| **Account** | acme-production (123456789012) |
| **Resource ARNs** | `arn:aws:rds:us-east-1:123456789012:db:acme-dev-postgres`, `arn:aws:rds:us-east-1:123456789012:db:acme-staging-mysql` |
| **CIS Benchmark** | CIS 2.3.1 - Ensure RDS encryption is enabled |

**Description:**
Two RDS instances (`acme-dev-postgres` and `acme-staging-mysql`) do not have storage encryption enabled. Data at rest, including automated backups, read replicas, and snapshots, is stored unencrypted. If snapshots are shared or the underlying storage is compromised, data is exposed in cleartext.

**Evidence:**
```
acme-dev-postgres:   StorageEncrypted=False, Engine=postgres 14.5
acme-staging-mysql:  StorageEncrypted=False, Engine=mysql 5.7.38
```

**Remediation:**
RDS storage encryption cannot be enabled on an existing instance. The remediation requires a snapshot-restore workflow:

```bash
# Create a snapshot:
aws rds create-db-snapshot \
  --db-instance-identifier acme-staging-mysql \
  --db-snapshot-identifier acme-staging-mysql-pre-encryption

# Copy snapshot with encryption:
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier acme-staging-mysql-pre-encryption \
  --target-db-snapshot-identifier acme-staging-mysql-encrypted \
  --kms-key-id alias/aws/rds

# Restore from encrypted snapshot:
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier acme-staging-mysql-encrypted \
  --db-snapshot-identifier acme-staging-mysql-encrypted
```

---

### Finding 14: Security Group Allows RDP from 0.0.0.0/0

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM |
| **Service** | EC2 |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:ec2:us-east-1:123456789012:security-group/sg-0a1b2c3d4e5f00004` |
| **CIS Benchmark** | CIS 5.3 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 |

**Description:**
Security group `rdp-windows` (sg-0a1b2c3d4e5f00004) allows inbound RDP (port 3389) from any IP address. RDP is a frequent target for brute-force attacks and has been exploited in several ransomware campaigns (e.g., BlueKeep CVE-2019-0708).

**Evidence:**
```
SecurityGroup: rdp-windows (sg-0a1b2c3d4e5f00004)
IpPermissions:
  - IpProtocol: tcp, FromPort: 3389, ToPort: 3389, CidrIp: 0.0.0.0/0
```

**Remediation:**
```bash
aws ec2 revoke-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f00004 \
  --protocol tcp --port 3389 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id sg-0a1b2c3d4e5f00004 \
  --protocol tcp --port 3389 --cidr 203.0.113.0/24
```

---

### Finding 15: IAM Password Policy Does Not Meet CIS Benchmarks

| Field | Detail |
|-------|--------|
| **Severity** | LOW |
| **Service** | IAM |
| **Account** | acme-production (123456789012) |
| **Resource ARN** | `arn:aws:iam::123456789012:account` |
| **CIS Benchmark** | CIS 1.8-1.11 |

**Description:**
The account password policy has several settings that fall short of CIS recommendations. The minimum password length is 8 (should be 14), uppercase characters are not required, symbols are not required, no maximum password age is set, and password reuse prevention is not configured.

**Evidence:**
```
MinimumPasswordLength: 8 (recommended: >= 14)
RequireSymbols: False
RequireUppercaseCharacters: False
MaxPasswordAge: 0 (no expiration; recommended: <= 90)
PasswordReusePrevention: 0 (recommended: >= 24)
```

**Remediation:**
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --allow-users-to-change-password
```

---

## Risk Matrix

| Finding | Service | Severity | Likelihood | Impact | CVSS-like Score |
|---------|---------|----------|-----------|--------|-----------------|
| F1: Root MFA Missing | IAM | Critical | Medium | Critical | 9.0 |
| F2: Root Access Keys | IAM | Critical | Medium | Critical | 9.0 |
| F3: Admin Service Account | IAM | Critical | High | Critical | 9.5 |
| F4: No MFA (dev-mwilliams) | IAM | High | Medium | High | 7.5 |
| F5: Stale Contractor Account | IAM | High | Medium | High | 7.0 |
| F6: Public S3 (website-assets) | S3 | High | High | Medium | 7.0 |
| F7: Public Write S3 (dev-scratch) | S3 | High | High | High | 8.5 |
| F8: SSH Open to Internet | EC2 | High | High | Medium | 7.5 |
| F9: MySQL Open to Internet | EC2 | High | High | High | 8.0 |
| F10: Unencrypted EBS | EC2 | Medium | Low | Medium | 5.0 |
| F11: CloudTrail Not Multi-Region | CloudTrail | Medium | Medium | Medium | 5.5 |
| F12: Public RDS Instance | RDS | Critical | High | Critical | 9.0 |
| F13: Unencrypted RDS | RDS | Medium | Low | Medium | 5.0 |
| F14: RDP Open to Internet | EC2 | Medium | Medium | Medium | 6.0 |
| F15: Weak Password Policy | IAM | Low | Low | Low | 3.0 |

---

## Remediation Priority Roadmap

### Immediate (Within 24 Hours)
1. **F7:** Delete the public bucket policy on `acme-dev-scratch` and enable Block Public Access
2. **F12:** Set `PubliclyAccessible=False` on `acme-dev-postgres`
3. **F9:** Revoke 0.0.0.0/0 ingress on port 3306 in `database-sg`
4. **F3:** Detach `AdministratorAccess` from `svc-deploy-pipeline` and rotate its access key
5. **F5:** Disable the access key for `former-contractor` and delete the user

### Within 1 Week
6. **F1:** Enable hardware MFA on the root account
7. **F2:** Delete root access keys
8. **F8:** Restrict SSH security group to corporate VPN CIDR; evaluate SSM Session Manager
9. **F14:** Restrict RDP security group to corporate VPN CIDR
10. **F4:** Enforce MFA for `dev-mwilliams` and all console users

### Within 30 Days
11. **F11:** Enable multi-region CloudTrail and add KMS encryption
12. **F6:** Migrate website assets to CloudFront + OAI; add encryption and logging
13. **F10:** Enable EBS encryption by default; migrate existing unencrypted volumes
14. **F13:** Encrypt RDS instances via snapshot-restore workflow
15. **F15:** Update IAM password policy to meet CIS benchmarks

### Ongoing
- Implement AWS Config rules for continuous compliance monitoring
- Enable AWS Security Hub with CIS AWS Foundations Benchmark standard
- Establish a quarterly access review process for IAM users and policies
- Implement automated key rotation using AWS Secrets Manager
- Deploy GuardDuty for threat detection across all accounts and regions

---

## Appendix: CIS AWS Foundations Benchmark Reference

| CIS Control | Finding | Status |
|-------------|---------|--------|
| CIS 1.4 - No root access keys | F2 | FAIL |
| CIS 1.5 - Root MFA enabled | F1 | FAIL |
| CIS 1.8 - Password minimum length >= 14 | F15 | FAIL |
| CIS 1.10 - MFA for console users | F4 | FAIL |
| CIS 1.12 - Disable unused credentials | F5 | FAIL |
| CIS 1.14 - Rotate access keys <= 90 days | F3, F5 | FAIL |
| CIS 1.16 - No full admin policies | F3 | FAIL |
| CIS 2.1.1 - S3 encryption | F6, F7 | FAIL |
| CIS 2.1.5 - S3 public access | F6, F7 | FAIL |
| CIS 2.2.1 - EBS encryption | F10 | FAIL |
| CIS 2.3.1 - RDS encryption | F13 | FAIL |
| CIS 3.1 - CloudTrail multi-region | F11 | FAIL |
| CIS 3.7 - CloudTrail CMK encryption | F11 | FAIL |
| CIS 5.2 - No SSH from 0.0.0.0/0 | F8 | FAIL |
| CIS 5.3 - No RDP from 0.0.0.0/0 | F14 | FAIL |

---

*Report generated by AWS Security Auditor v1.0. This report contains confidential security assessment information and should be handled according to Acme Corporation's data classification policies.*
