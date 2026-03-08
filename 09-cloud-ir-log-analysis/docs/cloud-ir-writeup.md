# Cloud Incident Response Write-Up: Compromised IAM Credentials Leading to Data Exfiltration

**Incident ID:** IR-2025-1118
**Date of Incident:** November 18, 2025
**Date of Report:** November 19, 2025
**Classification:** Confidential
**Severity:** Critical
**Status:** Remediated

---

## Executive Summary

On November 18, 2025, at approximately 02:14 UTC, an external threat actor
authenticated to the AWS Console using the compromised credentials of IAM user
`dev-carlos` without multi-factor authentication. The source IP address
(203.0.113.50) was not associated with any known corporate network.

Over the next two hours, the attacker conducted systematic reconnaissance of
the AWS environment, escalated privileges to AdministratorAccess, established
persistence through a backdoor IAM user with programmatic and console access,
exfiltrated sensitive files from the `confidential-hr-data` S3 bucket, and
disabled security monitoring by stopping CloudTrail logging and deleting the
GuardDuty detector.

The attacker accessed employee salary records, social security number
directories, performance reviews, financial reports, and legal documents. This
incident constitutes a data breach involving personally identifiable
information (PII).

---

## Timeline Reconstruction

All timestamps are in UTC. The events were reconstructed from CloudTrail logs
stored in the `cloudtrail-attack.json` file.

### Phase 1: Initial Access (02:14 - 02:15)

| Time | Event | Detail |
|------|-------|--------|
| 02:14:33 | **ConsoleLogin** | User `dev-carlos` logs in from 203.0.113.50 **without MFA**. User agent indicates a Linux-based browser. |

**Analysis:** The `dev-carlos` account had been provisioned with console access
and an IAM password but MFA was not enforced. The legitimate user typically
accesses AWS from the corporate IP range (198.51.100.0/24). The login from
203.0.113.50 at 02:14 UTC (outside business hours) was the first indicator of
compromise.

**MITRE ATT&CK:** T1078.004 -- Valid Accounts: Cloud Accounts

---

### Phase 2: Reconnaissance (02:16 - 02:20)

| Time | Event | Detail |
|------|-------|--------|
| 02:16:05 | **GetCallerIdentity** | Attacker verifies which identity they are using. Classic first move. |
| 02:17:22 | **ListUsers** | Enumerates all IAM users (maxItems=1000). |
| 02:17:55 | **ListRoles** | Enumerates all IAM roles (maxItems=1000). |
| 02:18:40 | **ListAttachedUserPolicies** | Checks what permissions dev-carlos currently has. |
| 02:19:15 | **ListBuckets** | Enumerates all S3 buckets in the account. |
| 02:20:02 | **DescribeInstances** | Enumerates all EC2 instances. |
| 02:20:45 | **DescribeSecurityGroups** | Enumerates all security groups. |

**Analysis:** Within six minutes of login, the attacker executed seven
discovery API calls using the AWS CLI (user agent: `aws-cli/2.13.0`). This is
a textbook cloud reconnaissance pattern. The switch from browser (ConsoleLogin)
to CLI indicates the attacker exported credentials or configured a CLI profile.
The rapid-fire enumeration pattern across IAM, S3, and EC2 resources is
consistent with automated tooling such as Pacu, ScoutSuite, or a custom
script.

**MITRE ATT&CK:**
- T1087.004 -- Account Discovery: Cloud Account
- T1580 -- Cloud Infrastructure Discovery

---

### Phase 3: Privilege Escalation (02:25)

| Time | Event | Detail |
|------|-------|--------|
| 02:25:10 | **AttachUserPolicy** | Attacker attaches `arn:aws:iam::aws:policy/AdministratorAccess` to `dev-carlos`. |

**Analysis:** The `dev-carlos` account originally had limited developer
permissions. The attacker's `ListAttachedUserPolicies` call at 02:18 revealed
the user had `iam:AttachUserPolicy` permission (a well-known IAM privilege
escalation vector). The attacker leveraged this to grant themselves full
AdministratorAccess. From this point forward, the attacker has unrestricted
access to the entire AWS account.

**MITRE ATT&CK:** T1098.003 -- Account Manipulation: Additional Cloud Roles

---

### Phase 4: Persistence (02:28 - 02:30)

| Time | Event | Detail |
|------|-------|--------|
| 02:28:33 | **CreateUser** | Attacker creates IAM user `svc-backup-ops` (named to blend in as a service account). |
| 02:29:05 | **AttachUserPolicy** | AdministratorAccess attached to `svc-backup-ops`. |
| 02:29:44 | **CreateAccessKey** | Access key `AKIAEXAMPLEBACKUPKEY` created for `svc-backup-ops`. |
| 02:30:12 | **CreateLoginProfile** | Console password created for `svc-backup-ops` with no forced password reset. |

**Analysis:** The attacker created a fully functional backdoor IAM user with
both programmatic (access key) and console (password) access. The naming
convention `svc-backup-ops` was deliberately chosen to appear legitimate. The
AdministratorAccess policy ensures continued full access even if the
`dev-carlos` compromise is detected and remediated. The attacker now has two
independent paths into the environment.

**MITRE ATT&CK:**
- T1136.003 -- Create Account: Cloud Account
- T1098.001 -- Account Manipulation: Additional Cloud Credentials

---

### Phase 5: Data Access and Exfiltration (02:35 - 02:39)

| Time | Event | Detail |
|------|-------|--------|
| 02:35:00 | **GetBucketPolicy** | Attacker reads the bucket policy for `confidential-hr-data`. |
| 02:36:10 | **ListObjects** | Attacker lists all objects in the bucket. |
| 02:37:22 | **GetObject** | `employee-records/salaries-2025.xlsx` |
| 02:37:45 | **GetObject** | `employee-records/ssn-directory.csv` |
| 02:38:02 | **GetObject** | `employee-records/performance-reviews-2025.pdf` |
| 02:38:15 | **GetObject** | `employee-records/benefits-enrollment.xlsx` |
| 02:38:30 | **GetObject** | `financial/quarterly-report-q3-2025.pdf` |
| 02:38:48 | **GetObject** | `financial/board-compensation-2025.xlsx` |
| 02:39:05 | **GetObject** | `legal/pending-litigation.docx` |

**Analysis:** The attacker systematically downloaded seven sensitive files
from the `confidential-hr-data` bucket over a two-minute window. The files
contain PII (social security numbers, salary data), financial records, and
privileged legal documents. The rapid, sequential downloads via CLI are
consistent with a scripted `aws s3 cp` or `aws s3 sync` operation. The S3
data event logging captured each individual object access.

**Data Classification of Exfiltrated Files:**
- `ssn-directory.csv` -- PII / Regulated (triggers breach notification requirements)
- `salaries-2025.xlsx` -- Confidential HR data
- `performance-reviews-2025.pdf` -- Confidential HR data
- `benefits-enrollment.xlsx` -- PII (health insurance information)
- `quarterly-report-q3-2025.pdf` -- Material non-public financial information
- `board-compensation-2025.xlsx` -- Confidential financial data
- `pending-litigation.docx` -- Attorney-client privileged

**MITRE ATT&CK:** T1530 -- Data from Cloud Storage Object

---

### Phase 6: Defense Evasion (02:45 - 02:51)

| Time | Event | Detail |
|------|-------|--------|
| 02:45:00 | **PutBucketPolicy** | Attacker modifies bucket policy to allow `s3:GetObject` by `Principal: "*"` (public access). |
| 02:47:30 | **DeleteBucketEncryption** | Server-side encryption removed from `confidential-hr-data`. |
| 02:50:00 | **StopLogging** | CloudTrail trail `organization-trail` stopped. |
| 02:51:15 | **DeleteDetector** | GuardDuty detector deleted. |

**Analysis:** After exfiltrating data, the attacker took steps to cover their
tracks and maintain alternative access. Making the bucket public provides a
secondary exfiltration channel that does not require AWS credentials.
Removing encryption weakens data protection at rest. Stopping CloudTrail
eliminates the audit trail for subsequent actions. Deleting the GuardDuty
detector removes automated threat detection.

The StopLogging call at 02:50:00 means that any attacker activity after this
point would not be captured in CloudTrail. This was the last event we have
full visibility into.

**MITRE ATT&CK:**
- T1562.008 -- Impair Defenses: Disable Cloud Logs
- T1562.001 -- Impair Defenses: Disable or Modify Tools

---

### Phase 7: Lateral Movement (03:00 - 04:10)

| Time | Event | Detail |
|------|-------|--------|
| 03:00:00 | **AuthorizeSecurityGroupIngress** | Opened sg-0abcdef1234567890 port 22 to 0.0.0.0/0. |
| 03:05:00 | **AssumeRole** | Assumed `CrossAccountAdmin` role in account 987654321098 (different AWS account). |
| 04:10:00 | **PutUserPolicy** | Inline policy `EmergencyFullAccess` (`*:*`) added to `dev-carlos`. |

**Analysis:** The attacker opened SSH access from the internet, likely
targeting an EC2 instance for OS-level persistence. The cross-account
AssumeRole call into account 987654321098 indicates the attacker is aware
of (and has access to) the organization's multi-account structure. The
inline policy at 04:10 provides another persistence mechanism separate from
the managed AdministratorAccess policy.

Note: Some of these events occurred after CloudTrail was stopped at 02:50.
These events were captured because they were recorded in the event log before
delivery was fully interrupted, or because they appeared in the CloudTrail
event history (which has a separate 90-day buffer).

**MITRE ATT&CK:**
- T1098 -- Account Manipulation
- T1550.001 -- Use Alternate Authentication Material: Application Access Token

---

## Attack Flow Summary

```
Initial Access          Reconnaissance         Privilege Escalation
ConsoleLogin ---------> GetCallerIdentity ---> AttachUserPolicy
(no MFA, 203.0.113.50)  ListUsers              (AdministratorAccess)
                         ListRoles                     |
                         ListBuckets                   v
                         DescribeInstances      Persistence
                         DescribeSecurityGroups CreateUser (svc-backup-ops)
                                                CreateAccessKey
                                                CreateLoginProfile
                                                       |
                                                       v
Data Exfiltration <---- Data Access            Defense Evasion
7 sensitive files       GetBucketPolicy        StopLogging
from S3                 ListObjects            DeleteDetector
                        7x GetObject           PutBucketPolicy (public)
                               |               DeleteBucketEncryption
                               v                       |
                        Lateral Movement               v
                        AuthorizeSecurityGroupIngress   Coverage Gap
                        AssumeRole (cross-account)     (no further visibility)
                        PutUserPolicy (*:*)
```

---

## Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
|----------|-------|---------|
| Source IP | 203.0.113.50 | All attacker API calls originated from this IP |
| IAM User | svc-backup-ops | Backdoor account created by attacker |
| Access Key | AKIAEXAMPLEBACKUPKEY | Backdoor access key for svc-backup-ops |
| User Agent | aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0-1040-aws | Attacker CLI fingerprint |
| Security Group | sg-0abcdef1234567890 | Modified to allow SSH from 0.0.0.0/0 |
| Bucket Policy | confidential-hr-data | Changed to Principal: "*" (public) |
| Inline Policy | EmergencyFullAccess on dev-carlos | Attacker persistence via `*:*` policy |
| Cross-Account | 987654321098 | Attacker pivoted to this account via AssumeRole |

---

## Root Cause Analysis

The root cause of this incident was a combination of factors:

1. **No MFA enforcement on IAM user `dev-carlos`.** The IAM password policy
   did not require MFA for console access. This allowed the attacker to
   authenticate with only a username and password.

2. **Overly permissive IAM policy.** The `dev-carlos` user had
   `iam:AttachUserPolicy` permission, which is a known privilege escalation
   path. A developer role should not have the ability to modify its own IAM
   policies.

3. **Likely credential exposure.** The credentials for `dev-carlos` were
   likely compromised through phishing, credential stuffing, a leaked code
   repository, or a compromised developer workstation. The exact vector
   requires further investigation outside AWS.

4. **Insufficient monitoring.** No CloudWatch alarm was configured to alert
   on ConsoleLogin events without MFA, or on sensitive IAM changes like
   AttachUserPolicy with AdministratorAccess.

5. **Cross-account trust without conditions.** The trust policy on
   `CrossAccountAdmin` role in account 987654321098 did not require MFA or
   restrict by source IP, allowing the compromised credentials to pivot
   laterally.

---

## Remediation Actions

### Immediate (Completed)

- [x] Disabled all access keys for `dev-carlos`
- [x] Forced password reset for `dev-carlos`
- [x] Deleted IAM user `svc-backup-ops` and its access key
- [x] Removed `AdministratorAccess` policy from `dev-carlos`
- [x] Removed `EmergencyFullAccess` inline policy from `dev-carlos`
- [x] Reverted S3 bucket policy on `confidential-hr-data` to deny-all
- [x] Re-enabled server-side encryption on `confidential-hr-data`
- [x] Re-enabled CloudTrail logging on `organization-trail`
- [x] Re-created GuardDuty detector
- [x] Revoked security group ingress rule (0.0.0.0/0 on port 22)
- [x] Revoked active IAM sessions for `dev-carlos` via epoch-based deny policy
- [x] Investigated account 987654321098 for attacker activity

### Short-Term (In Progress)

- [ ] Enforce MFA on all IAM users via IAM policy condition
- [ ] Implement SCP to deny `iam:AttachUserPolicy` except for admin roles
- [ ] Deploy CloudWatch alarms for: ConsoleLogin without MFA, StopLogging,
      DeleteDetector, AttachUserPolicy with AdministratorAccess, CreateUser
- [ ] Rotate all access keys for the AWS account
- [ ] Enable S3 Block Public Access at the account level
- [ ] Review and restrict cross-account trust policies

### Long-Term (Planned)

- [ ] Migrate from IAM users to SSO (AWS IAM Identity Center) with enforced MFA
- [ ] Implement least-privilege IAM policies using IAM Access Analyzer
- [ ] Deploy AWS Config rules to detect policy violations (public S3 buckets,
      open security groups, users without MFA)
- [ ] Enable CloudTrail Insights for anomaly detection
- [ ] Establish a CloudTrail log archive with S3 Object Lock (WORM) to prevent
      log tampering
- [ ] Conduct tabletop exercises for cloud IR scenarios

---

## Lessons Learned

1. **MFA is non-negotiable.** Every human IAM identity must have MFA enforced
   via IAM policy conditions. This single control would have prevented the
   initial access.

2. **Principle of least privilege must include IAM permissions.** A developer
   should never have `iam:AttachUserPolicy` or `iam:PutUserPolicy` on their
   own user. IAM permission boundaries should constrain what even
   administrators can delegate.

3. **Detection must precede response.** The attacker operated for nearly two
   hours before security monitoring was disabled. Real-time alerts on
   high-fidelity signals (no-MFA login, policy attachment, StopLogging) would
   have shortened the dwell time to minutes.

4. **CloudTrail is both your best friend and a target.** If the attacker had
   stopped logging earlier, we would have lost visibility into the data
   exfiltration. Protect CloudTrail with SCPs that deny StopLogging and
   DeleteTrail for all principals except a break-glass role.

5. **Cross-account access requires the same rigor as direct access.** Trust
   policies should require MFA (`aws:MultiFactorAuthPresent`), restrict
   source IPs, and use external ID conditions where possible.

6. **Naming conventions are not security.** The attacker named the backdoor
   user `svc-backup-ops` to appear legitimate. Automated detection of new
   IAM users (CloudWatch Events + Lambda) is more reliable than human review.

---

## Appendix: Tools Used

- **cloudtrail_analyzer.py** -- Custom Python script for parsing CloudTrail
  JSON logs, detecting suspicious API activity, mapping to MITRE ATT&CK, and
  generating investigation reports.
- **cloud_ioc_detector.py** -- Custom Python script for detecting cloud-specific
  IOCs including impossible travel, off-hours activity, enumeration patterns,
  and exfiltration indicators.
- **AWS CLI** -- For evidence collection and remediation commands.
- **MITRE ATT&CK Cloud Matrix** -- Framework for categorizing attacker
  tactics, techniques, and procedures.

---

*This write-up was prepared as part of a cybersecurity portfolio project. All
IP addresses use documentation ranges (RFC 5737). AWS account IDs and resource
identifiers are synthetic. The investigation methodology, timeline analysis,
and remediation procedures reflect real-world cloud incident response
practices.*
