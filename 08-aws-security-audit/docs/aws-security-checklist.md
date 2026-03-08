# AWS Security Checklist

A comprehensive security checklist for AWS environments, organized by service. Each item includes what to check, why it matters, how to verify using the AWS CLI, and the relevant CIS AWS Foundations Benchmark reference where applicable.

---

## IAM (Identity and Access Management)

### 1. Root Account MFA Enabled
- **What to check:** The root account must have a hardware or virtual MFA device configured.
- **Why it matters:** The root account has unrestricted access that cannot be limited by IAM policies. Without MFA, a compromised password gives complete account control.
- **How to verify:**
  ```bash
  aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
  # Expected: 1
  ```
- **CIS Ref:** CIS 1.5

### 2. No Root Account Access Keys
- **What to check:** The root account should not have any active access keys.
- **Why it matters:** Root access keys provide the same unrestricted access as the root console login but can be used programmatically. They are high-value targets that have been the cause of several public AWS breaches.
- **How to verify:**
  ```bash
  aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
  # Expected: 0
  ```
- **CIS Ref:** CIS 1.4

### 3. MFA Enabled for All Console Users
- **What to check:** Every IAM user with a console password must have an MFA device configured.
- **Why it matters:** MFA adds a second factor that protects against credential theft, phishing, and password reuse attacks.
- **How to verify:**
  ```bash
  # List users without MFA who have console access:
  aws iam generate-credential-report
  aws iam get-credential-report --query 'Content' --output text | base64 -d | \
    awk -F, '$4=="true" && $8=="false" {print $1}'
  ```
- **CIS Ref:** CIS 1.10

### 4. Access Keys Rotated Within 90 Days
- **What to check:** All active access keys should have been created or rotated within the last 90 days.
- **Why it matters:** Long-lived credentials increase the window of exposure if compromised. Regular rotation limits the useful lifetime of stolen keys.
- **How to verify:**
  ```bash
  # List access keys older than 90 days:
  for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
    aws iam list-access-keys --user-name "$user" \
      --query "AccessKeyMetadata[?Status=='Active'].[UserName,AccessKeyId,CreateDate]" \
      --output text
  done
  ```
- **CIS Ref:** CIS 1.14

### 5. No Unused Credentials (45+ Days)
- **What to check:** IAM users who have not logged in or used their access keys in 45 or more days should be disabled.
- **Why it matters:** Stale accounts from former employees or contractors are common attack vectors. They retain permissions but are not monitored.
- **How to verify:**
  ```bash
  aws iam generate-credential-report
  aws iam get-credential-report --query 'Content' --output text | base64 -d | \
    awk -F, 'NR>1 {print $1, $5, $11}'
  # Check password_last_used and access_key_last_used_date columns
  ```
- **CIS Ref:** CIS 1.12

### 6. No Wildcard Admin Policies on Users
- **What to check:** No IAM user should have a policy (attached or inline) that grants `Action: "*"` on `Resource: "*"`.
- **Why it matters:** Wildcard admin access violates least privilege and means a single compromised user grants full account control.
- **How to verify:**
  ```bash
  # Check for users with AdministratorAccess:
  for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
    aws iam list-attached-user-policies --user-name "$user" \
      --query "AttachedPolicies[?PolicyName=='AdministratorAccess'].PolicyName" --output text
  done
  ```
- **CIS Ref:** CIS 1.16

### 7. Policies Attached via Groups, Not Users
- **What to check:** IAM policies should be attached to groups or roles, not directly to individual users.
- **Why it matters:** Group-based access is easier to audit, more consistent, and simplifies onboarding/offboarding.
- **How to verify:**
  ```bash
  for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
    count=$(aws iam list-attached-user-policies --user-name "$user" \
      --query 'length(AttachedPolicies)' --output text)
    if [ "$count" -gt "0" ]; then echo "$user has $count directly attached policies"; fi
  done
  ```
- **CIS Ref:** CIS 1.15

### 8. Only One Active Access Key Per User
- **What to check:** Each IAM user should have at most one active access key.
- **Why it matters:** Multiple active keys increase the attack surface and make it harder to track which key is used where.
- **How to verify:**
  ```bash
  for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
    count=$(aws iam list-access-keys --user-name "$user" \
      --query "length(AccessKeyMetadata[?Status=='Active'])" --output text)
    if [ "$count" -gt "1" ]; then echo "$user has $count active access keys"; fi
  done
  ```
- **CIS Ref:** CIS 1.13

### 9. Strong Password Policy
- **What to check:** The account password policy should require: minimum 14 characters, uppercase, lowercase, numbers, symbols, max age <= 90 days, reuse prevention >= 24.
- **Why it matters:** Weak password policies allow easily guessable passwords that are vulnerable to brute-force and dictionary attacks.
- **How to verify:**
  ```bash
  aws iam get-account-password-policy
  ```
- **CIS Ref:** CIS 1.8-1.11

### 10. IAM Access Analyzer Enabled
- **What to check:** IAM Access Analyzer should be enabled in every region to identify resources shared externally.
- **Why it matters:** Access Analyzer continuously monitors resource policies and identifies unintended external access to S3 buckets, IAM roles, KMS keys, Lambda functions, and SQS queues.
- **How to verify:**
  ```bash
  aws accessanalyzer list-analyzers --query 'analyzers[*].[name,status]' --output table
  ```
- **CIS Ref:** CIS 1.20

### 11. Service Accounts Use Roles Instead of Users
- **What to check:** Workloads running on EC2, Lambda, ECS, or in CI/CD pipelines should use IAM roles (instance profiles, execution roles, OIDC federation) instead of IAM user access keys.
- **Why it matters:** IAM roles provide temporary credentials that are automatically rotated, eliminating the risk of long-lived key exposure.
- **How to verify:**
  ```bash
  # List IAM users with no console password (likely service accounts):
  aws iam generate-credential-report
  aws iam get-credential-report --query 'Content' --output text | base64 -d | \
    awk -F, '$4=="false" && $9=="true" {print $1, "has access keys but no console password"}'
  ```

### 12. Permissions Boundaries on Delegated Admin Users
- **What to check:** IAM users or roles with the ability to create other IAM entities should have a permissions boundary set.
- **Why it matters:** Without boundaries, a user who can create IAM roles can escalate their own privileges by creating a role with broader permissions.
- **How to verify:**
  ```bash
  aws iam list-users --query 'Users[?PermissionsBoundary==`null`].[UserName]' --output text
  ```

---

## S3 (Simple Storage Service)

### 1. S3 Block Public Access Enabled (Account Level)
- **What to check:** All four S3 Block Public Access settings should be enabled at the account level.
- **Why it matters:** Account-level Block Public Access overrides individual bucket settings, providing a safety net against accidental public exposure.
- **How to verify:**
  ```bash
  aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)
  ```
- **CIS Ref:** CIS 2.1.5

### 2. S3 Block Public Access Enabled (Bucket Level)
- **What to check:** Each bucket should have all four Block Public Access settings enabled unless public access is explicitly required and documented.
- **Why it matters:** Bucket-level settings provide defense in depth against public ACLs and bucket policies.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo "=== $bucket ==="
    aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "NO BLOCK PUBLIC ACCESS CONFIG"
  done
  ```
- **CIS Ref:** CIS 2.1.5

### 3. Default Encryption Enabled on All Buckets
- **What to check:** Every bucket should have server-side encryption (SSE-S3 or SSE-KMS) configured as the default.
- **Why it matters:** Without default encryption, objects uploaded without an encryption header are stored in plaintext.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo -n "$bucket: "
    aws s3api get-bucket-encryption --bucket "$bucket" \
      --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
      --output text 2>/dev/null || echo "NO ENCRYPTION"
  done
  ```
- **CIS Ref:** CIS 2.1.1

### 4. Versioning Enabled on Critical Buckets
- **What to check:** Buckets containing important data should have versioning enabled.
- **Why it matters:** Versioning protects against accidental deletion and overwrites, and is required for S3 Object Lock and cross-region replication.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo -n "$bucket: "
    aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text
  done
  ```

### 5. Server Access Logging Enabled
- **What to check:** S3 server access logging should be enabled, especially on buckets containing sensitive data.
- **Why it matters:** Access logs record every request made to a bucket, providing an audit trail for security investigations and compliance.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo -n "$bucket: "
    aws s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled.TargetBucket' --output text
  done
  ```
- **CIS Ref:** CIS 2.1.3 (related)

### 6. No Buckets with Public ACLs
- **What to check:** No bucket should grant access to the `AllUsers` or `AuthenticatedUsers` groups via ACLs.
- **Why it matters:** Public ACLs make bucket contents accessible to anyone on the internet.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    grants=$(aws s3api get-bucket-acl --bucket "$bucket" \
      --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers']" --output text)
    if [ -n "$grants" ]; then echo "PUBLIC ACL: $bucket"; fi
  done
  ```

### 7. Bucket Policies Do Not Allow Public Write
- **What to check:** No bucket policy should allow `s3:PutObject`, `s3:DeleteObject`, or `s3:*` to `Principal: "*"`.
- **Why it matters:** A publicly writable bucket can be used to host malware, store illegal content, or exfiltrate data.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3api get-bucket-policy --bucket "$bucket" --output text 2>/dev/null | \
      python3 -c "import sys,json; p=json.load(sys.stdin); [print(f'PUBLIC POLICY: $bucket -> {s[\"Action\"]}') for s in p.get('Statement',[]) if s.get('Principal')=='*' or (isinstance(s.get('Principal'),dict) and s['Principal'].get('AWS')=='*')]" 2>/dev/null
  done
  ```

### 8. MFA Delete Enabled on Critical Buckets
- **What to check:** Buckets with compliance or critical data should have MFA Delete enabled on versioning.
- **Why it matters:** MFA Delete requires multi-factor authentication to permanently delete object versions or change versioning state, protecting against accidental or malicious deletion.
- **How to verify:**
  ```bash
  aws s3api get-bucket-versioning --bucket <bucket-name> --query 'MFADelete'
  ```

### 9. CORS Configuration Reviewed
- **What to check:** If CORS is configured, `AllowedOrigins` should not include `*` (wildcard).
- **Why it matters:** Wildcard CORS allows any website to make cross-origin requests to the bucket, which could be exploited for data theft.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3api get-bucket-cors --bucket "$bucket" 2>/dev/null && echo "^ CORS on $bucket"
  done
  ```

### 10. Lifecycle Rules for Data Retention
- **What to check:** Buckets should have lifecycle rules to transition old objects to cheaper storage tiers or expire them.
- **Why it matters:** Without lifecycle rules, data accumulates indefinitely, increasing storage costs and the blast radius of a data breach.
- **How to verify:**
  ```bash
  for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo -n "$bucket: "
    aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" \
      --query 'Rules[*].ID' --output text 2>/dev/null || echo "NO LIFECYCLE RULES"
  done
  ```

---

## EC2 / VPC Security

### 1. No Security Groups with SSH Open to 0.0.0.0/0
- **What to check:** No security group should allow inbound TCP port 22 from 0.0.0.0/0 or ::/0.
- **Why it matters:** Publicly exposed SSH is a top target for automated brute-force attacks and exploitation of SSH daemon vulnerabilities.
- **How to verify:**
  ```bash
  aws ec2 describe-security-groups \
    --filters Name=ip-permission.from-port,Values=22 \
              Name=ip-permission.to-port,Values=22 \
              Name=ip-permission.cidr,Values=0.0.0.0/0 \
    --query 'SecurityGroups[*].[GroupId,GroupName]' --output table
  ```
- **CIS Ref:** CIS 5.2

### 2. No Security Groups with RDP Open to 0.0.0.0/0
- **What to check:** No security group should allow inbound TCP port 3389 from 0.0.0.0/0.
- **Why it matters:** RDP has been exploited in multiple ransomware campaigns (e.g., BlueKeep). Open RDP is one of the most common initial access vectors.
- **How to verify:**
  ```bash
  aws ec2 describe-security-groups \
    --filters Name=ip-permission.from-port,Values=3389 \
              Name=ip-permission.to-port,Values=3389 \
              Name=ip-permission.cidr,Values=0.0.0.0/0 \
    --query 'SecurityGroups[*].[GroupId,GroupName]' --output table
  ```
- **CIS Ref:** CIS 5.3

### 3. No Security Groups with Database Ports Open to 0.0.0.0/0
- **What to check:** Ports 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB), 6379 (Redis) should not be accessible from 0.0.0.0/0.
- **Why it matters:** Publicly exposed database ports are routinely scanned and attacked. A weak or default password combined with public exposure leads to immediate compromise.
- **How to verify:**
  ```bash
  for port in 3306 5432 1433 27017 6379; do
    result=$(aws ec2 describe-security-groups \
      --filters Name=ip-permission.from-port,Values=$port \
                Name=ip-permission.cidr,Values=0.0.0.0/0 \
      --query 'SecurityGroups[*].GroupId' --output text)
    if [ -n "$result" ]; then echo "Port $port open on: $result"; fi
  done
  ```

### 4. EBS Encryption Enabled by Default
- **What to check:** EBS encryption by default should be enabled in all regions.
- **Why it matters:** When enabled, all new EBS volumes and snapshots are automatically encrypted, preventing unintentional data exposure.
- **How to verify:**
  ```bash
  aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault'
  # Expected: true
  ```
- **CIS Ref:** CIS 2.2.1

### 5. No Unencrypted EBS Volumes
- **What to check:** All existing EBS volumes should be encrypted.
- **Why it matters:** Unencrypted volumes can be snapshotted and shared, exposing data. If the underlying hardware is decommissioned, data could be recovered.
- **How to verify:**
  ```bash
  aws ec2 describe-volumes \
    --filters Name=encrypted,Values=false \
    --query 'Volumes[*].[VolumeId,Size,State]' --output table
  ```

### 6. IMDSv2 Required on All Instances
- **What to check:** All EC2 instances should require Instance Metadata Service Version 2 (IMDSv2).
- **Why it matters:** IMDSv1 is vulnerable to SSRF attacks that can steal IAM role credentials from the metadata endpoint (as in the Capital One breach). IMDSv2 requires a session token.
- **How to verify:**
  ```bash
  aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' \
    --output table
  # HttpTokens should be "required" (not "optional")
  ```

### 7. VPC Flow Logs Enabled
- **What to check:** VPC Flow Logs should be enabled for all VPCs, logging to CloudWatch Logs or S3.
- **Why it matters:** Flow logs capture network traffic metadata (source, destination, port, action) and are essential for incident investigation and network monitoring.
- **How to verify:**
  ```bash
  for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text); do
    logs=$(aws ec2 describe-flow-logs --filter Name=resource-id,Values=$vpc \
      --query 'FlowLogs[*].FlowLogId' --output text)
    if [ -z "$logs" ]; then echo "NO FLOW LOGS: $vpc"; fi
  done
  ```
- **CIS Ref:** CIS 3.9

### 8. Default Security Group Restricts All Traffic
- **What to check:** The default security group in each VPC should have all inbound and outbound rules removed.
- **Why it matters:** Resources accidentally placed in the default security group could have unintended network access if the default rules are permissive.
- **How to verify:**
  ```bash
  aws ec2 describe-security-groups \
    --filters Name=group-name,Values=default \
    --query 'SecurityGroups[*].[VpcId,GroupId,IpPermissions,IpPermissionsEgress]' --output json
  ```
- **CIS Ref:** CIS 5.4

### 9. No Public IPs on Instances in Private Subnets
- **What to check:** Instances in private subnets should not have public IP addresses assigned.
- **Why it matters:** A public IP on a private-subnet instance is a misconfiguration that could expose internal workloads if routing changes.
- **How to verify:**
  ```bash
  aws ec2 describe-instances \
    --query 'Reservations[*].Instances[?PublicIpAddress!=`null`].[InstanceId,PublicIpAddress,SubnetId]' \
    --output table
  ```

### 10. No Orphaned EBS Volumes or Elastic IPs
- **What to check:** There should be no unattached EBS volumes or unassociated Elastic IPs.
- **Why it matters:** Orphaned resources incur costs and may contain sensitive data. Unassociated EIPs also waste limited IP address allocations.
- **How to verify:**
  ```bash
  aws ec2 describe-volumes --filters Name=status,Values=available \
    --query 'Volumes[*].[VolumeId,Size]' --output table

  aws ec2 describe-addresses --query 'Addresses[?AssociationId==`null`].[PublicIp,AllocationId]' --output table
  ```

---

## CloudTrail / Logging

### 1. CloudTrail Enabled in All Regions
- **What to check:** At least one CloudTrail trail must be configured as multi-region.
- **Why it matters:** Without multi-region logging, API calls in unmonitored regions are invisible. Attackers routinely operate in unused regions to avoid detection.
- **How to verify:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[*].[TrailARN,IsMultiRegionTrail]' --output table
  ```
- **CIS Ref:** CIS 3.1

### 2. CloudTrail Log File Validation Enabled
- **What to check:** Log file integrity validation should be enabled on all trails.
- **Why it matters:** Validation creates a hash chain of log files. If an attacker modifies or deletes log files, the tampering is detectable.
- **How to verify:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[*].[Name,LogFileValidationEnabled]' --output table
  ```
- **CIS Ref:** CIS 3.2

### 3. CloudTrail Logs Encrypted with CMK
- **What to check:** CloudTrail logs should be encrypted with a customer-managed KMS key (not just S3 default encryption).
- **Why it matters:** A CMK provides an additional layer of access control through the KMS key policy, limiting who can decrypt the logs.
- **How to verify:**
  ```bash
  aws cloudtrail describe-trails --query 'trailList[*].[Name,KmsKeyId]' --output table
  ```
- **CIS Ref:** CIS 3.7

### 4. CloudTrail Log Bucket Not Public
- **What to check:** The S3 bucket receiving CloudTrail logs must not be publicly accessible.
- **Why it matters:** CloudTrail logs contain detailed API call records including who did what and when. Public access would expose the entire audit history.
- **How to verify:**
  ```bash
  BUCKET=$(aws cloudtrail describe-trails --query 'trailList[0].S3BucketName' --output text)
  aws s3api get-public-access-block --bucket "$BUCKET"
  aws s3api get-bucket-policy-status --bucket "$BUCKET"
  ```

### 5. CloudWatch Log Metric Filters for Key Events
- **What to check:** CloudWatch metric filters and alarms should be configured for: unauthorized API calls, console sign-in without MFA, root account usage, IAM policy changes, CloudTrail configuration changes, S3 bucket policy changes, security group changes, and VPC changes.
- **Why it matters:** Real-time alerting on security-relevant events enables rapid incident detection and response.
- **How to verify:**
  ```bash
  aws logs describe-metric-filters --log-group-name <cloudtrail-log-group> \
    --query 'metricFilters[*].[filterName,filterPattern]' --output table
  ```
- **CIS Ref:** CIS 4.1-4.14

### 6. GuardDuty Enabled
- **What to check:** Amazon GuardDuty should be enabled in all regions and all accounts in the organization.
- **Why it matters:** GuardDuty uses machine learning, anomaly detection, and threat intelligence to identify malicious activity including compromised instances, unusual API calls, and cryptocurrency mining.
- **How to verify:**
  ```bash
  aws guardduty list-detectors --query 'DetectorIds'
  ```
- **CIS Ref:** Not directly in CIS, but strongly recommended

### 7. Config Recorder Active
- **What to check:** AWS Config should have an active configuration recorder tracking all supported resource types.
- **Why it matters:** Config maintains a continuous record of resource configurations and changes, enabling compliance auditing and drift detection.
- **How to verify:**
  ```bash
  aws configservice describe-configuration-recorders
  aws configservice describe-configuration-recorder-status
  ```

### 8. S3 Data Events Logged
- **What to check:** CloudTrail should be configured to log S3 data events (object-level operations) for critical buckets.
- **Why it matters:** Management events alone do not capture who read or modified specific objects. Data events provide the granular audit trail needed for sensitive data.
- **How to verify:**
  ```bash
  aws cloudtrail get-event-selectors --trail-name <trail-name> \
    --query 'EventSelectors[*].DataResources' --output json
  ```

---

## RDS (Relational Database Service)

### 1. No Publicly Accessible RDS Instances
- **What to check:** All RDS instances should have `PubliclyAccessible` set to `False`.
- **Why it matters:** A publicly accessible database can be reached from the internet if the associated security group permits it. Database breaches are among the most damaging security incidents.
- **How to verify:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]' \
    --output table
  ```

### 2. RDS Storage Encryption Enabled
- **What to check:** All RDS instances should have `StorageEncrypted` set to `True`.
- **Why it matters:** Encryption protects data at rest, including automated backups, read replicas, and snapshots. Without encryption, a shared or leaked snapshot exposes data in cleartext.
- **How to verify:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,Engine]' \
    --output table
  ```
- **CIS Ref:** CIS 2.3.1

### 3. Automated Backups Enabled (Retention >= 7 Days)
- **What to check:** All RDS instances should have `BackupRetentionPeriod` >= 7.
- **Why it matters:** Automated backups enable point-in-time recovery, which is essential for disaster recovery and for restoring data after a ransomware attack or accidental deletion.
- **How to verify:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?BackupRetentionPeriod<`7`].[DBInstanceIdentifier,BackupRetentionPeriod]' \
    --output table
  ```

### 4. Deletion Protection Enabled on Production Databases
- **What to check:** Production RDS instances should have `DeletionProtection` enabled.
- **Why it matters:** Deletion protection prevents accidental or malicious database deletion through the API or console.
- **How to verify:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?DeletionProtection==`false`].[DBInstanceIdentifier]' \
    --output table
  ```

### 5. Auto Minor Version Upgrade Enabled
- **What to check:** All RDS instances should have `AutoMinorVersionUpgrade` enabled.
- **Why it matters:** Minor version upgrades include security patches for the database engine. Without auto-upgrade, known vulnerabilities persist.
- **How to verify:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?AutoMinorVersionUpgrade==`false`].[DBInstanceIdentifier,Engine,EngineVersion]' \
    --output table
  ```

### 6. Multi-AZ Enabled for Production Databases
- **What to check:** Production RDS instances should be configured for Multi-AZ deployment.
- **Why it matters:** Multi-AZ provides automatic failover to a standby instance in a different Availability Zone, minimizing downtime during infrastructure failures.
- **How to verify:**
  ```bash
  aws rds describe-db-instances \
    --query 'DBInstances[?MultiAZ==`false`].[DBInstanceIdentifier,Engine]' \
    --output table
  ```

---

## General Account Security

### 1. AWS Organizations SCPs in Place
- **What to check:** If using AWS Organizations, Service Control Policies (SCPs) should restrict unused regions, prevent disabling of CloudTrail and GuardDuty, and deny root user actions.
- **Why it matters:** SCPs provide guardrails that apply to all accounts in the organization, preventing even administrator users from performing certain actions.
- **How to verify:**
  ```bash
  aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
    --query 'Policies[*].[Name,Id]' --output table
  ```

### 2. AWS Security Hub Enabled
- **What to check:** Security Hub should be enabled with the CIS AWS Foundations Benchmark standard active.
- **Why it matters:** Security Hub aggregates findings from multiple AWS security services (GuardDuty, Inspector, Macie, IAM Access Analyzer, Config) into a single dashboard with automated compliance checks.
- **How to verify:**
  ```bash
  aws securityhub describe-hub
  aws securityhub get-enabled-standards --query 'StandardsSubscriptions[*].StandardsArn' --output table
  ```

### 3. Billing Alerts and Budget Configured
- **What to check:** AWS Budgets should be configured with alerts for unexpected cost increases.
- **Why it matters:** Unexpected cost spikes can indicate cryptocurrency mining from compromised instances or mass data exfiltration. Cost alerts serve as an early warning system.
- **How to verify:**
  ```bash
  aws budgets describe-budgets --account-id $(aws sts get-caller-identity --query Account --output text)
  ```

### 4. Support Plan Reviewed
- **What to check:** The AWS support plan should be at least Business tier for production workloads.
- **Why it matters:** Business and Enterprise support plans provide access to AWS Trusted Advisor security checks, the AWS Support API, and a faster response time for security incidents.

### 5. Alternate Account Contacts Configured
- **What to check:** Security, billing, and operations alternate contacts should be configured on the account.
- **Why it matters:** AWS uses these contacts to reach the appropriate team for security notifications, billing issues, and operational events. Without them, critical alerts may be missed.
- **How to verify:**
  ```bash
  aws account get-alternate-contact --alternate-contact-type SECURITY
  aws account get-alternate-contact --alternate-contact-type BILLING
  aws account get-alternate-contact --alternate-contact-type OPERATIONS
  ```

---

*Checklist aligned with CIS AWS Foundations Benchmark v2.0 and AWS Well-Architected Framework Security Pillar.*
