# Cloud Incident Response Playbook

## Table of Contents

1. [Cloud-Specific IR Considerations](#cloud-specific-ir-considerations)
2. [Detection Sources](#detection-sources)
3. [Investigation Procedures](#investigation-procedures)
   - [Compromised IAM Credentials](#1-compromised-iam-credentials)
   - [Unauthorized Resource Creation (Crypto Mining)](#2-unauthorized-resource-creation-crypto-mining)
   - [S3 Data Exposure](#3-s3-data-exposure)
   - [Privilege Escalation](#4-privilege-escalation)
4. [Containment Actions](#containment-actions)
5. [Evidence Preservation](#evidence-preservation)
6. [MITRE ATT&CK Cloud Matrix Mapping](#mitre-attck-cloud-matrix-mapping)

---

## Cloud-Specific IR Considerations

Cloud incident response differs from traditional on-premises IR in several
fundamental ways that every responder must internalize before handling a cloud
security event.

### Shared Responsibility Model

AWS operates under a shared responsibility model. AWS secures the
infrastructure *of* the cloud (hardware, global network, managed services),
while the customer is responsible for security *in* the cloud (IAM policies,
data encryption, security group rules, application code). During an incident
the responder must be clear about which layer was compromised and who controls
the remediation.

- **AWS responsibility** -- physical security, hypervisor, network fabric,
  managed service internals.
- **Customer responsibility** -- IAM configuration, S3 bucket policies,
  security group rules, EC2 OS-level security, encryption key management,
  application-layer controls.

### API-Driven Everything

Every action in AWS is an API call. This is both the attack surface and the
investigation surface. CloudTrail captures these API calls, which means the
investigation record is far more complete than a typical endpoint
investigation.  However, the volume of events can be enormous, so knowing
which API calls matter is critical.

Key implication: if an attacker disables logging (StopLogging, DeleteTrail),
there will be a gap in your investigation timeline.

### Ephemeral Resources

Cloud resources can be created and destroyed in seconds. An EC2 instance
launched for crypto mining at 01:00 and terminated at 04:00 will leave only
CloudTrail records and (if configured) VPC Flow Logs. The instance itself will
be gone. This makes early evidence preservation essential.

### Identity Is the New Perimeter

In cloud environments, network-based perimeter controls are secondary to
identity-based controls. A compromised IAM access key provides the attacker
with the same API access as the legitimate user, from any IP address in the
world. Investigate identity-based indicators first.

### Multi-Region and Multi-Account

Attackers frequently pivot to unused AWS regions (where monitoring may be
weaker) or attempt cross-account lateral movement via AssumeRole. Always
investigate across all regions and linked accounts.

---

## Detection Sources

### CloudTrail

The primary audit log for all AWS API activity.

- **Management events** -- control-plane calls (CreateUser, RunInstances,
  PutBucketPolicy). Enabled by default.
- **Data events** -- data-plane calls (S3 GetObject/PutObject, Lambda
  Invoke). Must be explicitly enabled.
- **Insights events** -- anomaly detection for unusual API call volumes.
- **Delivery** -- logs are delivered to an S3 bucket (and optionally
  CloudWatch Logs) with a typical delay of 5-15 minutes.

```bash
# List trails
aws cloudtrail describe-trails

# Look up recent events (last 90 days via console/API)
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time 2025-11-01T00:00:00Z \
    --end-time 2025-11-20T00:00:00Z
```

### Amazon GuardDuty

Managed threat detection service that continuously monitors CloudTrail,
VPC Flow Logs, and DNS logs for malicious activity.

```bash
# List active findings
aws guardduty list-findings --detector-id <detector-id>
aws guardduty get-findings --detector-id <detector-id> --finding-ids <id>
```

### CloudWatch Logs and Alarms

Centralized log collection. CloudTrail can stream to CloudWatch Logs for
real-time metric filters and alarms on specific API calls.

```bash
# Search CloudWatch Logs for a specific pattern
aws logs filter-log-events \
    --log-group-name CloudTrail/DefaultLogGroup \
    --filter-pattern '{ $.eventName = "StopLogging" }' \
    --start-time 1700000000000
```

### VPC Flow Logs

Network-level traffic metadata (source, destination, ports, action, bytes).
Useful for identifying lateral movement, data exfiltration volumes, and
connections to known-bad IPs.

```bash
# Check if flow logs are enabled
aws ec2 describe-flow-logs --filter "Name=resource-id,Values=vpc-abc123"
```

### S3 Server Access Logs

Detailed request-level logging for S3 buckets. Records every GET, PUT, DELETE
including requester IP, bucket, key, HTTP status, and bytes transferred.

```bash
# Check if access logging is enabled on a bucket
aws s3api get-bucket-logging --bucket <bucket-name>
```

---

## Investigation Procedures

### 1. Compromised IAM Credentials

**Indicators:**
- API calls from unusual IP addresses or user agents
- ConsoleLogin events without MFA
- Programmatic access from IPs outside corporate ranges
- Spike in API call volume for a user
- GuardDuty finding: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`

**Investigation Steps:**

```bash
# Step 1: Identify the affected credential
aws iam list-access-keys --user-name <user>

# Step 2: Determine when the credential was last used
aws iam get-access-key-last-used --access-key-id <AKIA...>

# Step 3: Pull CloudTrail events for this user
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=<user> \
    --start-time <incident-start> \
    --max-results 50

# Step 4: Check for any new credentials the attacker created
aws iam list-access-keys --user-name <user>
aws iam list-mfa-devices --user-name <user>

# Step 5: Check for persistence (new users/roles created by this user)
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
    --start-time <incident-start>

# Step 6: Check AssumeRole activity (lateral movement)
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
    --start-time <incident-start>
```

**Containment:**
1. Deactivate the compromised access key immediately.
2. If the user has console access, force a password reset.
3. Revoke all active sessions (see Containment Actions below).
4. Apply a deny-all IAM policy to the user while investigating.

---

### 2. Unauthorized Resource Creation (Crypto Mining)

**Indicators:**
- RunInstances calls for GPU instances (p3, p4, g4dn, g5) in unusual regions
- Multiple instances launched simultaneously (maxCount > 2)
- New key pairs created in unfamiliar regions
- Security groups opened to 0.0.0.0/0
- ModifyInstanceAttribute to enable termination protection
- Spike in EC2 costs
- GuardDuty finding: `CryptoCurrency:EC2/BitcoinTool.B`

**Investigation Steps:**

```bash
# Step 1: List all running instances across all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    echo "--- $region ---"
    aws ec2 describe-instances \
        --region "$region" \
        --filters "Name=instance-state-name,Values=running" \
        --query 'Reservations[].Instances[].[InstanceId,InstanceType,LaunchTime,KeyName]' \
        --output table
done

# Step 2: Check who launched suspicious instances
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
    --start-time <incident-start>

# Step 3: Check for new key pairs
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreateKeyPair \
    --start-time <incident-start>

# Step 4: Check security group modifications
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
    --start-time <incident-start>

# Step 5: Check for termination protection (attacker anti-containment)
aws ec2 describe-instance-attribute \
    --instance-id <instance-id> \
    --attribute disableApiTermination \
    --region <region>
```

**Containment:**
1. Disable termination protection, then terminate rogue instances.
2. Delete attacker-created key pairs.
3. Revoke security group changes.
4. Disable or rotate the compromised credential.
5. Apply an SCP to deny RunInstances for GPU types if not used legitimately.

---

### 3. S3 Data Exposure

**Indicators:**
- PutBucketPolicy with Principal: "*" (public access)
- PutBucketAcl granting public-read
- DeleteBucketEncryption
- Mass GetObject calls on sensitive buckets
- S3 access logs showing external IP addresses
- GuardDuty finding: `Policy:S3/BucketPublicAccessGranted`

**Investigation Steps:**

```bash
# Step 1: Check current bucket policy
aws s3api get-bucket-policy --bucket <bucket-name> | python3 -m json.tool

# Step 2: Check bucket ACL
aws s3api get-bucket-acl --bucket <bucket-name>

# Step 3: Check public access block settings
aws s3api get-public-access-block --bucket <bucket-name>

# Step 4: Check bucket encryption status
aws s3api get-bucket-encryption --bucket <bucket-name>

# Step 5: Review CloudTrail for who changed the policy
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::S3::Bucket \
    --start-time <incident-start>

# Step 6: If S3 access logs are enabled, look for external downloads
# (Access logs are stored in another S3 bucket as text files)
aws s3 cp s3://<log-bucket>/prefix/ /tmp/s3logs/ --recursive
grep -h "GET" /tmp/s3logs/* | awk '{print $5, $8, $9}' | sort | uniq -c | sort -rn
```

**Containment:**
1. Apply a restrictive bucket policy immediately (deny all except your IR role).
2. Re-enable S3 Block Public Access at the account level.
3. Re-enable encryption.
4. If data was exfiltrated, begin breach notification procedures.

---

### 4. Privilege Escalation

**Indicators:**
- AttachUserPolicy or PutUserPolicy with AdministratorAccess or `*:*`
- User attaching policies to themselves
- CreatePolicyVersion (replacing a policy with a more permissive one)
- PassRole followed by CreateFunction or RunInstances (role chaining)
- GuardDuty: `PrivilegeEscalation:IAMUser/AdministrativePermissions`

**Investigation Steps:**

```bash
# Step 1: Check what policies are attached to the suspect user
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>

# Step 2: Review inline policy documents
aws iam get-user-policy --user-name <user> --policy-name <policy>

# Step 3: Look for policy attachment events in CloudTrail
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
    --start-time <incident-start>

# Step 4: Check if the user created new policy versions
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=CreatePolicyVersion \
    --start-time <incident-start>

# Step 5: Check for any roles the user could assume
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS==`arn:aws:iam::123456789012:user/<user>`]]'
```

**Containment:**
1. Detach all managed policies from the user.
2. Delete all inline policies.
3. Apply an explicit deny-all policy.
4. Revoke active sessions.
5. Audit all changes the user made after escalation.

---

## Containment Actions

### Disable Access Keys

```bash
aws iam update-access-key --user-name <user> --access-key-id <AKIA...> --status Inactive
```

### Revoke Active Sessions (Inline Deny Policy)

This policy denies all actions for sessions issued before a given time.

```bash
aws iam put-user-policy --user-name <user> --policy-name RevokeOldSessions \
    --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "DateLessThan": {
                "aws:TokenIssueTime": "2025-11-18T03:00:00Z"
            }
        }
    }]
}'
```

### Service Control Policy (SCP) for Emergency Lockdown

Apply to the OU or account to prevent further damage.

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "DenyAllExceptIR",
        "Effect": "Deny",
        "NotAction": [
            "iam:*",
            "cloudtrail:*",
            "guardduty:*",
            "sts:GetCallerIdentity"
        ],
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {
                "aws:PrincipalArn": "arn:aws:iam::123456789012:role/IncidentResponseRole"
            }
        }
    }]
}
```

### Security Group Lockdown

```bash
# Remove the offending rule
aws ec2 revoke-security-group-ingress \
    --group-id sg-0abcdef1234567890 \
    --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]'

# Or replace all rules with a deny-all (empty rule set)
aws ec2 revoke-security-group-ingress \
    --group-id sg-0abcdef1234567890 \
    --security-group-rule-ids <rule-id>
```

### Terminate Rogue EC2 Instances

```bash
# First disable termination protection if the attacker enabled it
aws ec2 modify-instance-attribute \
    --instance-id i-0mining00000000001 \
    --no-disable-api-termination \
    --region ap-southeast-1

# Then terminate
aws ec2 terminate-instances \
    --instance-ids i-0mining00000000001 i-0mining00000000002 \
    --region ap-southeast-1
```

---

## Evidence Preservation

### Snapshot EBS Volumes

Before terminating a compromised instance, capture its disks.

```bash
# List volumes attached to the instance
aws ec2 describe-volumes \
    --filters "Name=attachment.instance-id,Values=<instance-id>" \
    --query 'Volumes[].[VolumeId,Attachments[0].Device]' --output table

# Create snapshot
aws ec2 create-snapshot \
    --volume-id vol-0abcdef1234567890 \
    --description "IR Evidence - incident-2025-1118 - <instance-id>" \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Incident,Value=IR-2025-1118},{Key=Evidence,Value=true}]'
```

### Preserve CloudTrail Logs

```bash
# CloudTrail logs are stored in S3 -- copy them to a forensics bucket
# with object lock enabled (WORM) so they cannot be tampered with
aws s3 sync \
    s3://original-cloudtrail-bucket/AWSLogs/123456789012/CloudTrail/us-east-1/2025/11/ \
    s3://forensics-evidence-bucket/incident-2025-1118/cloudtrail/ \
    --storage-class GLACIER_IR
```

### Copy S3 Access Logs

```bash
aws s3 sync \
    s3://s3-access-log-bucket/confidential-hr-data/ \
    s3://forensics-evidence-bucket/incident-2025-1118/s3-access-logs/
```

### Capture Instance Metadata (Before Termination)

```bash
# From within the instance (if accessible via SSM)
aws ssm send-command \
    --instance-ids <instance-id> \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["ps aux > /tmp/processes.txt","netstat -tlnp > /tmp/connections.txt","cat /etc/passwd > /tmp/users.txt","crontab -l > /tmp/crontab.txt","find / -mtime -1 -type f > /tmp/recent_files.txt"]'
```

### Memory Acquisition

```bash
# For Nitro-based instances, use the EC2 instance connect or SSM
# to install LiME or AVML and capture memory
aws ssm send-command \
    --instance-ids <instance-id> \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["curl -L https://github.com/microsoft/avml/releases/latest/download/avml -o /tmp/avml","chmod +x /tmp/avml","/tmp/avml /tmp/memory.lime"]'
```

---

## MITRE ATT&CK Cloud Matrix Mapping

The following table maps common cloud attack patterns to MITRE ATT&CK for
Cloud (IaaS) techniques.  These mappings are used by the analysis scripts in
this project.

| Tactic | Technique | AWS API Indicators |
|--------|-----------|-------------------|
| **Initial Access** | T1078.004 Valid Accounts: Cloud Accounts | ConsoleLogin (without MFA, unusual IP) |
| **Execution** | T1059.009 Cloud API | Any unauthorized API call via stolen credentials |
| **Persistence** | T1136.003 Create Account: Cloud Account | CreateUser, CreateRole |
| **Persistence** | T1098.001 Additional Cloud Credentials | CreateAccessKey, CreateLoginProfile |
| **Persistence** | T1098.003 Additional Cloud Roles | AttachUserPolicy, PutUserPolicy, AttachRolePolicy |
| **Privilege Escalation** | T1098.003 Additional Cloud Roles | AttachUserPolicy (AdministratorAccess) |
| **Defense Evasion** | T1562.008 Disable Cloud Logs | StopLogging, DeleteTrail, UpdateTrail |
| **Defense Evasion** | T1562.001 Disable or Modify Tools | DeleteDetector (GuardDuty), DeleteConfigRule |
| **Discovery** | T1087.004 Cloud Account Discovery | ListUsers, ListRoles, GetCallerIdentity |
| **Discovery** | T1580 Cloud Infrastructure Discovery | DescribeInstances, ListBuckets, DescribeSecurityGroups |
| **Lateral Movement** | T1550.001 Application Access Token | AssumeRole (especially cross-account) |
| **Collection** | T1530 Data from Cloud Storage | GetObject on sensitive S3 buckets |
| **Exfiltration** | T1537 Transfer Data to Cloud Account | PutBucketPolicy (public), cross-account S3 copy |
| **Impact** | T1496 Resource Hijacking | RunInstances (GPU types), crypto mining |

---

*This playbook is maintained as part of a cybersecurity portfolio project. All
AWS CLI commands shown use documentation-safe account IDs and example IPs. In
a real engagement, replace placeholders with actual resource identifiers from
the affected environment.*
