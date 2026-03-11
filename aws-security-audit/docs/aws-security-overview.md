# AWS Security Overview

An overview of AWS security concepts, services, common misconfigurations, and how the audit toolkit in this project maps to industry-standard benchmarks.

---

## The Shared Responsibility Model

AWS security operates on a **shared responsibility model** that divides security obligations between AWS and the customer.

### AWS Responsibility ("Security OF the Cloud")

AWS is responsible for protecting the infrastructure that runs all AWS services:

- **Physical security** of data centers (access controls, surveillance, environmental protections)
- **Network infrastructure** (routers, switches, load balancers, firewalls)
- **Hypervisor and host operating system** for managed services
- **Hardware lifecycle** (provisioning, decommissioning, disk destruction)
- **Global infrastructure** (Regions, Availability Zones, Edge Locations)

### Customer Responsibility ("Security IN the Cloud")

Customers are responsible for everything they put in and configure on AWS:

- **Identity and Access Management (IAM)** -- who can do what
- **Data encryption** -- at rest and in transit
- **Network configuration** -- VPCs, security groups, NACLs, routing
- **Operating system and application patches** (for EC2, ECS, EKS)
- **Firewall and security group rules**
- **Client-side and server-side encryption settings**
- **Logging and monitoring configuration**
- **Compliance and data classification**

### Why This Matters for Security Auditing

The majority of AWS security incidents result from customer-side misconfigurations, not AWS infrastructure failures. Common causes include:

- Overly permissive IAM policies
- S3 buckets left public
- Security groups with 0.0.0.0/0 ingress on sensitive ports
- Unrotated access keys
- CloudTrail disabled or misconfigured
- Unencrypted data at rest

This audit toolkit focuses entirely on the customer side of the shared responsibility model -- the configurations that organizations control and are accountable for.

---

## AWS Security Services Overview

### IAM (Identity and Access Management)

The foundation of AWS security. IAM controls who (authentication) can do what (authorization) on which resources.

**Key concepts:**
- **Users:** Individual identities with long-term credentials
- **Roles:** Temporary credential providers for services, applications, and federated users
- **Policies:** JSON documents defining permissions (Allow/Deny on Actions for Resources)
- **Groups:** Collections of users for simplified policy management
- **Permissions boundaries:** Maximum permissions an IAM entity can have (prevents privilege escalation)

**Security considerations:** IAM misconfigurations are the most common root cause of AWS breaches. Overly permissive policies, unrotated credentials, and missing MFA account for a large percentage of incidents.

### AWS CloudTrail

Records API calls made in your AWS account. Every action taken through the console, CLI, SDKs, or other AWS services is logged.

**Key features:**
- Management events (control plane operations like `CreateBucket`, `RunInstances`)
- Data events (data plane operations like `GetObject`, `PutObject`)
- Insights events (anomalous API activity detection)
- Log file integrity validation (cryptographic hash chain)
- Multi-region and organization-level trails

**Security considerations:** CloudTrail is essential for incident investigation. Without it, you cannot determine what happened, who did it, or when. An attacker's first action is often to disable or modify CloudTrail.

### Amazon GuardDuty

A managed threat detection service that continuously monitors for malicious activity and unauthorized behavior.

**Detection categories:**
- **Reconnaissance:** Port scanning, unusual API probing
- **Instance compromise:** Cryptocurrency mining, C2 communication, DNS exfiltration
- **Account compromise:** API calls from Tor exit nodes, disabled security controls, unusual resource creation
- **Credential compromise:** Calls from unusual geolocations, impossible travel

**Data sources analyzed:**
- VPC Flow Logs
- DNS query logs
- CloudTrail management and S3 data events
- EKS audit logs
- RDS login activity
- Lambda network activity
- Runtime monitoring (agents on EC2/ECS/EKS)

**Security considerations:** GuardDuty requires no infrastructure to deploy and no log sources to configure. It should be enabled in every account and every region. Findings should be routed to a SIEM or Security Hub for centralized monitoring.

### AWS Security Hub

A centralized security findings aggregator and compliance checker.

**Key features:**
- Aggregates findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, Firewall Manager, and third-party tools
- Automated compliance checks against CIS AWS Foundations Benchmark, AWS Foundational Security Best Practices, PCI DSS, and NIST 800-53
- Cross-account and cross-region finding aggregation
- Custom actions and automated remediation via EventBridge

**Security considerations:** Security Hub provides the single-pane-of-glass view that SOC teams need. However, it is only as good as the services feeding into it. GuardDuty, Config, and CloudTrail must be properly configured first.

### AWS Config

Continuously records and evaluates resource configurations against desired rules.

**Key features:**
- Configuration recording for all supported resource types
- Configuration history and timeline
- Config Rules (managed and custom) for automated compliance evaluation
- Conformance packs (collections of rules for compliance frameworks)
- Remediation actions (automatic or manual via SSM)

**Security considerations:** Config enables continuous compliance monitoring. It answers the question "is this resource still compliant?" over time, not just at the point of an audit. Critical Config rules include: encrypted volumes, public S3 buckets, unused credentials, and unrestricted security groups.

### IAM Access Analyzer

Identifies resources shared with external entities by analyzing resource-based policies.

**Supported resource types:**
- S3 buckets
- IAM roles (cross-account trust)
- KMS keys
- Lambda functions and layers
- SQS queues
- Secrets Manager secrets

**Security considerations:** Access Analyzer generates findings when a resource policy grants access outside the zone of trust (the AWS account or organization). It is particularly valuable for catching unintended cross-account access and public resource exposure.

### Additional Security Services

| Service | Purpose |
|---------|---------|
| **Amazon Macie** | Uses ML to discover, classify, and protect sensitive data (PII, credentials) in S3 |
| **Amazon Inspector** | Automated vulnerability scanning for EC2 instances, container images, and Lambda functions |
| **AWS WAF** | Web application firewall for CloudFront, ALB, and API Gateway |
| **AWS Shield** | DDoS protection (Standard is free; Advanced provides response team support) |
| **AWS KMS** | Key management for encryption at rest; integrates with most AWS services |
| **AWS Secrets Manager** | Manages secrets (database passwords, API keys) with automatic rotation |
| **AWS Systems Manager Session Manager** | Secure shell access to EC2 without SSH keys or open ports |

---

## Common AWS Misconfigurations and Real-World Breaches

### 1. Publicly Accessible S3 Buckets

**The misconfiguration:** S3 buckets configured with public ACLs, public bucket policies, or Block Public Access disabled.

**Real-world examples:**
- **Capital One (2019):** 106 million customer records exposed. While the initial access was via SSRF against an EC2 instance, the attacker was able to exfiltrate data from S3 because the IAM role attached to the instance had overly broad S3 permissions. The root cause was a misconfigured WAF that allowed SSRF to the EC2 metadata service (IMDSv1), combined with an overly permissive IAM role.
- **Twitch (2021):** 125 GB of source code and internal data leaked from a misconfigured S3 bucket used for server backups.
- **Various US government agencies and contractors:** Repeatedly found with public S3 buckets containing sensitive data, discovered by security researchers scanning for publicly listed buckets.

**Lessons:**
- Enable S3 Block Public Access at the account level
- Use AWS Config rules to detect public buckets
- Require SSE-KMS encryption for sensitive data buckets
- Enforce IMDSv2 on all EC2 instances to prevent SSRF-based credential theft

### 2. Overly Permissive IAM Roles and Policies

**The misconfiguration:** IAM roles or users with `Action: "*", Resource: "*"` or broad service-level wildcards like `s3:*`.

**Real-world examples:**
- **Capital One (2019):** The WAF role had permissions to list and read all S3 buckets in the account. If the role had been scoped to only the buckets it needed, the blast radius would have been limited.
- **Uber (2016):** Attackers found AWS access keys in a GitHub repository. The keys had broad permissions that allowed access to an S3 bucket containing 57 million user records.

**Lessons:**
- Follow the principle of least privilege
- Use IAM Access Analyzer to identify unused permissions
- Set permissions boundaries on all service accounts
- Never store access keys in source code; use IAM roles or OIDC federation

### 3. Exposed Access Keys

**The misconfiguration:** AWS access keys committed to public GitHub repositories, embedded in client-side code, or stored in configuration files.

**Real-world examples:**
- **Uber (2016):** Access keys discovered in a private GitHub repository that was later made public.
- Numerous incidents where developers accidentally commit `.env` files or `credentials.csv` to public repositories. AWS monitors GitHub for exposed keys and notifies account owners, but the window of exposure can be minutes.

**Lessons:**
- Use `git-secrets` or `gitleaks` to prevent credential commits
- Prefer IAM roles and OIDC federation over long-lived access keys
- Rotate keys on a 90-day schedule at maximum
- Enable AWS Config rule `access-keys-rotated`

### 4. Unrestricted Security Groups

**The misconfiguration:** Security groups allowing inbound traffic from 0.0.0.0/0 on sensitive ports (SSH, RDP, database ports).

**Real-world examples:**
- **MongoDB ransomware campaigns (2017-2019):** Thousands of MongoDB instances with port 27017 open to the internet were compromised, data was exfiltrated, and ransom notes were left in the databases.
- **Redis and Elasticsearch exposures:** Similar campaigns targeting Redis (6379) and Elasticsearch (9200/9300) instances with public security groups.

**Lessons:**
- Never expose management ports (SSH, RDP) to 0.0.0.0/0
- Use AWS Systems Manager Session Manager instead of SSH bastion hosts
- Database ports should only be accessible from application-tier security groups
- Use VPC endpoints and PrivateLink for AWS service access

### 5. Missing or Disabled CloudTrail

**The misconfiguration:** CloudTrail not enabled, not multi-region, or log file validation disabled.

**Real-world examples:**
- Attackers who gain admin access frequently disable CloudTrail to cover their tracks. Without multi-region logging, activity in unused regions goes undetected.
- In several incident response engagements, organizations could not determine the scope of a breach because CloudTrail was not configured or logs were not retained long enough.

**Lessons:**
- Enable CloudTrail in all regions (multi-region trail)
- Enable log file integrity validation
- Send logs to a separate account with restricted access
- Set up CloudWatch metric filters to alert on CloudTrail configuration changes

### 6. EC2 Instance Metadata Service v1 (SSRF Vulnerability)

**The misconfiguration:** EC2 instances using IMDSv1, which allows any process on the instance to retrieve IAM role credentials via a simple HTTP GET to 169.254.169.254.

**Real-world examples:**
- **Capital One (2019):** The attacker used a server-side request forgery (SSRF) vulnerability in the WAF to reach the metadata service and retrieve temporary IAM credentials. IMDSv2 would have prevented this because it requires a PUT request with a TTL-limited session token.

**Lessons:**
- Require IMDSv2 on all instances: `--metadata-options HttpTokens=required`
- Use a Config rule to detect instances not requiring IMDSv2
- Apply this at the account level via an SCP or a launch template default

---

## How This Audit Tool Maps to CIS AWS Foundations Benchmark

The CIS AWS Foundations Benchmark is the most widely adopted security standard for AWS configurations. This audit toolkit covers the following sections:

### Section 1: Identity and Access Management

| CIS Control | Audit Check | Tool |
|-------------|-------------|------|
| 1.4 No root access keys | Checks `AccountAccessKeysPresent` | `aws_security_auditor.py` |
| 1.5 Root MFA enabled | Checks `AccountMFAEnabled` | `aws_security_auditor.py` |
| 1.8-1.11 Password policy | Validates all password policy settings | `aws_security_auditor.py` |
| 1.10 MFA for console users | Checks every user with a password | `aws_security_auditor.py`, `iam_analyzer.py` |
| 1.12 Unused credentials | Flags accounts inactive > 90 days | `iam_analyzer.py` |
| 1.13 Single active key | Checks for multiple active keys | `iam_analyzer.py` |
| 1.14 Key rotation | Flags keys older than 90 days | `aws_security_auditor.py`, `iam_analyzer.py` |
| 1.15 Policies via groups | Checks for directly attached policies | `iam_analyzer.py` |
| 1.16 No full admin policies | Identifies wildcard admin policies | `aws_security_auditor.py`, `iam_analyzer.py` |

### Section 2: Storage

| CIS Control | Audit Check | Tool |
|-------------|-------------|------|
| 2.1.1 S3 encryption | Checks default encryption on all buckets | `aws_security_auditor.py`, `s3_bucket_scanner.py` |
| 2.1.3 S3 logging | Checks access logging configuration | `s3_bucket_scanner.py` |
| 2.1.5 S3 public access | Checks Block Public Access, ACLs, policies | `aws_security_auditor.py`, `s3_bucket_scanner.py` |
| 2.2.1 EBS encryption | Identifies unencrypted volumes | `aws_security_auditor.py` |
| 2.3.1 RDS encryption | Checks `StorageEncrypted` on all instances | `aws_security_auditor.py` |

### Section 3: Logging

| CIS Control | Audit Check | Tool |
|-------------|-------------|------|
| 3.1 CloudTrail multi-region | Checks `IsMultiRegionTrail` | `aws_security_auditor.py` |
| 3.2 Log file validation | Checks `LogFileValidationEnabled` | `aws_security_auditor.py` |
| 3.7 CloudTrail CMK encryption | Checks for `KmsKeyId` on trail | `aws_security_auditor.py` |

### Section 5: Networking

| CIS Control | Audit Check | Tool |
|-------------|-------------|------|
| 5.2 No SSH from 0.0.0.0/0 | Scans all security groups for port 22 | `aws_security_auditor.py` |
| 5.3 No RDP from 0.0.0.0/0 | Scans all security groups for port 3389 | `aws_security_auditor.py` |

### Checks Beyond CIS

This toolkit also checks several items not explicitly covered by CIS but considered security best practices:

- **RDS publicly accessible instances** -- a common misconfiguration leading to data breaches
- **RDS backup retention** -- essential for disaster recovery
- **RDS deletion protection** -- prevents accidental database loss
- **Orphaned EBS volumes** -- potential sensitive data exposure and unnecessary cost
- **Public IP on private subnet instances** -- network misconfiguration indicator
- **Wildcard CORS on S3** -- cross-origin data theft risk
- **Service account risk scoring** -- identifies high-risk programmatic users
- **S3 lifecycle rules** -- data management and cost optimization

---

## Recommended AWS Security Architecture

For organizations building a secure AWS environment, the following architecture components are recommended:

1. **AWS Organizations** with SCPs to enforce guardrails across all accounts
2. **Centralized logging account** receiving CloudTrail, Config, and VPC Flow Logs from all accounts
3. **Security tooling account** running Security Hub, GuardDuty, and centralized SIEM
4. **Network account** managing Transit Gateway, shared VPCs, and DNS
5. **Workload accounts** separated by environment (prod, staging, dev) and business unit
6. **IAM Identity Center (SSO)** for centralized human access with MFA enforcement
7. **OIDC federation** for CI/CD pipelines (no long-lived access keys)
8. **Config Conformance Packs** for continuous compliance monitoring
9. **EventBridge rules** for automated remediation of common misconfigurations
10. **Macie** for continuous sensitive data discovery in S3

---

*This overview is part of the AWS Security Audit toolkit portfolio project. For hands-on assessment, run the audit scripts in demo mode to see realistic findings and remediation guidance.*
