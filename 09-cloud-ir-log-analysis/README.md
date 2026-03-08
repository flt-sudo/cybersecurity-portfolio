# Cloud Incident Response & Log Analysis

Offline analysis toolkit for investigating AWS CloudTrail logs. Designed for
security analysts who need to demonstrate cloud IR skills without requiring
access to a live AWS account. All scripts operate on local JSON files and use
only the Python standard library.

## Project Structure

```
09-cloud-ir-log-analysis/
├── README.md
├── scripts/
│   ├── cloudtrail_analyzer.py   # CloudTrail log parser and threat detector
│   └── cloud_ioc_detector.py    # Cloud-specific IOC detection engine
├── samples/
│   ├── cloudtrail-normal.json   # 23 events showing normal AWS activity
│   ├── cloudtrail-attack.json   # 29 events showing a credential compromise attack
│   └── cloudtrail-crypto-mining.json  # 17 events showing a crypto mining attack
└── docs/
    ├── cloud-ir-playbook.md     # Cloud IR procedures, containment, evidence preservation
    └── cloud-ir-writeup.md      # Full investigation write-up of the attack scenario
```

## Tools and Techniques

- **Log format:** AWS CloudTrail JSON (Records array)
- **Language:** Python 3.x (standard library only -- no pip install needed)
- **Detection coverage:**
  - Console logins without MFA
  - IAM privilege escalation (AttachUserPolicy, PutUserPolicy, CreateUser)
  - S3 configuration tampering (PutBucketPolicy, DeleteBucketEncryption)
  - Security group changes opening to 0.0.0.0/0
  - CloudTrail tampering (StopLogging, DeleteTrail, UpdateTrail)
  - EC2 resource hijacking (GPU instance launches, termination protection)
  - Cross-account lateral movement (AssumeRole to foreign accounts)
  - Impossible travel detection
  - Off-hours API activity
  - Rapid enumeration patterns
  - Mass S3 data exfiltration
- **Framework mapping:** MITRE ATT&CK for Cloud (IaaS)

## Quick Start

No installation required. Python 3.6+ is the only dependency.

### Analyze the attack scenario

```bash
# Full analysis report with MITRE ATT&CK mapping
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-attack.json

# Show only HIGH severity findings
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-attack.json --severity high

# Print the event timeline
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-attack.json --timeline

# JSON output for piping to other tools
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-attack.json --json
```

### Detect Indicators of Compromise

```bash
# IOC detection with user risk scoring
python3 scripts/cloud_ioc_detector.py -f samples/cloudtrail-attack.json

# Analyze all sample logs at once
python3 scripts/cloud_ioc_detector.py -d samples/

# Custom business hours (9 AM - 5 PM UTC)
python3 scripts/cloud_ioc_detector.py -d samples/ --business-hours 9-17

# JSON output
python3 scripts/cloud_ioc_detector.py -f samples/cloudtrail-attack.json --json
```

### Analyze the crypto mining scenario

```bash
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-crypto-mining.json
python3 scripts/cloud_ioc_detector.py -f samples/cloudtrail-crypto-mining.json
```

### Compare normal vs malicious activity

```bash
# Normal activity -- should produce zero or very few findings
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-normal.json

# Attack activity -- should produce many HIGH severity findings
python3 scripts/cloudtrail_analyzer.py -f samples/cloudtrail-attack.json --severity high
```

### Analyze a directory of logs

```bash
# Point at any directory; the tool will recursively find all *.json files
python3 scripts/cloudtrail_analyzer.py -d samples/
python3 scripts/cloud_ioc_detector.py -d samples/
```

## Sample Scenarios

### Normal Activity (`cloudtrail-normal.json`)

Simulates a typical workday with two users (alice.johnson, bob.smith) performing
routine read operations: browsing the EC2 console, listing S3 buckets, checking
CloudWatch alarms. Both users authenticate with MFA from consistent corporate
IPs. Service-linked role AssumeRole calls from ELB and CloudFormation represent
normal background AWS activity.

### Credential Compromise Attack (`cloudtrail-attack.json`)

A complete attack lifecycle over approximately two hours:

1. **Initial Access** -- Console login without MFA from an external IP
2. **Reconnaissance** -- Rapid enumeration of IAM users, roles, S3 buckets, and EC2 instances
3. **Privilege Escalation** -- Self-attachment of AdministratorAccess policy
4. **Persistence** -- Creation of backdoor IAM user with access keys and console password
5. **Data Exfiltration** -- Download of seven sensitive files from a confidential S3 bucket
6. **Defense Evasion** -- CloudTrail stopped, GuardDuty deleted, bucket made public
7. **Lateral Movement** -- Cross-account AssumeRole and security group modification

### Crypto Mining Attack (`cloudtrail-crypto-mining.json`)

A compromised service account access key used to:

1. Enumerate GPU instance availability across regions
2. Create SSH key pairs in ap-southeast-1 and eu-west-1
3. Open security groups to all traffic (0.0.0.0/0 on all ports)
4. Launch 8x p3.8xlarge instances across two regions and 2x g4dn.xlarge in a third
5. Enable termination protection to prevent defenders from shutting them down
6. Create a new access key for persistence
7. Modify CloudTrail to disable multi-region logging and log validation

## Documentation

- **[Cloud IR Playbook](docs/cloud-ir-playbook.md)** -- Step-by-step procedures
  for investigating compromised credentials, crypto mining, S3 data exposure,
  and privilege escalation. Includes AWS CLI commands for containment and
  evidence preservation.

- **[Investigation Write-Up](docs/cloud-ir-writeup.md)** -- Full incident
  report analyzing the attack scenario from `cloudtrail-attack.json`, including
  timeline reconstruction, IOC identification, MITRE ATT&CK mapping, root
  cause analysis, and lessons learned.

## Design Decisions

**No AWS account required.** Every script works with local JSON files. This
makes the project portable, safe to run anywhere, and suitable for a portfolio
where live AWS access is not available.

**Standard library only.** No third-party packages means zero setup friction.
Clone the repo and run the scripts immediately.

**Realistic sample data.** The CloudTrail JSON files use the exact schema that
AWS produces, with all required fields (eventVersion, userIdentity, eventTime,
eventSource, eventName, awsRegion, sourceIPAddress, userAgent,
requestParameters, responseElements). IP addresses use RFC 5737 documentation
ranges (198.51.100.0/24, 203.0.113.0/24). The AWS account ID 123456789012 is
the standard documentation placeholder.

**Detection over prevention.** The scripts are investigative tools, not
preventive controls. They answer the question "what happened?" rather than
"how do we block it?" This reflects the SOC analyst workflow of receiving
alerts and conducting investigations.
