# Cybersecurity Operations Toolkit

**SOC Analyst | Security Operations | Incident Response**

Defensive security tools, automation scripts, and investigation workflows built on Kali Linux with open-source tooling used in production SOC environments.

## What's Here

| Tool | What It Does |
|------|-------------|
| [SIEM Threat Detection](./siem-threat-detection/) | Wazuh SIEM deployment with custom detection rules for brute-force, SQLi, XSS, and file integrity monitoring. Includes alert triage playbook and MITRE ATT&CK-mapped detection scenarios. |
| [Phishing Analysis](./phishing-analysis/) | Email header forensics and IOC extraction toolkit. Parses .eml files, extracts indicators (IPs, domains, hashes), supports defang/refang for safe sharing. |
| [Vulnerability Assessment](./vulnerability-assessment/) | Nmap wrapper with scan profiles, automated XML parsing, CVSS severity scoring, and Markdown report generation for stakeholder delivery. |
| [Security Automation](./security-automation/) | Five Python tools for SOC workflows: log parser, hash checker (VirusTotal), port monitor, IP reputation (AbuseIPDB), and file integrity monitor. Zero dependencies. |
| [Incident Response](./incident-response/) | NIST 800-61 playbooks for malware, ransomware, and phishing incidents. Includes two full investigation write-ups with timelines and ATT&CK mappings. |
| [Network Traffic Analysis](./network-traffic-analysis/) | Pcap analyzer and DNS anomaly detector. Flags C2 beaconing, port scans, DGA domains, and DNS tunneling. Wireshark and tcpdump filter references included. |
| [NIST Compliance Tool](./nist-compliance-tool/) | NIST CSF v1.1 assessment engine. Interactive or file-based input, weighted scoring across 43 controls, maturity tier calculation, and gap analysis with remediation roadmap. |
| [AWS Security Audit](./aws-security-audit/) | Automated security checks across IAM, S3, EC2, CloudTrail, and RDS mapped to CIS AWS Foundations Benchmark v2.0. Includes demo mode for evaluation without credentials. |
| [Cloud IR & Log Analysis](./cloud-ir-log-analysis/) | CloudTrail log analysis for cloud incident investigations. Detects credential compromise, privilege escalation, crypto mining, and data exfiltration. Fully offline with sample attack scenarios. |

## Tools & Technologies

**SIEM/Monitoring:** Wazuh, Splunk (fundamentals), ELK Stack
**Network Analysis:** Wireshark, tcpdump, Zeek
**Scanning:** Nmap, OpenVAS, Nikto
**Scripting:** Python 3, Bash
**OS:** Kali Linux, Ubuntu Server
**Cloud:** AWS (IAM, S3, EC2, CloudTrail, RDS, GuardDuty, Security Hub)
**Frameworks:** NIST CSF, NIST 800-61 (IR), MITRE ATT&CK, CIS Benchmarks, Kill Chain

## Certifications

- Google Cybersecurity Professional Certificate *(in progress)*
- CompTIA Security+ *(planned)*

## Contact

- Email: flt@ifly.app
