# Incident Response Documentation Suite

## Overview

This project contains a comprehensive set of incident response (IR) playbooks, report templates, simulated scenario write-ups, and reference documentation aligned with the **NIST SP 800-61 Rev. 2** *Computer Security Incident Handling Guide*. The materials reflect the processes, tooling, and decision-making expected in a modern Security Operations Center (SOC) environment.

Every artifact in this repository is designed to be operationally useful -- not theoretical. Playbooks contain specific commands, tool references, and escalation criteria. Scenario write-ups follow realistic timelines with MITRE ATT&CK mappings. Templates are ready for direct adoption or adaptation.

## NIST 800-61 Framework Alignment

The IR lifecycle defined by NIST 800-61 organizes incident handling into four phases. All playbooks and scenario documentation in this project follow this structure:

| Phase | Description | Where It Appears |
|-------|-------------|------------------|
| **1. Preparation** | Policies, tooling, training, and communication plans established before an incident occurs | Playbook prerequisites and preparation sections |
| **2. Detection & Analysis** | Identifying potential incidents through alerts, logs, and user reports; triaging and classifying severity | Playbook detection sections; scenario investigation steps |
| **3. Containment, Eradication & Recovery** | Stopping the spread, removing the threat, and restoring normal operations | Playbook response sections; scenario remediation actions |
| **4. Post-Incident Activity** | Lessons learned, IOC sharing, documentation, and process improvement | Playbook post-incident sections; scenario conclusions |

## Repository Structure

```
05-incident-response/
|-- README.md                                  # This file
|-- playbooks/
|   |-- malware-infection.md                   # Malware detection and response playbook
|   |-- ransomware.md                          # Ransomware-specific IR playbook
|   |-- phishing-compromise.md                 # Credential phishing response playbook
|-- templates/
|   |-- incident-report-template.md            # Standardized incident report format
|-- scenarios/
|   |-- scenario-01-brute-force.md             # SSH brute-force simulated write-up
|   |-- scenario-02-data-exfiltration.md       # DNS exfiltration simulated write-up
|-- docs/
    |-- nist-800-61-reference.md               # NIST 800-61 quick-reference guide
```

## Playbooks

Each playbook follows a consistent format:

- **Objective** -- What the playbook addresses and when to invoke it.
- **Scope & Applicability** -- Systems, environments, and threat categories covered.
- **Severity Classification** -- Criteria for assigning incident severity (P1-P4).
- **Detection & Identification** -- Alert sources, initial triage steps, indicators to look for.
- **Containment** -- Short-term and long-term containment actions with specific commands.
- **Eradication** -- Removal of threat artifacts, persistence mechanisms, and backdoors.
- **Recovery** -- System restoration, validation, and return to production.
- **Post-Incident Activity** -- Lessons learned, IOC documentation, rule tuning, stakeholder reporting.

## Scenario Write-ups

Simulated incident scenarios provide end-to-end examples of the IR process applied to realistic attack narratives. Each scenario includes:

- A fictional but technically plausible attack narrative
- Timestamped event timelines
- Log excerpts and SIEM alert details
- Investigation methodology and forensic analysis
- MITRE ATT&CK technique mappings
- Response actions taken and their outcomes
- Lessons learned and recommended improvements

## Tools Referenced

The playbooks and scenarios reference tools commonly deployed in enterprise SOC environments:

| Category | Tools |
|----------|-------|
| SIEM | Splunk, Elastic Security (ELK), Microsoft Sentinel |
| EDR | CrowdStrike Falcon, Microsoft Defender for Endpoint, Carbon Black |
| Network | Wireshark, Zeek, Suricata, tcpdump |
| Forensics | Volatility, KAPE, Autopsy, FTK Imager |
| Threat Intel | VirusTotal, AbuseIPDB, Shodan, MISP, AlienVault OTX |
| Ticketing | ServiceNow, Jira, TheHive |

## Intended Audience

- SOC Analysts (Tier 1 through Tier 3)
- Incident Responders
- Security Engineers building or refining IR programs
- Hiring managers and interviewers evaluating IR competency

## Author

Created as part of a cybersecurity portfolio demonstrating hands-on incident response methodology, technical writing, and SOC operational knowledge.
