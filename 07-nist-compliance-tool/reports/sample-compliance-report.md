# NIST Cybersecurity Framework Compliance Report

## Pinnacle Financial Services, LLC

| | |
|---|---|
| **Report Date** | 2025-11-15 14:30:00 |
| **Assessment Date** | 2025-11-15 |
| **Assessor** | Security & Compliance Team |
| **Scope** | Enterprise IT environment including corporate network, cloud workloads (AWS), SaaS applications, and remote workforce infrastructure |
| **Framework** | NIST Cybersecurity Framework (CSF) v1.1 |
| **Overall Score** | 62.3% |
| **Maturity Tier** | Tier 3 - Repeatable |

**Classification: CONFIDENTIAL**

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Compliance Score Dashboard](#compliance-score-dashboard)
3. [Maturity Level Assessment](#maturity-level-assessment)
4. [Function-by-Function Breakdown](#function-by-function-breakdown)
5. [Gap Analysis](#gap-analysis)
6. [Remediation Roadmap](#remediation-roadmap)
7. [Appendix: Methodology](#appendix-methodology)

---

## Executive Summary

This report presents the findings of a NIST Cybersecurity Framework (CSF) v1.1 compliance assessment conducted for **Pinnacle Financial Services, LLC** on **2025-11-15**.

### Key Findings

- **Overall compliance score: 62.3%** -- classified as **Moderate** posture.
- **Maturity tier: Tier 3 (Repeatable)** -- Formally approved risk management practices are regularly updated based on business requirements and a changing threat landscape.
- **43** controls were assessed, of which **19** are fully compliant, **15** are partially compliant, and **9** are non-compliant.
- **24 gaps** were identified, including **9 high-priority** and **10 medium-priority** findings.
- **Strongest function:** Respond (RS) at 78.1%.
- **Weakest function:** Recover (RC) at 21.5% -- requires immediate attention.

### Risk Posture Overview

The assessment reveals a security program that has foundational elements in place but exhibits significant gaps in several critical areas. The organization demonstrates strength in incident response and operational security controls (Respond function at 78.1%), reflecting investment in MSSP SOC services and a formalized IRP. However, recovery planning (21.5%) represents a critical weakness, with outdated disaster recovery documentation, undefined RTOs/RPOs for supporting infrastructure, and no post-incident recovery strategies.

The Identify (60.7%), Protect (70.0%), and Detect (62.5%) functions show moderate compliance, with a pattern of foundational controls being in place but lacking the maturity, automation, and coverage needed for a financial services organization.

### Compliance Distribution

```
  Compliant (Yes)       19  [#############---------------------]
  Partial              15  [##########------------------------]
  Non-Compliant (No)    9  [######----------------------------]
```

---

## Compliance Score Dashboard

### Overall Score

```
  62.3%  [###############################-------------------] 62.3%
```

### Function Scores

```
  Identify   (ID)  [########################----------------] 60.7%  (Moderate)
  Protect    (PR)  [############################------------] 70.0%  (Moderate)
  Detect     (DE)  [#########################---------------] 62.5%  (Moderate)
  Respond    (RS)  [###############################---------] 78.1%  (Moderate)
  Recover    (RC)  [########--------------------------------] 21.5%  (Critical)
```

### Category Heat Map

| Function | Category | Score | Rating |
|----------|----------|-------|--------|
| Identify | Asset Management (ID.AM) | 38.5% | Critical |
| Identify | Business Environment (ID.BE) | 73.1% | Moderate |
| Identify | Governance (ID.GV) | 100.0% | Strong |
| Identify | Risk Assessment (ID.RA) | 72.2% | Moderate |
| Identify | Risk Management Strategy (ID.RM) | 50.0% | Weak |
| Identify | Supply Chain Risk Management (ID.SC) | 0.0% | Critical |
| Protect | Identity Mgmt & Access Control (PR.AC) | 83.3% | Strong |
| Protect | Awareness and Training (PR.AT) | 100.0% | Strong |
| Protect | Data Security (PR.DS) | 75.0% | Moderate |
| Protect | Information Protection (PR.IP) | 73.7% | Moderate |
| Protect | Maintenance (PR.MA) | 50.0% | Weak |
| Protect | Protective Technology (PR.PT) | 50.0% | Weak |
| Detect | Anomalies and Events (DE.AE) | 34.5% | Critical |
| Detect | Security Continuous Monitoring (DE.CM) | 82.8% | Strong |
| Detect | Detection Processes (DE.DP) | 75.0% | Moderate |
| Respond | Response Planning (RS.RP) | 100.0% | Strong |
| Respond | Communications (RS.CO) | 72.2% | Moderate |
| Respond | Analysis (RS.AN) | 76.3% | Moderate |
| Respond | Mitigation (RS.MI) | 100.0% | Strong |
| Respond | Improvements (RS.IM) | 50.0% | Weak |
| Recover | Recovery Planning (RC.RP) | 26.3% | Critical |
| Recover | Improvements (RC.IM) | 0.0% | Critical |
| Recover | Communications (RC.CO) | 38.5% | Critical |

---

## Maturity Level Assessment

**Current Maturity: Tier 3 - Repeatable**

| Tier | Name | Score Range | Description | Current |
|------|------|-------------|-------------|---------|
| Tier 4 | Adaptive | 80%+ | The organization adapts its cybersecurity practices based on lessons learned and predictive indicators. Risk management is part of organizational culture. Real-time continuous monitoring and automated response capabilities are in place. | |
| Tier 3 | Repeatable | 60-79% | Formally approved policies and procedures exist, are regularly updated, and address anticipated cyber events. Risk-informed decisions are consistently applied across the organization. | <<< |
| Tier 2 | Risk Informed | 30-59% | Management-approved practices exist but may not be consistently applied across the organization. Risk awareness is present but processes are not fully formalized or organization-wide. | |
| Tier 1 | Partial | 0-29% | Cybersecurity risk management is ad-hoc and reactive. Practices are implemented in an irregular fashion. Limited organizational awareness of cybersecurity risk. | |

### Path to Next Tier

To advance from Tier 3 to **Tier 4 (Adaptive)**, the organization needs to improve by approximately **18 percentage points**. Key actions:

- Implement predictive cybersecurity analytics and threat modeling
- Establish automated, real-time response capabilities
- Embed cybersecurity risk management into organizational culture
- Develop metrics-driven continuous improvement processes

---

## Function-by-Function Breakdown

### Identify (ID) -- 60.7% (Moderate)

*Develop an organizational understanding to manage cybersecurity risk to systems, people, assets, data, and capabilities.*

```
  Score: [########################----------------] 60.7%
```

#### Asset Management (ID.AM) -- 38.5%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| ID.AM-1 | Physical devices and systems within the organization are inventoried. | PARTIAL | Hardware inventory exists in a spreadsheet but is not automated. Last full reconciliation was 6 months ago. No coverage for IoT devices or personal mobile devices used for work. |
| ID.AM-2 | Software platforms and applications within the organization are inventoried. | PARTIAL | Software inventory maintained for licensed commercial software only. No visibility into SaaS shadow IT. Open-source components not tracked. |
| ID.AM-3 | Organizational communication and data flows are mapped. | FAIL | No formal data flow diagrams exist. Network topology is partially documented but data flows between cloud and on-prem are not mapped. |

#### Business Environment (ID.BE) -- 73.1%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| ID.BE-1 | The organization's role in the supply chain is identified and communicated. | PASS | Supply chain role documented as part of vendor management program. Critical vendor dependencies identified. |
| ID.BE-2 | The organization's place in critical infrastructure and its industry sector is identified and communicated. | PARTIAL | Financial services sector role acknowledged but formal communication to DFS regulator and sector ISAC is inconsistent. |

#### Governance (ID.GV) -- 100.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| ID.GV-1 | Organizational cybersecurity policy is established and communicated. | PASS | Cybersecurity policy suite approved by CISO and Board. Policies reviewed annually. Distributed via intranet and acknowledged by all employees during onboarding. |
| ID.GV-2 | Cybersecurity roles and responsibilities are coordinated and aligned with internal roles and external partners. | PASS | RACI matrix in place for cybersecurity functions. Dedicated security team of 3 FTEs plus MSSP for 24/7 SOC coverage. |

#### Risk Assessment (ID.RA) -- 72.2%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| ID.RA-1 | Asset vulnerabilities are identified and documented. | PARTIAL | Quarterly vulnerability scans run via Nessus for internal network. Cloud workloads scanned monthly. No regular scanning of web applications or APIs. |
| ID.RA-2 | Cyber threat intelligence is received from information sharing forums and sources. | PASS | Subscribed to FS-ISAC threat feeds, CISA alerts, and vendor security advisories. Threat intel reviewed weekly by security team. |

#### Risk Management Strategy (ID.RM) -- 50.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| ID.RM-1 | Risk management processes are established, managed, and agreed to by organizational stakeholders. | PARTIAL | Risk management framework documented but risk register is not regularly updated. Last formal risk assessment was 14 months ago. |

#### Supply Chain Risk Management (ID.SC) -- 0.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| ID.SC-1 | Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders. | FAIL | No formal supply chain risk management program. Vendor security assessments performed ad-hoc for new vendors only. No continuous monitoring of existing vendor risk posture. |

---

### Protect (PR) -- 70.0% (Moderate)

*Develop and implement appropriate safeguards to ensure delivery of critical infrastructure services.*

```
  Score: [############################------------] 70.0%
```

#### Identity Management, Authentication, and Access Control (PR.AC) -- 83.3%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| PR.AC-1 | Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users, and processes. | PASS | Active Directory for identity lifecycle. Automated provisioning/deprovisioning via HR integration. Quarterly access reviews completed. |
| PR.AC-3 | Remote access is managed. | PASS | Remote access via Cisco AnyConnect VPN with MFA (Duo). Session timeouts configured. Split tunneling disabled. |
| PR.AC-4 | Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties. | PARTIAL | Least privilege implemented for production systems. Separation of duties enforced for financial applications. However, admin account proliferation exists in dev/test environments. |

#### Awareness and Training (PR.AT) -- 100.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| PR.AT-1 | All users are informed and trained. | PASS | Monthly phishing simulations via KnowBe4. Annual security awareness training mandatory for all employees. Completion rate: 94% last quarter. |

#### Data Security (PR.DS) -- 75.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| PR.DS-1 | Data-at-rest is protected. | PARTIAL | BitLocker deployed on all company laptops. Database encryption enabled for production databases. File server data not encrypted at rest. AWS S3 buckets use SSE-S3. |
| PR.DS-2 | Data-in-transit is protected. | PASS | TLS 1.2+ enforced for all web traffic. Internal APIs use mutual TLS. Legacy TLS 1.0/1.1 disabled across all endpoints. |

#### Information Protection Processes and Procedures (PR.IP) -- 73.7%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| PR.IP-1 | A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles. | PARTIAL | CIS Benchmark hardening applied to Windows servers. Linux hardening is ad-hoc. No formal baseline for cloud workloads or containers. |
| PR.IP-4 | Backups of information are conducted, maintained, and tested. | PASS | Daily incremental, weekly full backups via Veeam. Backups replicated to offsite location and AWS S3. Restoration tested semi-annually with documented results. |

#### Maintenance (PR.MA) -- 50.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| PR.MA-1 | Maintenance and repair of organizational assets are performed and logged in a timely manner, with approved and controlled tools. | PARTIAL | Maintenance windows defined for production systems. Change management process in ServiceNow. However, maintenance logging is inconsistent for network equipment. |

#### Protective Technology (PR.PT) -- 50.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| PR.PT-1 | Audit/log records are determined, documented, implemented, and reviewed in accordance with policy. | PARTIAL | Logs collected from Windows servers, firewalls, and VPN in Splunk SIEM. Linux server logs and cloud audit trails (CloudTrail) not yet integrated. Log review is reactive, not proactive. |

---

### Detect (DE) -- 62.5% (Moderate)

*Develop and implement appropriate activities to identify the occurrence of a cybersecurity event.*

```
  Score: [#########################---------------] 62.5%
```

#### Anomalies and Events (DE.AE) -- 34.5%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| DE.AE-1 | A baseline of network operations and expected data flows for users and systems is established and managed. | FAIL | No formal baseline of normal network operations established. Network monitoring is threshold-based only (bandwidth alerts), not behavioral. |
| DE.AE-2 | Detected events are analyzed to understand attack targets and methods. | PARTIAL | MSSP SOC performs initial triage of alerts. However, internal team lacks formal triage procedures and threat analysis frameworks (e.g., MITRE ATT&CK mapping). |
| DE.AE-3 | Event data are collected and correlated from multiple sources and sensors. | PARTIAL | Splunk SIEM ingests logs from multiple sources but correlation rules are basic. No integration with cloud-native security tools (GuardDuty, Security Hub). |

#### Security Continuous Monitoring (DE.CM) -- 82.8%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| DE.CM-1 | The network is monitored to detect potential cybersecurity events. | PASS | Palo Alto NGFW with IPS enabled at perimeter. MSSP monitors firewall alerts 24/7. Internal network segmentation monitored via switch ACL logs. |
| DE.CM-4 | Malicious code is detected. | PASS | CrowdStrike Falcon EDR deployed on all endpoints (workstations and servers). Real-time detection with automated containment for high-severity threats. |
| DE.CM-7 | Monitoring for unauthorized personnel, connections, devices, and software is performed. | PARTIAL | NAC implemented for wired connections but not wireless. Software inventory checked via endpoint agent but no real-time blocking of unauthorized software. |

#### Detection Processes (DE.DP) -- 75.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| DE.DP-1 | Roles and responsibilities for detection are well defined to ensure accountability. | PASS | SOC team roles defined in SOC charter. Tier 1 (MSSP), Tier 2 (internal analysts), Tier 3 (senior/IR lead) escalation path documented. |
| DE.DP-4 | Event detection information is communicated. | PARTIAL | Critical alerts escalated to management via PagerDuty. Routine event summaries provided weekly. No formal process for communicating detection information to external parties or regulators. |

---

### Respond (RS) -- 78.1% (Moderate)

*Develop and implement appropriate activities to take action regarding a detected cybersecurity incident.*

```
  Score: [###############################---------] 78.1%
```

#### Response Planning (RS.RP) -- 100.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RS.RP-1 | Response plan is executed during or after an incident. | PASS | Incident Response Plan documented and approved. Based on NIST SP 800-61 Rev 2. Tabletop exercise conducted 8 months ago. |

#### Communications (RS.CO) -- 72.2%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RS.CO-1 | Personnel know their roles and order of operations when a response is needed. | PASS | IRP includes roles, escalation matrix, and communication templates. Contact list updated quarterly. War room procedures defined. |
| RS.CO-2 | Incidents are reported consistent with established criteria. | PARTIAL | Internal reporting criteria defined. However, regulatory notification requirements (state breach laws, NYDFS) not fully mapped to IR procedures. |

#### Analysis (RS.AN) -- 76.3%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RS.AN-1 | Notifications from detection systems are investigated. | PASS | MSSP SOC investigates all alerts with SLA: Critical <15 min, High <1 hr. Internal team reviews escalated incidents with documented analysis. |
| RS.AN-2 | The impact of the incident is understood. | PARTIAL | Impact assessment performed for major incidents. However, no formal business impact analysis (BIA) framework is integrated into the IR process for rapid scoping. |

#### Mitigation (RS.MI) -- 100.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RS.MI-1 | Incidents are contained. | PASS | Containment procedures documented: network isolation via firewall rules, endpoint quarantine via CrowdStrike, account lockout procedures. Tested during tabletop. |
| RS.MI-2 | Incidents are mitigated. | PASS | Eradication and remediation steps documented in IRP. Post-containment vulnerability patching and credential rotation procedures in place. |

#### Improvements (RS.IM) -- 50.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RS.IM-1 | Response plans incorporate lessons learned. | PARTIAL | Lessons learned meetings held after major incidents. However, findings are not consistently tracked to completion and IRP updates are delayed. |

---

### Recover (RC) -- 21.5% (Critical)

*Develop and implement appropriate activities to maintain plans for resilience and to restore any capabilities or services that were impaired due to a cybersecurity incident.*

```
  Score: [########--------------------------------] 21.5%
```

#### Recovery Planning (RC.RP) -- 26.3%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RC.RP-1 | Recovery plan is executed during or after a cybersecurity incident. | PARTIAL | Business Continuity Plan exists but DRP is outdated (last updated 18 months ago). Recovery procedures not tested for cloud workloads. |
| RC.RP-2 | Recovery strategies and plans are updated based on lessons learned. | FAIL | RTOs and RPOs defined for Tier 1 applications only. Not defined for supporting infrastructure or cloud services. No recent DR test to validate achievability. |

#### Improvements (RC.IM) -- 0.0%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RC.IM-1 | Recovery plans incorporate lessons learned. | FAIL | Recovery plans have not been updated based on recent incidents or organizational changes. Cloud migration changes not reflected. |
| RC.IM-2 | Recovery strategies are updated. | FAIL | Recovery strategies not reviewed since initial creation. No process for periodic review of recovery strategies against evolving threat landscape. |

#### Communications (RC.CO) -- 38.5%

| Control | Description | Status | Notes |
|---------|-------------|--------|-------|
| RC.CO-1 | Public relations are managed. | PARTIAL | Basic crisis communication templates exist. PR firm on retainer. However, customer notification procedures not tested and media response plan lacks detail. |
| RC.CO-2 | Reputation is repaired after an incident. | FAIL | No formal reputation recovery plan. Post-incident stakeholder communication is ad-hoc. No planned transparency measures or trust-rebuilding activities. |

---

## Gap Analysis

A total of **24 compliance gaps** were identified:

- **High Priority:** 9
- **Medium Priority:** 10
- **Low Priority:** 5

### Top Gaps by Priority

| Rank | Control | Function | Status | Priority | Finding |
|------|---------|----------|--------|----------|---------|
| 1 | ID.AM-3 | Identify | No | High | Organizational communication and data flows are mapped. |
| 2 | DE.AE-1 | Detect | No | High | A baseline of network operations and expected data flows for users and systems is established and managed. |
| 3 | RC.RP-2 | Recover | No | High | Recovery strategies and plans are updated based on lessons learned. |
| 4 | PR.AC-4 | Protect | Partial | High | Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties. |
| 5 | PR.DS-1 | Protect | Partial | High | Data-at-rest is protected. |
| 6 | PR.IP-1 | Protect | Partial | High | A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles. |
| 7 | PR.PT-1 | Protect | Partial | High | Audit/log records are determined, documented, implemented, and reviewed in accordance with policy. |
| 8 | ID.RA-1 | Identify | Partial | High | Asset vulnerabilities are identified and documented. |
| 9 | RC.RP-1 | Recover | Partial | High | Recovery plan is executed during or after a cybersecurity incident. |
| 10 | ID.AM-1 | Identify | Partial | Medium | Physical devices and systems within the organization are inventoried. |
| 11 | ID.AM-2 | Identify | Partial | Medium | Software platforms and applications within the organization are inventoried. |
| 12 | ID.RM-1 | Identify | Partial | Medium | Risk management processes are established, managed, and agreed to by organizational stakeholders. |
| 13 | DE.AE-2 | Detect | Partial | Medium | Detected events are analyzed to understand attack targets and methods. |
| 14 | DE.AE-3 | Detect | Partial | Medium | Event data are collected and correlated from multiple sources and sensors. |
| 15 | DE.CM-7 | Detect | Partial | Medium | Monitoring for unauthorized personnel, connections, devices, and software is performed. |

### Gap Distribution by Function

```
  Identify    [##############-----------] 5 gaps
  Protect     [###################------] 5 gaps
  Detect      [###################------] 5 gaps
  Respond     [###########--------------] 3 gaps
  Recover     [#########################] 6 gaps
```

### Detailed Gap Findings

#### Finding #1: ID.AM-3 -- High Priority

- **Control:** Organizational communication and data flows are mapped.
- **Function:** Identify
- **Current Status:** No
- **Assessment Question:** Are organizational communication and data flows (internal and external) documented and mapped?
- **Assessor Notes:** No formal data flow diagrams exist. Network topology is partially documented but data flows between cloud and on-prem are not mapped.

#### Finding #2: DE.AE-1 -- High Priority

- **Control:** A baseline of network operations and expected data flows for users and systems is established and managed.
- **Function:** Detect
- **Current Status:** No
- **Assessment Question:** Has the organization established and documented a baseline of normal network operations and expected data flows to enable anomaly detection?
- **Assessor Notes:** No formal baseline of normal network operations established. Network monitoring is threshold-based only (bandwidth alerts), not behavioral.

#### Finding #3: RC.RP-2 -- High Priority

- **Control:** Recovery strategies and plans are updated based on lessons learned.
- **Function:** Recover
- **Current Status:** No
- **Assessment Question:** Are recovery time objectives (RTO) and recovery point objectives (RPO) defined for critical systems, and are they tested and achievable?
- **Assessor Notes:** RTOs and RPOs defined for Tier 1 applications only. Not defined for supporting infrastructure or cloud services. No recent DR test to validate achievability.

#### Finding #4: PR.AC-4 -- High Priority

- **Control:** Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties.
- **Function:** Protect
- **Current Status:** Partial
- **Assessment Question:** Are access permissions managed using the principle of least privilege and separation of duties, with periodic access reviews?
- **Assessor Notes:** Least privilege implemented for production systems. Separation of duties enforced for financial applications. However, admin account proliferation exists in dev/test environments.

#### Finding #5: PR.DS-1 -- High Priority

- **Control:** Data-at-rest is protected.
- **Function:** Protect
- **Current Status:** Partial
- **Assessment Question:** Is data-at-rest protected using encryption (e.g., AES-256, BitLocker, LUKS) on endpoints, servers, databases, and removable media?
- **Assessor Notes:** BitLocker deployed on all company laptops. Database encryption enabled for production databases. File server data not encrypted at rest. AWS S3 buckets use SSE-S3.

#### Finding #6: PR.IP-1 -- High Priority

- **Control:** A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles.
- **Function:** Protect
- **Current Status:** Partial
- **Assessment Question:** Are baseline security configurations (hardening standards) established, documented, and maintained for all IT systems and platforms?
- **Assessor Notes:** CIS Benchmark hardening applied to Windows servers. Linux hardening is ad-hoc. No formal baseline for cloud workloads or containers.

#### Finding #7: PR.PT-1 -- High Priority

- **Control:** Audit/log records are determined, documented, implemented, and reviewed in accordance with policy.
- **Function:** Protect
- **Current Status:** Partial
- **Assessment Question:** Are audit and log records collected from critical systems, centralized in a SIEM or log management platform, and reviewed regularly?
- **Assessor Notes:** Logs collected from Windows servers, firewalls, and VPN in Splunk SIEM. Linux server logs and cloud audit trails (CloudTrail) not yet integrated. Log review is reactive, not proactive.

#### Finding #8: ID.RA-1 -- High Priority

- **Control:** Asset vulnerabilities are identified and documented.
- **Function:** Identify
- **Current Status:** Partial
- **Assessment Question:** Does the organization regularly identify, document, and track asset vulnerabilities using scanning tools and threat intelligence?
- **Assessor Notes:** Quarterly vulnerability scans run via Nessus for internal network. Cloud workloads scanned monthly. No regular scanning of web applications or APIs.

#### Finding #9: RC.RP-1 -- High Priority

- **Control:** Recovery plan is executed during or after a cybersecurity incident.
- **Function:** Recover
- **Current Status:** Partial
- **Assessment Question:** Does the organization have a formal recovery plan (BCP/DRP) that is executed during or after a cybersecurity incident to restore normal operations?
- **Assessor Notes:** Business Continuity Plan exists but DRP is outdated (last updated 18 months ago). Recovery procedures not tested for cloud workloads.

#### Finding #10: ID.AM-1 -- Medium Priority

- **Control:** Physical devices and systems within the organization are inventoried.
- **Function:** Identify
- **Current Status:** Partial
- **Assessment Question:** Does the organization maintain a current inventory of all physical devices and systems (servers, workstations, mobile devices, IoT, network equipment)?
- **Assessor Notes:** Hardware inventory exists in a spreadsheet but is not automated. Last full reconciliation was 6 months ago. No coverage for IoT devices or personal mobile devices used for work.

#### Finding #11: ID.AM-2 -- Medium Priority

- **Control:** Software platforms and applications within the organization are inventoried.
- **Function:** Identify
- **Current Status:** Partial
- **Assessment Question:** Does the organization maintain a current inventory of all software platforms and applications deployed across the environment?
- **Assessor Notes:** Software inventory maintained for licensed commercial software only. No visibility into SaaS shadow IT. Open-source components not tracked.

#### Finding #12: ID.RM-1 -- Medium Priority

- **Control:** Risk management processes are established, managed, and agreed to by organizational stakeholders.
- **Function:** Identify
- **Current Status:** Partial
- **Assessment Question:** Are formal risk management processes established, documented, and agreed upon by key organizational stakeholders including executive leadership?
- **Assessor Notes:** Risk management framework documented but risk register is not regularly updated. Last formal risk assessment was 14 months ago.

#### Finding #13: DE.AE-2 -- Medium Priority

- **Control:** Detected events are analyzed to understand attack targets and methods.
- **Function:** Detect
- **Current Status:** Partial
- **Assessment Question:** Are detected security events analyzed to determine attack targets, methods, and potential impact using structured triage processes?
- **Assessor Notes:** MSSP SOC performs initial triage of alerts. However, internal team lacks formal triage procedures and threat analysis frameworks (e.g., MITRE ATT&CK mapping).

#### Finding #14: DE.AE-3 -- Medium Priority

- **Control:** Event data are collected and correlated from multiple sources and sensors.
- **Function:** Detect
- **Current Status:** Partial
- **Assessment Question:** Is event data collected and correlated from multiple sources (firewalls, IDS/IPS, endpoints, servers, cloud) using a SIEM or similar platform?
- **Assessor Notes:** Splunk SIEM ingests logs from multiple sources but correlation rules are basic. No integration with cloud-native security tools (GuardDuty, Security Hub).

#### Finding #15: DE.CM-7 -- Medium Priority

- **Control:** Monitoring for unauthorized personnel, connections, devices, and software is performed.
- **Function:** Detect
- **Current Status:** Partial
- **Assessment Question:** Does the organization monitor for unauthorized personnel, rogue devices, unauthorized connections, and unapproved software installations?
- **Assessor Notes:** NAC implemented for wired connections but not wireless. Software inventory checked via endpoint agent but no real-time blocking of unauthorized software.

#### Finding #16: RS.CO-2 -- Medium Priority

- **Control:** Incidents are reported consistent with established criteria.
- **Function:** Respond
- **Current Status:** Partial
- **Assessment Question:** Are incidents reported according to established criteria, including regulatory notification requirements (e.g., breach notification laws, CISA reporting)?
- **Assessor Notes:** Internal reporting criteria defined. However, regulatory notification requirements (state breach laws, NYDFS) not fully mapped to IR procedures.

#### Finding #17: RS.AN-2 -- Medium Priority

- **Control:** The impact of the incident is understood.
- **Function:** Respond
- **Current Status:** Partial
- **Assessment Question:** During incident response, is the full impact of the incident assessed including affected systems, data exposure scope, and business impact?
- **Assessor Notes:** Impact assessment performed for major incidents. However, no formal business impact analysis (BIA) framework is integrated into the IR process for rapid scoping.

#### Finding #18: DE.DP-4 -- Medium Priority

- **Control:** Event detection information is communicated.
- **Function:** Detect
- **Current Status:** Partial
- **Assessment Question:** Is event detection information communicated to appropriate stakeholders, including security teams, management, and external parties as required?
- **Assessor Notes:** Critical alerts escalated to management via PagerDuty. Routine event summaries provided weekly. No formal process for communicating detection information to external parties or regulators.

#### Finding #19: RS.IM-1 -- Medium Priority

- **Control:** Response plans incorporate lessons learned.
- **Function:** Respond
- **Current Status:** Partial
- **Assessment Question:** Are post-incident reviews (lessons learned) conducted after significant incidents, and are findings incorporated into updated response plans?
- **Assessor Notes:** Lessons learned meetings held after major incidents. However, findings are not consistently tracked to completion and IRP updates are delayed.

#### Finding #20: ID.SC-1 -- Low Priority

- **Control:** Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders.
- **Function:** Identify
- **Current Status:** No
- **Assessment Question:** Does the organization have formal supply chain risk management processes that assess and manage cybersecurity risks from third-party suppliers and partners?
- **Assessor Notes:** No formal supply chain risk management program. Vendor security assessments performed ad-hoc for new vendors only. No continuous monitoring of existing vendor risk posture.

#### Finding #21: PR.MA-1 -- Low Priority

- **Control:** Maintenance and repair of organizational assets are performed and logged in a timely manner, with approved and controlled tools.
- **Function:** Protect
- **Current Status:** Partial
- **Assessment Question:** Is maintenance and repair of IT assets performed in a timely manner with approved tools, and are all maintenance activities logged?
- **Assessor Notes:** Maintenance windows defined for production systems. Change management process in ServiceNow. However, maintenance logging is inconsistent for network equipment.

#### Finding #22: RC.IM-1 -- Low Priority

- **Control:** Recovery plans incorporate lessons learned.
- **Function:** Recover
- **Current Status:** No
- **Assessment Question:** Are recovery plans updated based on lessons learned from incidents, exercises, and changes in the business environment?
- **Assessor Notes:** Recovery plans have not been updated based on recent incidents or organizational changes. Cloud migration changes not reflected.

#### Finding #23: RC.IM-2 -- Low Priority

- **Control:** Recovery strategies are updated.
- **Function:** Recover
- **Current Status:** No
- **Assessment Question:** Are recovery strategies periodically reviewed and updated to reflect new threats, technology changes, and organizational changes?
- **Assessor Notes:** Recovery strategies not reviewed since initial creation. No process for periodic review of recovery strategies against evolving threat landscape.

#### Finding #24: RC.CO-2 -- Low Priority

- **Control:** Reputation is repaired after an incident.
- **Function:** Recover
- **Current Status:** No
- **Assessment Question:** Are reputation recovery activities planned and executed after incidents, including stakeholder communication and transparency measures?
- **Assessor Notes:** No formal reputation recovery plan. Post-incident stakeholder communication is ad-hoc. No planned transparency measures or trust-rebuilding activities.

---

## Remediation Roadmap

The following remediation plan is organized into three phases based on risk priority, implementation complexity, and potential security impact.

### Phase 1: Immediate Actions (0-90 Days)

**Objective:** Address high-priority gaps that represent the greatest risk to the organization.

| # | Control | Action | Effort Estimate |
|---|---------|--------|-----------------|
| 1 | ID.AM-3 | Implement: Organizational communication and data flows are mapped. | Medium |
| 2 | DE.AE-1 | Implement: A baseline of network operations and expected data flows for users and systems is established and managed. | Medium |
| 3 | RC.RP-2 | Implement: Recovery strategies and plans are updated based on lessons learned. | Medium |
| 4 | PR.AC-4 | Enhance and formalize: Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties. | High |
| 5 | PR.DS-1 | Enhance and formalize: Data-at-rest is protected. | High |
| 6 | PR.IP-1 | Enhance and formalize: A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles. | Medium |
| 7 | PR.PT-1 | Enhance and formalize: Audit/log records are determined, documented, implemented, and reviewed in accordance with policy. | High |
| 8 | ID.RA-1 | Enhance and formalize: Asset vulnerabilities are identified and documented. | High |
| 9 | RC.RP-1 | Enhance and formalize: Recovery plan is executed during or after a cybersecurity incident. | High |

**Estimated Resource Requirement:** 360-720 person-hours

**Recommended Actions:**

1. **Data Flow Mapping (ID.AM-3):** Engage network and application teams to document all data flows using a tool such as Lucidchart or Visio. Prioritize flows involving PII, financial data, and cross-boundary (cloud/on-prem) transfers.

2. **Network Baseline (DE.AE-1):** Deploy a network detection and response (NDR) solution or configure behavioral analytics in the existing SIEM to establish and monitor baseline traffic patterns.

3. **DRP Modernization (RC.RP-1, RC.RP-2):** Update the disaster recovery plan to include cloud workloads. Define RTOs/RPOs for all Tier 1-3 applications. Schedule a full DR test within 60 days.

4. **Access Control Remediation (PR.AC-4):** Conduct an audit of dev/test environment admin accounts. Implement JIT (just-in-time) access for privileged accounts. Remove standing admin access where possible.

5. **SIEM Enhancement (PR.PT-1):** Integrate Linux server logs, AWS CloudTrail, and GuardDuty alerts into Splunk. Develop proactive monitoring dashboards and scheduled searches.

### Phase 2: Short-Term Improvements (90-180 Days)

**Objective:** Strengthen partially implemented controls and address medium-priority gaps.

| # | Control | Action | Effort Estimate |
|---|---------|--------|-----------------|
| 1 | ID.AM-1 | Enhance and document: Physical devices and systems within the organization are inventoried. | Medium |
| 2 | ID.AM-2 | Enhance and document: Software platforms and applications within the organization are inventoried. | Medium |
| 3 | ID.RM-1 | Enhance and document: Risk management processes are established, managed, and agreed to by organizational stakeholders. | Medium |
| 4 | DE.AE-2 | Enhance and document: Detected events are analyzed to understand attack targets and methods. | Medium |
| 5 | DE.AE-3 | Enhance and document: Event data are collected and correlated from multiple sources and sensors. | Medium |
| 6 | DE.CM-7 | Enhance and document: Monitoring for unauthorized personnel, connections, devices, and software is performed. | Medium |
| 7 | RS.CO-2 | Enhance and document: Incidents are reported consistent with established criteria. | Medium |
| 8 | RS.AN-2 | Enhance and document: The impact of the incident is understood. | Medium |
| 9 | DE.DP-4 | Enhance and document: Event detection information is communicated. | Medium |
| 10 | RS.IM-1 | Enhance and document: Response plans incorporate lessons learned. | Medium |

**Estimated Resource Requirement:** 300-600 person-hours

**Recommended Actions:**

1. **Asset Management Automation (ID.AM-1, ID.AM-2):** Deploy an automated asset discovery tool (e.g., Lansweeper, ServiceNow Discovery) that covers hardware, software, SaaS, and cloud assets. Integrate with CMDB.

2. **Risk Register Update (ID.RM-1):** Conduct a formal risk assessment and update the risk register. Establish a quarterly risk review cadence with executive stakeholders.

3. **SIEM Correlation (DE.AE-2, DE.AE-3):** Develop MITRE ATT&CK-aligned correlation rules in Splunk. Integrate cloud-native security tools. Create analyst playbooks for common alert types.

4. **Regulatory Mapping (RS.CO-2):** Map all applicable breach notification laws (state laws, NYDFS 23 NYCRR 500, GLBA) to IR procedures with specific timelines and responsible parties.

### Phase 3: Long-Term Maturity (180-365 Days)

**Objective:** Build organizational maturity and address remaining gaps to advance to the next tier.

| # | Control | Action | Effort Estimate |
|---|---------|--------|-----------------|
| 1 | ID.SC-1 | Implement: Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders. | Low |
| 2 | PR.MA-1 | Formalize and document: Maintenance and repair of organizational assets are performed and logged in a timely manner, with approved and controlled tools. | Low |
| 3 | RC.IM-1 | Implement: Recovery plans incorporate lessons learned. | Low |
| 4 | RC.IM-2 | Implement: Recovery strategies are updated. | Low |
| 5 | RC.CO-2 | Implement: Reputation is repaired after an incident. | Low |

**Estimated Resource Requirement:** 100-200 person-hours

**Recommended Actions:**

1. **Vendor Risk Management (ID.SC-1):** Implement a third-party risk management program using a platform (e.g., SecurityScorecard, BitSight) for continuous vendor risk monitoring. Establish vendor tiering and assessment frequency based on data access and criticality.

2. **Recovery Program Maturity (RC.IM-1, RC.IM-2):** Establish a quarterly review cadence for recovery plans. Integrate lessons learned from incidents and exercises. Update strategies to reflect cloud architecture changes.

3. **Crisis Communications (RC.CO-2):** Develop a comprehensive crisis communications playbook including customer notification templates, media holding statements, and stakeholder briefing cadences.

### Resource Summary

| Phase | Gaps | Timeline | Est. Hours |
|-------|------|----------|------------|
| Phase 1 (Immediate) | 9 | 0-90 days | 360-720 |
| Phase 2 (Short-term) | 10 | 90-180 days | 300-600 |
| Phase 3 (Long-term) | 5 | 180-365 days | 100-200 |
| **Total** | **24** | **12 months** | **760-1,520** |

### Key Success Metrics

To track remediation progress, monitor the following KPIs:

- **Gap closure rate:** Percentage of identified gaps remediated per quarter
- **Overall compliance score:** Target progression from 62.3% toward 80% (Tier 4)
- **Mean time to remediate (MTTR):** Average days from gap identification to closure
- **Recurrence rate:** Percentage of previously closed gaps that reopen
- **Assessment coverage:** Percentage of controls assessed in subsequent reviews

---

## Appendix: Methodology

### Assessment Framework

This assessment was conducted using the **NIST Cybersecurity Framework (CSF) v1.1**, published by the National Institute of Standards and Technology. The CSF provides a structured approach for organizations to manage and reduce cybersecurity risk.

### Scoring Methodology

Each control was assessed using the following scale:

| Response | Score | Description |
|----------|-------|-------------|
| Yes | 1.0 | Control is fully implemented and operating effectively |
| Partial | 0.5 | Control is partially implemented or not consistently applied |
| No | 0.0 | Control is not implemented |
| N/A | -- | Control is not applicable to the organization's environment |

Scores are weighted by control importance and aggregated at the category, function, and overall levels using weighted averages.

### Priority Classification

Gaps are prioritized based on control weight and compliance status:

- **High:** Non-compliant controls with weight >= 0.9, or partially compliant controls with weight >= 1.0
- **Medium:** Controls with weight >= 0.7 not classified as High
- **Low:** All remaining gaps

### Maturity Tiers

The NIST CSF defines four implementation tiers that describe the degree of rigor and sophistication of an organization's cybersecurity risk management practices:

- **Tier 1 (Partial, 0-29%):** Ad-hoc, reactive practices
- **Tier 2 (Risk Informed, 30-59%):** Management-approved but inconsistent practices
- **Tier 3 (Repeatable, 60-79%):** Formally approved and regularly updated practices
- **Tier 4 (Adaptive, 80%+):** Practices adapted based on predictive indicators

### Limitations

- This assessment reflects a point-in-time evaluation based on information provided by the organization.
- Self-assessment responses were not independently validated through technical testing.
- Scores represent compliance posture, not security effectiveness.
- Remediation timelines are estimates and depend on organizational resources and priorities.

---

*Report generated on 2025-11-15 14:30:00 by NIST CSF Compliance Checker v1.0.0*

*This document is classified as CONFIDENTIAL and intended for authorized recipients only.*
