# NIST Cybersecurity Framework (CSF) -- Quick Reference Guide

## What Is the NIST CSF?

The **NIST Cybersecurity Framework (CSF)** is a voluntary framework published by the National Institute of Standards and Technology (a U.S. federal agency within the Department of Commerce). First released in 2014 and updated to version 1.1 in 2018, the CSF provides a structured, flexible, and repeatable approach for organizations to manage and reduce cybersecurity risk.

The framework was originally developed for critical infrastructure sectors (energy, financial services, healthcare, etc.) in response to Executive Order 13636, but has since been widely adopted across industries and organization sizes -- from Fortune 500 enterprises to small businesses and nonprofits.

### Why Organizations Use It

- **Common language:** Provides a shared vocabulary for cybersecurity risk management across technical and business stakeholders, enabling clearer communication between CISOs, executives, boards, and regulators.
- **Risk-based approach:** Focuses on outcomes rather than prescriptive checklists, allowing organizations to prioritize activities based on their specific risk profile and business context.
- **Regulatory alignment:** Maps to and is referenced by numerous regulations and standards (HIPAA, PCI DSS, SOX, CMMC, state privacy laws), making it useful as a foundational compliance framework.
- **Scalability:** Works for organizations of any size. A 50-person company and a 50,000-person enterprise can both use the CSF; the depth of implementation scales with the organization's resources and risk appetite.
- **Continuous improvement:** The tiered maturity model encourages organizations to progressively improve their cybersecurity posture rather than treating security as a one-time project.

---

## The Five Core Functions

The CSF organizes cybersecurity activities into five concurrent and continuous functions. These are not sequential steps -- they operate simultaneously and form a lifecycle for managing cybersecurity risk.

### 1. Identify (ID)

**Purpose:** Develop an organizational understanding of cybersecurity risk to systems, people, assets, data, and capabilities.

**Key Activities:**
- Asset management -- inventory hardware, software, data, and personnel
- Business environment -- understand critical business processes and dependencies
- Governance -- establish cybersecurity policies, roles, and legal/regulatory requirements
- Risk assessment -- identify vulnerabilities, threats, and potential business impacts
- Risk management strategy -- define risk tolerance and decision-making processes
- Supply chain risk management -- assess and manage third-party cybersecurity risks

**Why It Matters:** You cannot protect what you do not know you have. The Identify function builds the foundation for the entire cybersecurity program. Without a comprehensive understanding of assets, data flows, and risks, all other security activities are reactive and incomplete.

**Common Tools & Practices:** CMDB/asset inventory (ServiceNow, Lansweeper), risk assessments (NIST SP 800-30), vulnerability scanners (Nessus, Qualys), vendor risk platforms (SecurityScorecard, BitSight).

---

### 2. Protect (PR)

**Purpose:** Develop and implement appropriate safeguards to ensure delivery of critical infrastructure services.

**Key Activities:**
- Identity management and access control -- manage identities, credentials, and access permissions (IAM, MFA, least privilege)
- Awareness and training -- security awareness programs and role-based training
- Data security -- protect data at rest and in transit through encryption, DLP, and classification
- Information protection processes -- configuration management, change control, backups
- Maintenance -- timely patching and maintenance with proper controls
- Protective technology -- firewalls, endpoint protection, log management, network segmentation

**Why It Matters:** Protection limits the impact of potential cybersecurity events. Even the best detection capabilities are insufficient if foundational protective controls (access control, encryption, patching) are weak.

**Common Tools & Practices:** Active Directory/Entra ID, MFA (Duo, Okta), EDR (CrowdStrike, SentinelOne), DLP solutions, SIEM (Splunk, Microsoft Sentinel), backup solutions (Veeam, Commvault), CIS Benchmarks for hardening.

---

### 3. Detect (DE)

**Purpose:** Develop and implement appropriate activities to identify the occurrence of a cybersecurity event.

**Key Activities:**
- Anomalies and events -- establish baselines of normal activity and detect deviations
- Security continuous monitoring -- monitor networks, endpoints, and applications for threats
- Detection processes -- define roles, test detection capabilities, and communicate findings

**Why It Matters:** Detection determines the mean time to identify (MTTI) a threat. The faster an organization can detect malicious activity, the lower the potential damage. The 2024 IBM Cost of a Data Breach Report found that breaches taking over 200 days to identify cost an average of $5.46 million versus $4.07 million for those found in under 200 days.

**Common Tools & Practices:** SIEM (Splunk, Elastic, Sentinel), IDS/IPS (Snort, Suricata, Palo Alto), EDR/XDR (CrowdStrike, Microsoft Defender), NDR (Darktrace, ExtraHop), SOC operations (internal or MSSP).

---

### 4. Respond (RS)

**Purpose:** Develop and implement appropriate activities to take action regarding a detected cybersecurity incident.

**Key Activities:**
- Response planning -- maintain and execute an incident response plan
- Communications -- coordinate with internal teams, management, legal, regulators, and affected parties
- Analysis -- investigate alerts, determine impact, perform forensic analysis
- Mitigation -- contain incidents, eradicate threats, remediate vulnerabilities
- Improvements -- conduct post-incident reviews and update plans based on lessons learned

**Why It Matters:** Effective incident response limits damage, reduces recovery time and costs, and helps prevent recurrence. Organizations with tested incident response plans save an average of $2.66 million per breach compared to those without (IBM CODB 2024).

**Common Tools & Practices:** Incident response plans (based on NIST SP 800-61), SOAR platforms (Palo Alto XSOAR, Splunk SOAR), forensic tools (Autopsy, Volatility, KAPE), communication tools (PagerDuty, Opsgenie), tabletop exercises.

---

### 5. Recover (RC)

**Purpose:** Develop and implement appropriate activities to maintain plans for resilience and to restore capabilities impaired by a cybersecurity incident.

**Key Activities:**
- Recovery planning -- maintain and test business continuity and disaster recovery plans
- Improvements -- update recovery strategies based on lessons learned and changing threats
- Communications -- manage crisis communications, public relations, and stakeholder notification

**Why It Matters:** Recovery ensures business resilience. An organization's ability to return to normal operations after an incident directly impacts financial loss, customer trust, and regulatory standing. Recovery planning is often the most neglected function, yet it determines whether an organization survives a major incident.

**Common Tools & Practices:** BCP/DRP documentation, backup and recovery testing, RTO/RPO definitions, crisis communication plans, cloud-based DR (AWS Elastic Disaster Recovery, Azure Site Recovery), tabletop and full-scale exercises.

---

## Implementation Tiers

The CSF defines four **implementation tiers** that describe the degree of rigor and sophistication in an organization's cybersecurity risk management practices. Tiers are not maturity levels in the traditional sense -- they describe how well cybersecurity risk management is integrated into broader organizational risk management.

### Tier 1: Partial (0-29%)

- Cybersecurity risk management is **ad-hoc and reactive**.
- There is limited awareness of cybersecurity risk at the organizational level.
- The organization may not have processes to share cybersecurity information internally.
- Risk management is not formalized; decisions are made inconsistently.

**Typical characteristics:** No formal security policies, no dedicated security staff, reactive patching, no incident response plan, minimal logging.

### Tier 2: Risk Informed (30-59%)

- Risk management practices are **approved by management** but may not be established as organization-wide policy.
- There is awareness of cybersecurity risk at the organizational level, but an organization-wide approach has not been established.
- Cybersecurity information is shared informally within the organization.

**Typical characteristics:** Some documented policies, basic security controls in place, periodic vulnerability scanning, informal incident handling, security awareness training exists but may not be comprehensive.

### Tier 3: Repeatable (60-79%)

- The organization's risk management practices are **formally approved and expressed as policy**.
- Practices are regularly updated based on the application of risk management processes to changes in business requirements and the threat landscape.
- There is an organization-wide approach to managing cybersecurity risk.

**Typical characteristics:** Comprehensive security policies, dedicated security team or MSSP, SIEM deployed, formal incident response plan tested regularly, regular risk assessments, security metrics reported to leadership.

### Tier 4: Adaptive (80%+)

- The organization **adapts its cybersecurity practices** based on lessons learned and predictive indicators derived from previous and current activities.
- Cybersecurity risk management is part of the organizational culture.
- The organization actively shares information with partners to ensure accurate, current threat information is available.

**Typical characteristics:** Threat-informed defense strategies, automated detection and response, continuous monitoring with behavioral analytics, proactive threat hunting, security integrated into business processes, advanced metrics and KPIs driving continuous improvement.

---

## How This Tool Maps to Real-World GRC Assessments

This compliance checker tool replicates the core workflow a GRC analyst or consultant performs during a NIST CSF assessment:

### 1. Control Identification
The tool loads the NIST CSF control catalog (functions, categories, and subcategories) from a structured template -- the same structure used in commercial GRC platforms like Archer, ServiceNow GRC, or OneTrust.

### 2. Evidence Collection
In interactive mode, the tool walks the assessor through each control, collecting Yes/No/Partial/N-A responses and supporting notes. In file mode, pre-collected responses (from interviews, document reviews, and technical testing) are loaded from a structured JSON file.

### 3. Scoring and Analysis
The tool calculates weighted compliance scores at the control, category, function, and overall levels -- the same aggregation methodology used in real assessments. Scores are mapped to NIST implementation tiers.

### 4. Gap Analysis
Non-compliant and partially compliant controls are identified, prioritized by risk weight, and documented with assessor notes. This produces the gap analysis section that is central to any GRC assessment deliverable.

### 5. Remediation Planning
Gaps are organized into a prioritized remediation roadmap with timeline recommendations (immediate, short-term, long-term), mirroring the action plans produced by GRC consultants.

### 6. Reporting
The tool generates a professional Markdown report suitable for executive and technical audiences -- similar to the deliverables produced by consulting firms during compliance engagements.

### What This Tool Does NOT Do

- **Technical validation:** The tool collects self-reported responses; it does not perform technical testing (scanning, penetration testing, configuration auditing).
- **Evidence management:** Real GRC platforms maintain evidence repositories (screenshots, policy documents, scan reports). This tool captures notes but does not manage evidence artifacts.
- **Continuous monitoring:** This is a point-in-time assessment tool, not a continuous compliance monitoring platform.
- **Regulatory mapping:** While the NIST CSF maps to many regulations, this tool does not automatically cross-reference requirements from HIPAA, PCI DSS, SOX, or other frameworks.

---

## Comparison with ISO 27001

Organizations often compare NIST CSF with ISO/IEC 27001, another widely adopted cybersecurity framework. They are complementary, not competing.

| Aspect | NIST CSF | ISO/IEC 27001 |
|--------|----------|---------------|
| **Type** | Voluntary framework / guidelines | International standard (certifiable) |
| **Origin** | U.S. (NIST, Dept. of Commerce) | International (ISO/IEC JTC 1) |
| **Certification** | No formal certification | Yes -- third-party audit and certification |
| **Structure** | 5 Functions, 23 Categories, 108 Subcategories | 14 Domains, 114 Controls (Annex A) |
| **Approach** | Risk-based, outcome-focused | Risk-based with mandatory ISMS requirements |
| **Prescriptiveness** | Flexible -- describes "what" not "how" | More prescriptive -- requires documented ISMS |
| **Cost** | Free | Standard purchase + certification audit costs |
| **Best For** | Organizations seeking a risk management framework, U.S. regulatory alignment | Organizations seeking formal certification, international recognition |
| **Maturity Model** | 4 Implementation Tiers | Maturity assessed through audit findings |
| **Maintenance** | Self-assessed, voluntary updates | Annual surveillance audits, triennial recertification |

### When to Use Which

- **Use NIST CSF** when you need a flexible, risk-based framework for internal cybersecurity program management, when regulatory bodies reference it (FFIEC, NYDFS, CMMC), or as a starting point before pursuing formal certification.
- **Use ISO 27001** when customers or partners require formal certification, when operating internationally, or when you need a prescriptive management system with external validation.
- **Use both:** Many organizations use NIST CSF for internal risk management and program measurement while pursuing ISO 27001 certification for external assurance. The two frameworks overlap significantly (NIST provides a mapping document: NIST SP 800-53 to ISO 27001).

---

## Key References

- **NIST Cybersecurity Framework v1.1:** https://www.nist.gov/cyberframework
- **NIST SP 800-53 Rev. 5 (Security and Privacy Controls):** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **NIST SP 800-61 Rev. 2 (Incident Handling Guide):** https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- **NIST SP 800-30 Rev. 1 (Risk Assessment Guide):** https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
- **CSF Reference Tool:** https://csrc.nist.gov/projects/cprt/catalog
- **ISO/IEC 27001:2022:** https://www.iso.org/standard/27001
