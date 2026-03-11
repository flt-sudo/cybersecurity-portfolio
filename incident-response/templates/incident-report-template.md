# Incident Report

---

## Incident Metadata

| Field | Value |
|-------|-------|
| **Incident ID** | INC-YYYY-NNNN |
| **Date Opened** | YYYY-MM-DD HH:MM UTC |
| **Date Closed** | YYYY-MM-DD HH:MM UTC |
| **Duration** | _Total time from detection to closure_ |
| **Incident Handler** | _Name, title_ |
| **Severity** | P1 Critical / P2 High / P3 Medium / P4 Low |
| **Classification** | Malware / Ransomware / Phishing / Data Breach / Unauthorized Access / Denial of Service / Insider Threat / Other |
| **Status** | Open / Investigating / Contained / Eradicated / Recovered / Closed |
| **MITRE ATT&CK Techniques** | _e.g., T1566.001, T1078, T1486_ |
| **Related Tickets** | _Links to ITSM tickets, change requests, etc._ |

---

## 1. Executive Summary

_Provide a concise, non-technical summary of the incident suitable for senior leadership. Cover what happened, what the impact was, how it was resolved, and what is being done to prevent recurrence. Keep this to 3-5 sentences._

> On [DATE], the Security Operations Center detected [BRIEF DESCRIPTION OF INCIDENT] affecting [NUMBER] [systems/users/records]. The incident was classified as [SEVERITY] and was caused by [ROOT CAUSE AT A HIGH LEVEL]. Containment was achieved within [TIME], and full recovery was completed by [DATE/TIME]. [NUMBER] [records/systems/users] were impacted. [BRIEF STATEMENT ON REMEDIATION OR PREVENTION ACTIONS].

---

## 2. Timeline of Events

_Document all significant events in chronological order. Use UTC timestamps for consistency. Include detection, escalation, containment, eradication, recovery milestones, and key decisions._

| Timestamp (UTC) | Source | Event Description |
|-----------------|--------|-------------------|
| YYYY-MM-DD HH:MM | _Alert source_ | Initial alert triggered: _description_ |
| YYYY-MM-DD HH:MM | _SOC Analyst_ | Alert triaged and validated; incident created |
| YYYY-MM-DD HH:MM | _SOC Analyst_ | Escalated to [Tier 2 / IR Lead / Management] |
| YYYY-MM-DD HH:MM | _IR Team_ | Containment action: _description_ |
| YYYY-MM-DD HH:MM | _IR Team_ | Evidence collected: _description_ |
| YYYY-MM-DD HH:MM | _IR Team_ | Eradication action: _description_ |
| YYYY-MM-DD HH:MM | _IT Operations_ | Recovery action: _description_ |
| YYYY-MM-DD HH:MM | _IR Lead_ | System returned to production |
| YYYY-MM-DD HH:MM | _IR Lead_ | Incident closed |

---

## 3. Technical Analysis

### 3.1 Detection

_How was the incident detected? What alerts, logs, or reports led to the initial identification?_

- Alert name and source:
- Detection logic / rule that fired:
- Initial indicators observed:

### 3.2 Attack Vector

_How did the attacker gain initial access or how did the incident originate?_

- Entry point:
- Vulnerability or weakness exploited (if applicable, include CVE):
- User interaction required (e.g., phishing click, credential submission):

### 3.3 Attacker Actions / Incident Progression

_What did the attacker do after gaining access? Or, how did the incident progress from initial trigger to detected state?_

- Techniques used (map to MITRE ATT&CK where possible):
- Lateral movement observed:
- Tools or malware used:
- Data accessed or exfiltrated:
- Persistence mechanisms established:

### 3.4 Affected Systems

| Hostname | IP Address | OS | Role | Impact |
|----------|------------|----|------|--------|
| | | | | |
| | | | | |

### 3.5 Affected Accounts

| Account | Type | Compromise Confirmed | Actions Taken |
|---------|------|---------------------|---------------|
| | Standard / Admin / Service | Yes / Suspected | Password reset, disabled, etc. |
| | | | |

---

## 4. Impact Assessment

### 4.1 Business Impact

- **Systems affected:** _Number and criticality of systems impacted_
- **Downtime:** _Duration of any service disruption_
- **Data impact:** _Was data accessed, modified, exfiltrated, or destroyed? What type and volume?_
- **Financial impact:** _Estimated cost (response costs, lost productivity, remediation, legal, regulatory)_
- **Regulatory impact:** _Are there regulatory notification obligations? (GDPR, HIPAA, PCI DSS, state breach laws)_
- **Reputational impact:** _Was the incident public? Is there media or customer impact?_

### 4.2 Data Exposure Assessment

| Data Category | Records Affected | Classification | Exposure Type |
|---------------|-----------------|----------------|---------------|
| _e.g., PII, PHI, financial, credentials_ | _Count or estimate_ | _Confidential, Internal, Public_ | _Accessed / Exfiltrated / Destroyed_ |

---

## 5. Containment, Eradication & Recovery Actions

### 5.1 Containment

_What actions were taken to stop the incident from spreading or causing further damage?_

| Action | Timestamp | Performed By | Details |
|--------|-----------|-------------|---------|
| | | | |
| | | | |

### 5.2 Eradication

_What actions were taken to remove the threat from the environment?_

| Action | Timestamp | Performed By | Details |
|--------|-----------|-------------|---------|
| | | | |
| | | | |

### 5.3 Recovery

_What actions were taken to restore systems and operations to normal?_

| Action | Timestamp | Performed By | Details |
|--------|-----------|-------------|---------|
| | | | |
| | | | |

### 5.4 Verification

_How was it confirmed that the threat was fully removed and systems were clean?_

- Verification method:
- Verification results:
- Ongoing monitoring plan:

---

## 6. Root Cause Analysis

_Identify the fundamental cause of the incident. Go beyond the immediate technical cause to identify systemic issues._

- **Immediate cause:** _What directly led to the incident (e.g., user clicked phishing link, unpatched vulnerability)_
- **Contributing factors:** _What conditions allowed the incident to occur or increased its impact (e.g., missing MFA, flat network, excessive permissions, lack of monitoring)_
- **Root cause:** _The underlying systemic issue (e.g., no patch management process for edge devices, security awareness training not covering this attack type, no network segmentation between IT and OT)_

---

## 7. Recommendations

_Actionable recommendations to prevent recurrence and improve security posture. Each recommendation should have an owner and target completion date._

| Priority | Recommendation | Owner | Target Date | Status |
|----------|---------------|-------|-------------|--------|
| High | | | | Not Started / In Progress / Complete |
| High | | | | |
| Medium | | | | |
| Medium | | | | |
| Low | | | | |

---

## 8. Lessons Learned

_Capture what went well, what could be improved, and specific action items from the post-incident review._

### 8.1 What Went Well

- _e.g., rapid detection, effective containment, good communication_

### 8.2 What Could Be Improved

- _e.g., detection gap, slow escalation, missing runbook, tooling limitation_

### 8.3 Action Items

| Action Item | Owner | Due Date | Status |
|-------------|-------|----------|--------|
| | | | |
| | | | |

---

## 9. Notifications

| Recipient | Method | Date/Time | Notified By | Notes |
|-----------|--------|-----------|-------------|-------|
| _e.g., CISO, Legal, HR, Regulatory Body, Law Enforcement, Affected Users_ | _Email, Phone, Portal_ | | | |

---

## Appendix A: Indicators of Compromise (IOCs)

### File Indicators

| Type | Value | Context |
|------|-------|---------|
| SHA256 | | |
| SHA1 | | |
| MD5 | | |
| Filename | | |
| File path | | |

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| IP Address | | |
| Domain | | |
| URL | | |
| User-Agent | | |

### Host Indicators

| Type | Value | Context |
|------|-------|---------|
| Registry key | | |
| Scheduled task | | |
| Service name | | |
| Mutex | | |

---

## Appendix B: Evidence Log

_Chain of custody for all evidence collected during the investigation._

| Evidence ID | Description | Source | Collected By | Date/Time | Hash (SHA256) | Storage Location |
|-------------|-------------|--------|-------------|-----------|---------------|-----------------|
| EV-001 | | | | | | |
| EV-002 | | | | | | |
| EV-003 | | | | | | |

---

## Appendix C: Referenced Playbooks and Documentation

| Document | Version | Relevance |
|----------|---------|-----------|
| | | |

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Report Author** | |
| **Report Date** | |
| **Review/Approval** | _Name, title, date_ |
| **Distribution** | _Who should receive this report_ |
| **Classification** | Confidential / Internal / Restricted |
| **Next Review Date** | _If the incident has open action items_ |
