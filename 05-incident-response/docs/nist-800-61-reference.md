# NIST SP 800-61 Rev. 2: Quick Reference Guide

## Computer Security Incident Handling Guide -- Practical Application

This reference maps the four phases of the NIST 800-61 incident response lifecycle to practical actions, tools, and deliverables used in a modern SOC environment.

---

## Incident Response Lifecycle Overview

```
+-------------------+     +------------------------+     +----------------------------------+     +----------------------+
|   1. Preparation  | --> | 2. Detection & Analysis| --> | 3. Containment, Eradication &    | --> | 4. Post-Incident     |
|                   |     |                        |     |    Recovery                       |     |    Activity           |
+-------------------+     +------------------------+     +----------------------------------+     +----------------------+
        ^                                                                                                   |
        |                                                                                                   |
        +---------------------------------------------------------------------------------------------------+
                                              Continuous Improvement Loop
```

Each incident feeds lessons learned back into the Preparation phase, improving the organization's ability to prevent, detect, and respond to future incidents.

---

## Phase 1: Preparation

**NIST Guidance:** Establish the capability to respond to incidents before they occur. This includes policies, procedures, tools, training, and communication plans.

### Key Activities

| Activity | Practical Implementation | Tools / Resources |
|----------|------------------------|-------------------|
| Develop incident response policy | Define what constitutes an incident, roles and responsibilities, reporting requirements, authority to act | Policy document approved by CISO and executive leadership |
| Build the IR team | Define on-call rotation, escalation paths, roles (handler, lead, communications, forensics) | PagerDuty / Opsgenie for on-call; contact cards for key personnel |
| Establish communication plan | Internal (management, legal, HR, PR) and external (law enforcement, regulators, customers, ISACs) notification procedures | Pre-drafted communication templates; secure out-of-band communication channel (Signal, satellite phone) |
| Deploy detection infrastructure | Ensure adequate visibility across endpoints, network, cloud, identity | SIEM (Splunk, Elastic, Sentinel), EDR (CrowdStrike, Defender), NDR (Zeek, Suricata), CASB |
| Prepare forensic capability | Forensic workstations, tools, evidence storage, chain of custody procedures | KAPE, Volatility, Autopsy, FTK Imager, write blockers, evidence drives |
| Configure logging | Ensure critical log sources feed into SIEM with adequate retention | Sysmon (Windows), auditd (Linux), cloud audit logs, proxy, DNS, authentication logs |
| Conduct exercises | Tabletop exercises, red team engagements, purple team exercises | Annual tabletops at minimum; quarterly technical exercises |
| Maintain asset inventory | Know what you have, who owns it, and how critical it is | CMDB (ServiceNow), asset discovery tools (Qualys, Rapid7) |
| Establish baselines | Document normal behavior to identify anomalies | Network flow baselines, user behavior analytics, process baselines |

### Preparation Checklist

- [ ] IR policy and plan documented, approved, and distributed
- [ ] IR team members identified with current contact information
- [ ] On-call rotation established and tested
- [ ] Communication templates prepared for common incident types
- [ ] SIEM deployed with critical log sources ingested
- [ ] EDR deployed to all endpoints
- [ ] Forensic toolkit assembled and validated
- [ ] Evidence handling and chain of custody procedures documented
- [ ] Playbooks created for common incident types (malware, ransomware, phishing, unauthorized access, data breach)
- [ ] Tabletop exercise conducted within the last 12 months
- [ ] External IR retainer under contract
- [ ] Cyber insurance policy in place and current
- [ ] Legal counsel identified and briefed on IR process
- [ ] Backup and recovery procedures validated

---

## Phase 2: Detection & Analysis

**NIST Guidance:** Identify potential security incidents through various means and analyze them to determine whether an incident has actually occurred, and if so, its scope and severity.

### Detection Sources

| Source Category | Specific Sources | What They Detect |
|----------------|-----------------|------------------|
| **Automated alerts** | SIEM correlation rules, EDR behavioral alerts, IDS/IPS signatures, AV detections, DLP alerts | Known attack patterns, malware, policy violations, anomalous behavior |
| **Log analysis** | Authentication logs, proxy logs, DNS logs, firewall logs, application logs | Failed logins, suspicious connections, lateral movement, data access patterns |
| **Threat intelligence** | IOC feeds, ISAC bulletins, vendor advisories, OSINT | Known-bad indicators matching internal telemetry |
| **User reports** | Help desk tickets, phishing report button, direct escalation | Suspicious emails, unusual behavior, social engineering attempts |
| **Third-party notification** | Law enforcement, partner organizations, security researchers, media | External discovery of compromise or data exposure |
| **Proactive hunting** | Hypothesis-driven threat hunts, anomaly investigation | Advanced threats that evade automated detection |

### Analysis Steps

1. **Validate the alert**
   - Is this a true positive or false positive?
   - Cross-reference against known FP patterns and suppression lists
   - Check the alert fidelity score and tuning history

2. **Gather context**
   - What is the affected asset? (hostname, IP, owner, criticality, OS, role)
   - What is the affected user? (role, privileges, recent activity)
   - What is the attack timeline? (first event, most recent event)
   - What other alerts have fired for this asset or user recently?

3. **Determine scope**
   - Is this an isolated event or part of a larger campaign?
   - Are other systems or users affected?
   - Search for related IOCs across the environment

4. **Classify severity**

   | Severity | Criteria |
   |----------|----------|
   | **P1 - Critical** | Active, confirmed compromise with high business impact. Active data exfiltration, ransomware, domain controller compromise, active attacker on the network. |
   | **P2 - High** | Confirmed compromise with controlled or moderate impact. Single-host malware with no lateral movement, compromised user account with limited access. |
   | **P3 - Medium** | Suspected compromise or contained threat. Malware blocked by AV, phishing email reported before interaction, anomaly under investigation. |
   | **P4 - Low** | Minor policy violation or low-impact event. PUP detection, non-sensitive policy violation, informational alert. |

5. **Document findings**
   - Open an incident ticket with all collected details
   - Begin the incident timeline
   - Assign an incident handler

### Analysis Tools and Techniques

| Need | Tool / Technique | Command / Query Example |
|------|-----------------|------------------------|
| IP reputation | AbuseIPDB, VirusTotal, Shodan | `curl https://api.abuseipdb.com/api/v2/check -G -d ipAddress=<IP> -H "Key: $API_KEY"` |
| File hash lookup | VirusTotal, MISP, Hybrid Analysis | `curl https://www.virustotal.com/api/v3/files/<hash> -H "x-apikey: $VT_KEY"` |
| Domain investigation | Whois, VirusTotal, urlscan.io | `whois suspicious-domain.example` |
| Log correlation | Splunk, Elastic, Sentinel | SIEM queries joining multiple data sources by shared fields (IP, user, timestamp) |
| Process analysis | EDR console, Sysmon logs | Process tree visualization, command-line analysis |
| Network analysis | Zeek, Wireshark, tcpdump | `tcpdump -i eth0 host <suspicious_ip> -w capture.pcap` |
| Memory analysis | Volatility | `vol.py -f memory.raw windows.pslist`, `vol.py -f memory.raw windows.netscan` |

---

## Phase 3: Containment, Eradication & Recovery

**NIST Guidance:** Prevent the incident from causing further damage (containment), remove the threat from the environment (eradication), and restore systems to normal operation (recovery).

### 3a. Containment

**Goal:** Stop the bleeding. Prevent the attacker from expanding their access or causing additional damage.

| Containment Type | When to Use | Actions |
|-----------------|-------------|---------|
| **Short-term** | Immediately upon confirmed incident | Network isolation via EDR, disable user accounts, block malicious IPs/domains, disconnect affected shares |
| **Long-term** | When immediate remediation is not possible (e.g., critical production system) | Apply targeted firewall rules, increase monitoring, deploy additional sensors, schedule maintenance window |

**Key containment decisions:**

| Factor | Consideration |
|--------|--------------|
| System criticality | Can the system be taken offline, or must it stay up? |
| Evidence preservation | Has volatile evidence been captured before containment actions alter the system state? |
| Containment effectiveness | Will the containment action fully stop the threat, or can the attacker bypass it? |
| Business impact | What is the cost of containment (downtime) vs. the cost of continued compromise? |
| Attacker awareness | Will containment actions alert the attacker and cause them to accelerate damage? |

**Common containment tools:**

| Action | Tool | Command |
|--------|------|---------|
| Network isolation (endpoint) | CrowdStrike Falcon | `falconctl -s --network-contain=enable` |
| Network isolation (endpoint) | Defender for Endpoint | API: `POST /api/machines/{id}/isolate` |
| Network isolation (network) | Switch / firewall | Shut down switch port or apply ACL |
| Block IP/domain | Firewall, DNS sinkhole, proxy | Add to block list at the perimeter |
| Disable account | Active Directory | `Disable-ADAccount -Identity <user>` |
| Revoke sessions | Azure AD | `Revoke-AzureADUserAllRefreshToken` |
| Kill process | EDR or local command | EDR RTR: `kill <PID>` |

### 3b. Eradication

**Goal:** Remove all traces of the threat from the environment.

| Activity | Details |
|----------|---------|
| Remove malware | Delete malicious files, processes, and artifacts from all affected systems |
| Remove persistence | Eliminate scheduled tasks, services, registry keys, cron jobs, SSH keys, web shells, and any other persistence mechanisms |
| Patch vulnerabilities | Apply patches for the vulnerability used for initial access |
| Reset credentials | Reset passwords and revoke tokens for all compromised and potentially compromised accounts |
| Remove unauthorized access | Delete backdoor accounts, unauthorized OAuth apps, VPN profiles, and remote access tools |
| Verify removal | Re-scan affected systems, validate against known-good baselines, confirm no artifacts remain |

### 3c. Recovery

**Goal:** Restore systems to normal operation and confirm the threat is eliminated.

| Activity | Details |
|----------|---------|
| Reimage or restore | Reimage endpoints from golden image; restore servers from known-good backups |
| Patch and harden | Apply all current patches and hardening baselines before returning to production |
| Validate security controls | Confirm EDR, AV, firewall rules, and monitoring are operational on restored systems |
| Monitored return | Bring systems back online in stages with heightened monitoring |
| User restoration | Provide users with new credentials, restore access, verify functionality |
| Monitor for recurrence | Enhanced monitoring for 30-72 hours post-recovery, depending on severity |

### Recovery Decision Matrix

| Scenario | Recommended Action |
|----------|-------------------|
| Single endpoint with commodity malware, no persistence | Clean in place, monitor |
| Endpoint with rootkit or kernel compromise | Reimage from golden image |
| Server with complex configuration, limited infection | Clean in place if feasible, plan reimage |
| Ransomware encryption | Reimage and restore from backup |
| Domain controller compromise | Rebuild AD from scratch or known-good DC backup |
| Cloud account compromise | Credential reset, session revocation, audit for modifications |

---

## Phase 4: Post-Incident Activity

**NIST Guidance:** Learn from the incident to improve the organization's security posture and incident response capability.

### Lessons Learned Meeting

**When:** Within 5-10 business days of incident closure.

**Attendees:** Incident handler, IR lead, affected system owners, IT operations, management (as appropriate).

**Agenda:**

| Question | Purpose |
|----------|---------|
| What exactly happened, and at what times? | Establish a shared understanding of the incident |
| How was the incident detected? | Evaluate detection effectiveness |
| How well did the response process work? | Identify process strengths and gaps |
| What could the staff and management have done differently? | Identify training and resource needs |
| What corrective actions can prevent similar incidents? | Drive security improvements |
| What additional tools or resources are needed? | Justify budget and capability requests |
| What indicators should be monitored in the future? | Improve detection for recurrence |

### Required Deliverables

| Deliverable | Owner | Timeline |
|-------------|-------|----------|
| **Incident report** | Incident handler | Within 5 business days of closure |
| **Lessons learned summary** | IR lead | Within 10 business days of closure |
| **IOC package** | IR lead / threat intelligence | Within 2 business days of closure |
| **Detection rule updates** | SOC engineering | Within 10 business days of closure |
| **Remediation action items** | Assigned owners | Tracked to completion |
| **Updated playbooks** (if gaps identified) | SOC lead | Within 30 days |
| **Evidence archive** | Incident handler | At closure (retain per policy, minimum 1 year) |

### Metrics to Track

| Metric | What It Measures | Target |
|--------|-----------------|--------|
| **Mean Time to Detect (MTTD)** | Time from incident start to first detection | Minimize |
| **Mean Time to Respond (MTTR)** | Time from detection to containment | P1: <1hr, P2: <4hr |
| **Mean Time to Recover (MTTRec)** | Time from containment to full recovery | Depends on severity |
| **Dwell Time** | Total time the attacker was in the environment | Minimize |
| **False Positive Rate** | Percentage of alerts that are not true incidents | <30% |
| **Incidents per Category** | Breakdown by type (malware, phishing, unauthorized access) | Trend analysis |
| **Recurring Incidents** | Same root cause appearing in multiple incidents | Should decrease over time |
| **Action Item Completion Rate** | Percentage of post-incident recommendations implemented | >90% within target dates |

---

## Incident Classification Categories (from NIST 800-61)

| Category | Description | Examples |
|----------|-------------|---------|
| **Unauthorized Access** | Gaining logical or physical access without permission | Brute force, credential theft, privilege escalation |
| **Denial of Service** | Disrupting or degrading service availability | DDoS, resource exhaustion, service crash |
| **Malicious Code** | Virus, worm, trojan, ransomware, or other malware | Ransomware encryption, info-stealer, RAT deployment |
| **Improper Usage** | Violation of acceptable use policies | Unauthorized software installation, policy violation |
| **Scans / Probes / Attempted Access** | Reconnaissance activities | Port scanning, vulnerability scanning, failed login attempts |
| **Investigation** | Unconfirmed anomalous activity under review | Suspicious but unclassified events |

---

## Quick-Reference: Who to Notify and When

| Condition | Notify | Method | Timing |
|-----------|--------|--------|--------|
| Any confirmed incident (P1-P3) | SOC Lead | Ticket + Slack | Immediately |
| P1 Critical incident | CISO, CTO, Legal | Phone + Email | Within 30 minutes |
| Suspected data breach (PII/PHI) | Legal Counsel, Privacy Officer | Phone + Email | Within 1 hour |
| Confirmed data breach | Regulatory bodies per applicable law | Formal filing | Per regulatory requirement (24-72 hours typically) |
| Law enforcement involvement needed | FBI (IC3), CISA, local law enforcement | Phone + Portal | As determined by legal and IR lead |
| Customer data exposed | Customer communications team | Email | After legal and executive approval |
| Insurance claim likely | Cyber insurance broker | Phone | Within 24 hours (per policy terms) |
| External IR assistance needed | Retainer firm | Phone | When internal capacity is exceeded |

---

## Appendix: Key NIST 800-61 Rev. 2 References

| Section | Topic | Key Takeaway |
|---------|-------|-------------|
| 2.3 | Incident Response Policy, Plan, and Procedure Creation | Policies should be reviewed annually; procedures should be specific enough to be actionable |
| 2.4 | Incident Response Team Structure | Can be central, distributed, or coordinated; must have clear authority and communication channels |
| 3.1 | Attack Vectors | Common categories: external/removable media, attrition, web, email, impersonation, improper usage, loss/theft |
| 3.2 | Signs of an Incident | Precursors (before) vs. indicators (during/after); most incidents are detected through indicators, not precursors |
| 3.2.4 | Incident Prioritization | Prioritize based on: functional impact, information impact, and recoverability |
| 3.3 | Notification and Escalation | Define who gets notified, by what method, and at what threshold |
| 3.4 | Containment Strategies | Criteria for containment: damage potential, evidence preservation needs, service availability, resource requirements |
| 3.5 | Evidence Gathering and Handling | Maintain chain of custody, capture volatile evidence first, use forensic imaging, document all actions |
| 4.1 | Lessons Learned | Hold meetings within several days of incident closure; develop follow-up reports and action items |
| 4.2 | Using Collected Data | Metrics-driven improvement: track incident counts, response times, and trends to guide investment |

**Full document:** NIST SP 800-61 Rev. 2 is available at: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
