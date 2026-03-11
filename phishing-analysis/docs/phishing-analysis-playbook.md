# Phishing Analysis Playbook

A step-by-step standard operating procedure (SOP) for SOC analysts handling a reported phishing email. This playbook covers the full lifecycle from initial triage through containment, eradication, and documentation.

---

## Table of Contents

1. [Initial Triage](#1-initial-triage)
2. [Header Analysis](#2-header-analysis)
3. [Body and Content Analysis](#3-body-and-content-analysis)
4. [URL Analysis](#4-url-analysis)
5. [Attachment Analysis](#5-attachment-analysis)
6. [IOC Extraction and Threat Intel Lookup](#6-ioc-extraction-and-threat-intel-lookup)
7. [Determination: Phishing vs Legitimate](#7-determination-phishing-vs-legitimate)
8. [Response Actions](#8-response-actions)
9. [Documentation Requirements](#9-documentation-requirements)
10. [Escalation Criteria](#10-escalation-criteria)

---

## 1. Initial Triage

**Goal:** Determine the scope and urgency of the report before beginning deep analysis.

### Checklist

- [ ] Record the ticket/case number, reporter name, and time of report.
- [ ] Obtain the original email in raw `.eml` or `.msg` format (not a screenshot or forwarded copy -- forwarding strips headers).
- [ ] Ask the reporter:
  - Did you click any links in the email?
  - Did you open any attachments?
  - Did you enter credentials anywhere?
  - Did you reply to or forward the message?
- [ ] If the user clicked a link or entered credentials, **escalate immediately** -- treat as a potential compromise (skip to Section 8, Response Actions).
- [ ] Check the mail gateway / email security logs for the Message-ID to determine how many users received the same message.
- [ ] Assign a preliminary severity:
  - **Low:** No interaction, clearly spam/bulk.
  - **Medium:** No interaction, but the email is targeted or convincing.
  - **High:** User interacted with links or attachments.
  - **Critical:** User entered credentials or executed an attachment.

---

## 2. Header Analysis

**Goal:** Trace the email's origin, verify sender identity, and detect spoofing.

### Steps

1. **Extract envelope headers** using the Email Header Analyzer script or a tool such as MXToolbox Header Analyzer:
   ```
   python3 scripts/email_header_analyzer.py suspicious.eml
   ```

2. **Examine the From / Return-Path / Reply-To fields:**
   - Do they all belong to the same domain?
   - Does the display name match the actual email address?
   - Is the Reply-To address at a different domain (common in phishing)?

3. **Walk the Received headers (bottom to top):**
   - Identify the originating IP address (the first Received header added by the sender's mail server).
   - Run a WHOIS lookup on the originating IP. Does the owner match the purported sender?
   - Check for geographic inconsistencies (e.g., an email claiming to be from a US bank originating from a residential IP in a different country).

4. **Check authentication results:**
   - **SPF:** Did the sending IP pass the sender domain's SPF record? A `fail` or `softfail` indicates the server was not authorised to send on behalf of that domain.
   - **DKIM:** Did the message pass DKIM verification? A `fail` means the message was modified in transit or the signature is forged.
   - **DMARC:** Did the message pass DMARC alignment? A `fail` with `p=reject` means the domain owner has explicitly told receivers to reject unauthenticated mail.

5. **Check the X-Mailer / User-Agent header:**
   - Legitimate corporate mail is typically sent via Exchange, Google Workspace, or similar. Seeing `PHPMailer`, `Python`, or a bulk-mailer indicates a non-standard sending method.

### Red Flags

| Header Field | Suspicious Indicator |
|---|---|
| From vs Return-Path | Different domains |
| Reply-To | Free webmail provider (gmail, outlook, yahoo) when sender claims to be corporate |
| Authentication-Results | SPF fail, DKIM fail, DMARC fail |
| Received chain | Unexpected country, residential ISP, VPS provider |
| Message-ID | Domain in Message-ID does not match From domain |
| X-Mailer | PHPMailer, mass-mailing software |

---

## 3. Body and Content Analysis

**Goal:** Identify social engineering tactics and anomalies in the email body.

### What to Look For

- **Urgency and threats:** "Your account will be suspended," "Respond within 24 hours," "Immediate action required."
- **Authority impersonation:** Claims to be from IT, HR, a CEO, a bank, or law enforcement.
- **Generic greetings:** "Dear Valued Customer" instead of the recipient's actual name.
- **Grammar and spelling errors:** Mismatched tenses, unusual phrasing, or obviously machine-translated text.
- **Mismatched display text and actual URLs:** The visible text says `https://bigcorp.com/login` but the `href` attribute points to a completely different domain.
- **Embedded tracking pixels:** 1x1 images loaded from external URLs, used to confirm the recipient opened the message.
- **Request for credentials or sensitive data:** Legitimate organisations almost never ask for passwords via email.

---

## 4. URL Analysis

**Goal:** Determine whether URLs in the email lead to credential-harvesting pages, malware downloads, or other malicious destinations.

### Steps

1. **Extract all URLs** from the email body (plain-text and HTML parts). The header analyzer script does this automatically.

2. **Inspect each URL without clicking it:**
   - Does the domain match the purported sender?
   - Does it use a look-alike domain (e.g., `big-corp.com` instead of `bigcorp.com`)?
   - Does it use a raw IP address instead of a hostname?
   - Does it use URL shorteners (bit.ly, tinyurl, t.co)?
   - Does the path contain a long Base64 or hex string (common in phishing kits for victim tracking)?

3. **Look up the domain/URL in threat intelligence:**
   - VirusTotal: `https://www.virustotal.com/gui/domain/<domain>`
   - URLScan.io: `https://urlscan.io/` (submit URL for a sandboxed screenshot and analysis)
   - Google Safe Browsing: `https://transparencyreport.google.com/safe-browsing/search`
   - PhishTank: `https://phishtank.org/`

4. **If the URL must be visited for deeper analysis**, use a sandboxed browser (e.g., Any.Run, Joe Sandbox, or a disposable VM). Never visit suspicious URLs from a production workstation.

5. **Expand shortened URLs** before visiting. Use `curl -sI <short-url>` and examine the `Location` header, or use an unshortening service such as `checkshorturl.com`.

---

## 5. Attachment Analysis

**Goal:** Determine whether attachments are malicious without executing them.

### Steps

1. **Identify the attachment type.** Do not trust the file extension alone -- check the MIME type and use the `file` command to verify the actual file type.
   ```
   file Mailbox_Storage_Policy_2024.docm
   ```

2. **Compute the hash (SHA-256)** and search for it in VirusTotal:
   ```
   sha256sum suspicious_file.docm
   ```
   Then query: `https://www.virustotal.com/gui/file/<hash>`

3. **Check for macro-enabled Office formats.** Extensions like `.docm`, `.xlsm`, `.pptm` contain macros. Use `olevba` (from the `oletools` package) to extract and inspect VBA code without executing it:
   ```
   olevba suspicious_file.docm
   ```

4. **For executables and scripts** (.exe, .js, .ps1, .hta, .vbs, .bat), upload to a malware sandbox:
   - Any.Run
   - Joe Sandbox
   - Hybrid Analysis (hybrid-analysis.com)
   - Triage (tria.ge)

5. **For PDF files**, use `pdf-parser.py` or `pdfid.py` (from Didier Stevens' tools) to check for JavaScript, embedded files, or launch actions.

6. **For archive files** (.zip, .rar, .7z, .iso), note whether they are password-protected (the password is often provided in the email body -- a common evasion tactic). Extract in a sandbox and analyze the contents.

### Risk Levels by File Type

| Extension | Risk Level | Notes |
|---|---|---|
| .exe, .scr, .dll | Critical | Direct executable |
| .docm, .xlsm, .pptm | High | Macro-enabled Office documents |
| .js, .vbs, .wsf, .hta | High | Script files that execute on double-click |
| .iso, .img | High | Disk images that auto-mount on modern Windows |
| .lnk | High | Shortcut files that can run arbitrary commands |
| .ps1, .bat, .cmd | High | Shell/PowerShell scripts |
| .pdf | Medium | Can contain JavaScript and embedded files |
| .doc, .xls, .ppt | Medium | Legacy Office formats (can contain macros) |
| .html, .htm | Medium | Can redirect or run JavaScript |
| .zip, .rar, .7z | Varies | Depends on contents; password-protection is a red flag |

---

## 6. IOC Extraction and Threat Intel Lookup

**Goal:** Extract all indicators of compromise and correlate them against threat intelligence.

### Steps

1. **Extract IOCs** from the email headers, body, and any decoded attachment metadata:
   ```
   python3 scripts/email_header_analyzer.py suspicious.eml > analysis.txt
   python3 scripts/ioc_extractor.py -f analysis.txt --format json -o iocs.json
   ```

2. **Categorise the IOCs:**
   - Sender IP addresses (from Received headers)
   - Sender email addresses and domains
   - URLs in the email body
   - Attachment file names and hashes
   - Any IP addresses, domains, or hashes found inside attachments

3. **Query each IOC against threat intelligence platforms:**

   | IOC Type | Lookup Tools |
   |---|---|
   | IP address | VirusTotal, AbuseIPDB, Shodan, GreyNoise |
   | Domain | VirusTotal, URLScan, WHOIS, PassiveTotal |
   | URL | VirusTotal, URLScan, Google Safe Browsing, PhishTank |
   | File hash | VirusTotal, MalwareBazaar, Hybrid Analysis |
   | Email address | Have I Been Pwned (breach check), EmailRep.io |

4. **Check internal threat intel:** Search your SIEM, EDR, and firewall logs for any of the extracted IOCs. This determines whether anyone else in the organisation has interacted with the same infrastructure.

5. **Record the findings** -- note which IOCs returned positive hits, the associated malware family or campaign name (if any), and the confidence level of the intelligence.

---

## 7. Determination: Phishing vs Legitimate

**Goal:** Reach a verdict and assign a classification.

### Decision Matrix

| Factor | Points to Phishing | Points to Legitimate |
|---|---|---|
| SPF/DKIM/DMARC | Any `fail` result | All `pass` |
| From vs Return-Path | Different domains | Same domain |
| Reply-To | Different domain or free webmail | Same as From domain |
| URL domains | Mismatch with sender, use of IP addresses, look-alike domains | Match the sender's actual domain |
| Attachment type | Macro-enabled, executable, script | Standard document without macros |
| Content tone | Urgency, threats, credential requests | Informational, no credential request |
| Threat intel | IOCs flagged by multiple sources | No hits |
| Recipient targeting | Sent to many users, generic greeting | Sent to a specific person with context |

### Verdicts

- **Confirmed Phishing:** Multiple indicators align. Proceed to Response Actions.
- **Suspicious / Inconclusive:** Some indicators present but not definitive. Escalate to Tier 2 for deeper analysis and hold the email in quarantine.
- **Legitimate / False Positive:** No indicators found, sender and content are verified. Release from quarantine if applicable and close the ticket.

---

## 8. Response Actions

**Goal:** Contain the threat and prevent further exposure.

### If the email is confirmed phishing:

1. **Quarantine / Purge:**
   - Use the email admin console (Exchange Admin Center, Google Admin, etc.) to search for and delete all instances of the message across all mailboxes using the Message-ID.
   - Quarantine the email on the mail gateway.

2. **Block the sender:**
   - Add the sender address and domain to the email gateway block list.
   - Add the originating IP to the mail gateway IP deny list.

3. **Block IOCs on network controls:**
   - Add malicious URLs and domains to the web proxy / DNS sinkhole block list.
   - Add malicious IPs to the firewall deny list.
   - Create IDS/IPS signatures if applicable.

4. **If the user clicked a link:**
   - Force a password reset for the affected account immediately.
   - Review the account's recent sign-in activity for evidence of unauthorised access.
   - Check for newly created inbox rules (attackers often create auto-forward rules).
   - Enable or verify MFA on the account.
   - Check web proxy logs for the user's workstation to see what data was sent to the phishing site.

5. **If the user opened an attachment:**
   - Isolate the endpoint from the network using the EDR tool.
   - Run a full malware scan.
   - Collect forensic artefacts (process list, network connections, recently created files, scheduled tasks, registry autoruns).
   - Re-image the workstation if malware execution is confirmed.

6. **Notify affected users:**
   - Send a targeted notification to all recipients of the phishing email.
   - Include a brief description of what the email looked like (subject, sender) and instruct users who interacted with it to report immediately.

7. **Notify management / CIRT:**
   - Escalate per the organisation's incident response plan if multiple users are affected or if credential compromise is confirmed.

---

## 9. Documentation Requirements

Every analysed phishing report must be documented in the ticketing system with the following fields:

| Field | Description |
|---|---|
| Case/Ticket ID | Unique identifier |
| Date/Time Reported | When the user submitted the report |
| Reporter | Name, email, and department of the person who reported it |
| Subject Line | Exact subject of the phishing email |
| Sender Address | From header value |
| Return-Path | Envelope sender |
| Originating IP | First Received header IP |
| Authentication Results | SPF, DKIM, DMARC verdicts |
| IOCs | All extracted IPs, domains, URLs, hashes |
| Threat Intel Findings | Which IOCs were flagged and by which source |
| Verdict | Confirmed Phishing / Suspicious / Legitimate |
| Users Affected | Count and list of recipients |
| User Interaction | Did any user click, open, or enter credentials? |
| Response Actions Taken | Block lists updated, passwords reset, endpoints isolated, etc. |
| Analyst | Name of the analyst who performed the investigation |
| Time to Resolution | Elapsed time from report to closure |
| Lessons Learned | Any process gaps or detection improvements identified |

---

## 10. Escalation Criteria

Escalate to Tier 2 / Incident Response Team immediately if any of the following are true:

- A user entered credentials on a phishing page.
- Malware was executed on an endpoint.
- More than 10 users received the same phishing email.
- The phishing campaign appears to be specifically targeting your organisation (spear phishing).
- The email contains a zero-day exploit or novel malware (no VirusTotal results).
- The phishing infrastructure is linked to a known APT group.
- A senior executive or privileged account holder is among the recipients.

---

## Appendix: Tool Quick Reference

| Tool | Purpose | Link |
|---|---|---|
| MXToolbox Header Analyzer | Online header analysis | https://mxtoolbox.com/EmailHeaders.aspx |
| VirusTotal | Multi-engine file/URL/IP/domain analysis | https://www.virustotal.com |
| URLScan.io | Sandboxed URL screenshot and analysis | https://urlscan.io |
| AbuseIPDB | IP reputation lookup | https://www.abuseipdb.com |
| PhishTank | Community phishing URL database | https://phishtank.org |
| Any.Run | Interactive malware sandbox | https://any.run |
| Hybrid Analysis | Automated malware sandbox | https://hybrid-analysis.com |
| MalwareBazaar | Malware sample sharing | https://bazaar.abuse.ch |
| oletools (olevba) | Office macro extraction | https://github.com/decalage2/oletools |
| Didier Stevens PDF tools | PDF structure analysis | https://blog.didierstevens.com |
