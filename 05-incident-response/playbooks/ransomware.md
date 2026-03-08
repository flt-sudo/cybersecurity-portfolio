# Playbook: Ransomware Incident Response

**Playbook ID:** PB-RAN-001
**Version:** 2.1
**Last Reviewed:** 2026-02-20
**Classification:** Internal Use -- PRIORITY PLAYBOOK
**NIST 800-61 Phase Coverage:** Detection & Analysis, Containment, Eradication, Recovery, Post-Incident

---

## 1. Objective

Define the response procedure for confirmed or suspected ransomware incidents. Ransomware is treated as a **P1 Critical** incident by default due to its potential for rapid lateral propagation and catastrophic operational impact. Speed of containment is the single most important factor in limiting damage.

> **Critical Principle:** Contain first, investigate second. Every minute of delay in isolation allows encryption to spread to additional systems and shared storage.

## 2. Scope & Applicability

- **Applies to:** All endpoints, servers, file shares, NAS devices, cloud storage, and virtualization infrastructure.
- **Trigger conditions:**
  - EDR alert for ransomware behavior (mass file rename, encryption API calls, ransom note creation)
  - User report of inaccessible files with unfamiliar extensions
  - Ransom note discovered on a system or shared drive
  - Shadow copy deletion detected (`vssadmin delete shadows`)
  - Mass file modification events in file integrity monitoring (FIM)
  - Canary/honeypot file triggered (decoy documents placed in shares)

## 3. Severity Classification

**All confirmed ransomware events begin at P1 -- Critical.** Severity may be downgraded only after containment is confirmed and scope is determined to be limited to a single, non-critical, isolated endpoint with no evidence of lateral movement.

---

## 4. Preparation (Prerequisites)

- [ ] Offline backup strategy validated -- backups exist that are **not accessible** from the production network
- [ ] Backup restoration tested within the last quarter
- [ ] EDR configured with anti-ransomware behavioral rules (canary file monitoring, volume shadow copy protection)
- [ ] Network segmentation in place to limit lateral movement
- [ ] Pre-authorized network isolation procedures documented and tested
- [ ] Legal counsel and cyber insurance carrier contact information readily accessible
- [ ] Executive communication templates prepared
- [ ] Cryptocurrency analysis capability or retainer identified (for tracking payments if needed for investigation)
- [ ] External IR retainer under contract for surge capacity

---

## 5. Detection & Identification

### 5.1 Immediate Triage (First 5 Minutes)

**Do not wait for a complete investigation before containing.** If ransomware indicators are present, initiate containment in parallel with triage.

1. **Confirm ransomware indicators:**
   - Ransom note present? Document the ransom note text and any contact information.
   - Files encrypted with unfamiliar extensions (e.g., `.locked`, `.encrypted`, `.ryuk`, `.conti`)?
   - Volume shadow copies deleted?
     ```powershell
     # Check for shadow copy deletion events in Windows Event Log
     Get-WinEvent -FilterHashtable @{LogName='System'; Id=7036} |
       Where-Object {$_.Message -like "*Volume Shadow Copy*stopped*"}

     # Check if vssadmin was recently executed
     Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
       Where-Object {$_.Message -like "*vssadmin*delete*"}
     ```

2. **Identify the ransomware variant (do not delay containment for this):**
   - Upload the ransom note to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
   - Check the encrypted file extension against known ransomware families
   - Search the ransom note text in threat intelligence platforms
   - Record the bitcoin/cryptocurrency wallet address from the ransom note

3. **Determine the initial infection vector (begin investigation, do not delay containment):**
   - Check email logs for recent phishing deliveries to the affected user
   - Review VPN and RDP access logs for the affected system
   - Check for recently exploited vulnerabilities on internet-facing systems
   - Review EDR process tree to find the parent process of the encryption binary

### 5.2 Scope Assessment

```
# SIEM query: find all hosts exhibiting ransomware indicators (Splunk)
index=edr sourcetype=crowdstrike:events
  (event_type=FileWritten AND (file_extension=".locked" OR file_extension=".encrypted"))
  OR (CommandLine="*vssadmin*delete*shadows*")
  OR (CommandLine="*wmic*shadowcopy*delete*")
  OR (CommandLine="*bcdedit*/set*recoveryenabled*no*")
  earliest=-24h
| stats count by ComputerName, UserName, earliest(_time)
| sort -earliest(_time)

# Check for lateral movement via SMB to file shares
index=proxy OR index=firewall sourcetype=pan:traffic
  dest_port=445
  src_ip=<infected_host_ip>
  earliest=-24h
| stats count by src_ip, dest_ip, earliest(_time)
```

---

## 6. Containment

### 6.1 Containment Decision Tree

```
RANSOMWARE DETECTED
       |
       v
Is it actively encrypting files RIGHT NOW?
       |
  YES -+-> IMMEDIATE ACTIONS (all in parallel):
  |         1. Network-isolate the host via EDR
  |         2. Disable the user account
  |         3. If server: shut down the VM (do NOT gracefully shut down -- hard power off)
  |         4. Disconnect affected network shares
  |         5. Alert SOC Lead and IR Lead
  |
  NO --+-> Is there evidence of lateral movement?
       |
  YES -+-> BROAD CONTAINMENT:
  |         1. Isolate the entire affected VLAN/subnet
  |         2. Disable administrative accounts used for lateral movement
  |         3. Block SMB (445) and RDP (3389) at internal segment boundaries
  |         4. Activate incident bridge call
  |         5. Engage external IR retainer
  |
  NO --+-> TARGETED CONTAINMENT:
            1. Isolate the specific host via EDR
            2. Disable the user account
            3. Monitor adjacent systems closely for 24 hours
            4. Scan all hosts in the same subnet with IOCs
```

### 6.2 Containment Actions

**Execute these in parallel -- speed is critical.**

1. **Isolate infected hosts immediately:**
   ```
   # CrowdStrike Falcon -- contain host
   falconctl -s --network-contain=enable

   # If EDR is not responding, physically disconnect the network cable
   # or disable the switch port:
   # Cisco IOS
   configure terminal
   interface GigabitEthernet0/1
   shutdown
   exit

   # For VMs, disconnect the virtual NIC:
   # VMware PowerCLI
   Get-VM -Name <vm_name> | Get-NetworkAdapter | Set-NetworkAdapter -Connected $false -Confirm:$false
   ```

2. **Disable potentially compromised accounts:**
   ```powershell
   # Disable the affected user account
   Disable-ADAccount -Identity "infected.user"

   # If domain admin credentials may be compromised, reset krbtgt TWICE
   # (second reset after replication completes -- coordinate with AD team)
   # This invalidates all Kerberos tickets domain-wide
   Reset-KrbTgt -Server "dc01.corp.example.com"

   # Disable any service accounts used by the ransomware for lateral movement
   Disable-ADAccount -Identity "svc_backup"
   ```

3. **Protect backup infrastructure:**
   ```bash
   # Immediately verify backup system isolation
   # Disconnect backup servers from the production network if not already segmented
   # Check backup integrity -- are recent backups clean?

   # Veeam -- check recent backup job status
   Get-VBRJob | Select-Object Name, LastResult, LastState, NextRun

   # Verify offline/immutable backups exist
   # Check tape library, cloud-immutable storage, or air-gapped backup sets
   ```

4. **Block ransomware infrastructure at the perimeter:**
   ```bash
   # Block known ransomware C2 IPs and domains at the firewall
   # Block TOR exit nodes if not already blocked
   # Block known ransomware file-sharing/exfiltration sites

   # Example: Palo Alto Networks -- block C2 IP
   set address RAN-C2-203.0.113.22 ip-netmask 203.0.113.22/32
   set security policy rules BLOCK-RANSOMWARE-C2 from any to any \
     source any destination RAN-C2-203.0.113.22 action deny log-start yes
   commit
   ```

5. **Disconnect affected file shares to prevent further encryption:**
   ```powershell
   # Windows file server -- stop the Server service to disconnect all shares
   Stop-Service LanmanServer -Force

   # Or disable specific shares
   Remove-SmbShare -Name "SharedDrive" -Force
   ```

### 6.3 Evidence Preservation During Containment

Even during rapid containment, preserve evidence:

```powershell
# Capture memory before shutting down (if time permits and encryption is not active)
winpmem_mini_x64.exe \\forensics-share\evidence\%COMPUTERNAME%_memory.raw

# Take a VM snapshot before any remediation (VMware)
Get-VM -Name <vm_name> | New-Snapshot -Name "IR-Evidence-$(Get-Date -Format yyyyMMdd)" -Memory

# Capture the ransom note
Copy-Item "C:\Users\*\Desktop\DECRYPT-FILES.txt" "\\forensics-share\evidence\"

# Capture encrypted file samples (for variant identification)
Copy-Item "C:\Users\*\Documents\*.locked" "\\forensics-share\evidence\encrypted_samples\" -First 5
```

---

## 7. Eradication

### 7.1 Identify All Compromised Systems

Before eradication, build a complete picture of the attack:

1. Map every system the attacker accessed (use EDR telemetry and authentication logs)
2. Identify all accounts used by the attacker
3. Identify the ransomware binary, any dropper or loader, and any post-exploitation tools (Cobalt Strike, Mimikatz, PsExec, etc.)
4. Identify all persistence mechanisms

```powershell
# Search for ransomware binary and related tools across all endpoints
# EDR hunt query (CrowdStrike example)
event_search:
  FileName IN ("locker.exe", "encrypt.exe", "psexec.exe", "mimikatz.exe")
  OR SHA256 IN ("<known_bad_hash_1>", "<known_bad_hash_2>")
  earliest=-30d
| stats count by ComputerName, FileName, FilePath, SHA256
```

### 7.2 Remove Threat Actor Access

1. Reset passwords for all compromised accounts
2. Reset passwords for all service accounts that were accessible from compromised systems
3. Revoke all active sessions and tokens
4. Remove any backdoors, web shells, or remote access tools deployed by the attacker
5. Remove persistence mechanisms (scheduled tasks, services, registry keys, GPO modifications)
6. Patch the vulnerability used for initial access (if identified)

### 7.3 Check for Decryptors

Before committing to full recovery from backups, check if a free decryptor exists:

- **No More Ransom Project:** https://www.nomoreransom.org/
- **ID Ransomware:** https://id-ransomware.malwarehunterteam.com/
- **Emsisoft Decryptors:** https://www.emsisoft.com/en/ransomware-decryption/
- Search for `<ransomware_variant> decryptor` in security research publications

> **Do not attempt decryption on original files.** Always work on copies.

---

## 8. Recovery

### 8.1 Backup Assessment

| Question | Action |
|----------|--------|
| Are offline/immutable backups available? | Verify integrity and completeness |
| When was the last clean backup taken? | Determine acceptable data loss window |
| Were backup systems compromised? | Scan backup infrastructure for IOCs before restoring |
| How long will restoration take? | Communicate realistic timelines to leadership |
| Are backup encryption keys accessible? | Verify access independent of compromised systems |

### 8.2 Recovery Priorities

Restore systems in the following order:

1. **Identity infrastructure** -- Active Directory domain controllers, DNS, DHCP
2. **Security infrastructure** -- SIEM, EDR management, backup servers
3. **Communication systems** -- Email, messaging, telephony
4. **Critical business systems** -- As defined by the Business Continuity Plan
5. **General user endpoints** -- Reimage from golden image

### 8.3 Recovery Procedure

1. **Rebuild domain controllers from known-good backup or clean install**
   - Do not restore a DC from a potentially compromised backup
   - Reset all privileged account passwords
   - Reset krbtgt password twice (with replication interval between resets)

2. **Reimage affected endpoints:**
   ```powershell
   # Use SCCM/Intune/MDT for automated reimaging
   # Verify the golden image itself is not compromised

   # Post-reimage checklist:
   # 1. Apply all current patches
   # 2. Install and verify EDR agent check-in
   # 3. Apply current GPO settings
   # 4. Restore user data from scanned backup
   ```

3. **Restore file servers from backup:**
   ```bash
   # Verify backup integrity before restoring
   # Scan restored data with updated AV before making accessible

   # Veeam restore example
   Start-VBRRestoreSession -BackupObject <backup_object> -PointInTime "2026-02-19T02:00:00"
   ```

4. **Validate recovery:**
   - Confirm all restored systems are free of malware
   - Verify EDR is reporting clean status
   - Run vulnerability scans against restored systems
   - Test critical business functions

### 8.4 Monitored Return to Production

- Reconnect systems to the network in stages, not all at once
- Maintain heightened monitoring for 30 days post-recovery
- Set up honeypot files in previously affected shares to detect re-infection

---

## 9. Law Enforcement & Regulatory Notification

### 9.1 Law Enforcement

- **Report to:** FBI Internet Crime Complaint Center (IC3) at ic3.gov; contact local FBI field office
- **Report to:** CISA at cisa.gov/report
- **Provide:** Ransomware variant, IOCs, cryptocurrency wallet addresses, ransom note, timeline
- **Do not delay containment** for law enforcement coordination

### 9.2 Regulatory Notification

| Regulation | Notification Requirement |
|------------|------------------------|
| GDPR | 72 hours to supervisory authority if personal data affected |
| HIPAA | 60 days to HHS if PHI affected; individual notification required |
| PCI DSS | Immediate notification to acquiring bank and PCI council |
| State breach laws | Varies by jurisdiction -- consult legal counsel |
| SEC (public companies) | Material incident disclosure within 4 business days (Form 8-K) |

### 9.3 Ransom Payment Considerations

> **This playbook does not recommend paying the ransom.** The decision to pay is a business decision that must involve executive leadership, legal counsel, and the cyber insurance carrier.

Factors to consider if payment is discussed:

- Paying does not guarantee data recovery -- many victims do not receive working decryptors
- Payment funds criminal operations and incentivizes future attacks
- The threat actor may have exfiltrated data regardless -- payment does not prevent publication
- OFAC sanctions may prohibit payment to certain threat actor groups, creating legal liability
- Cyber insurance may or may not cover ransom payments depending on the policy
- If payment is considered, engage a professional ransomware negotiation firm through the insurance carrier

---

## 10. Post-Incident Activity

### 10.1 Lessons Learned

Conduct a formal post-incident review within 10 business days. Address:

1. How did the attacker gain initial access, and how can we prevent it?
2. How long was the attacker in the environment before ransomware deployment (dwell time)?
3. Were backups adequate for recovery? What was the actual RTO vs. planned RTO?
4. Were containment actions fast enough? What slowed them down?
5. Were detection capabilities adequate? What additional detections should be built?
6. Was communication effective during the incident?

### 10.2 Post-Incident Hardening

- [ ] Patch the initial access vulnerability
- [ ] Implement or improve network segmentation
- [ ] Enforce MFA on all remote access (VPN, RDP, cloud admin portals)
- [ ] Restrict lateral movement (disable SMBv1, restrict admin shares, implement LAPS)
- [ ] Harden Active Directory (tier administrative accounts, restrict DCSync rights, monitor privileged group changes)
- [ ] Implement application whitelisting on critical servers
- [ ] Deploy canary files in file shares for early ransomware detection
- [ ] Review and test backup strategy -- ensure immutable/offline copies exist
- [ ] Conduct tabletop exercise of this playbook with all stakeholders

### 10.3 IOC Distribution

- Publish IOCs to internal MISP instance
- Share with industry ISAC
- Submit samples to VirusTotal and malware analysis platforms
- Update internal detection rules with new IOCs and TTPs

---

## Appendix A: Ransomware Indicators Cheat Sheet

| Indicator | Detection Method |
|-----------|-----------------|
| Mass file renames with new extensions | FIM, EDR behavioral rules, canary files |
| `vssadmin delete shadows /all /quiet` | Sysmon Event ID 1, EDR process monitoring |
| `wmic shadowcopy delete` | Sysmon Event ID 1, EDR process monitoring |
| `bcdedit /set {default} recoveryenabled no` | Sysmon Event ID 1, EDR process monitoring |
| Ransom note files created (README.txt, DECRYPT.html) | FIM, EDR file creation rules |
| Lateral movement via PsExec, WMI, SMB | EDR, Windows Event ID 4624 Type 3, Sysmon Event ID 1 |
| Large-scale outbound data transfer before encryption | Network monitoring, DLP, proxy logs |
| Cobalt Strike beacons | EDR behavioral detection, network signature (JA3/JA3S) |
| Mimikatz / credential dumping | EDR, LSASS access monitoring (Sysmon Event ID 10) |

## Appendix B: Communication Templates

### Executive Notification (Initial)

> **Subject: SECURITY INCIDENT -- Ransomware Event -- Immediate Awareness**
>
> At [TIME] on [DATE], the Security Operations Center detected a ransomware incident affecting [NUMBER] systems in [LOCATION/BUSINESS UNIT]. Containment actions are underway. The Incident Response team has been mobilized.
>
> **Current Impact:** [Brief description of affected systems and business functions]
> **Current Status:** Containment in progress / Complete
> **Next Update:** [TIME] or sooner if material changes occur
>
> A bridge call is active at [CONFERENCE DETAILS] for real-time coordination.

### User Communication (Post-Containment)

> **Subject: IT Security Notice -- System Access Disruption**
>
> You may be experiencing difficulty accessing certain files or systems. The IT Security team is aware of the issue and is actively working to resolve it. For your protection, some systems have been temporarily taken offline.
>
> **What you need to do:**
> - Do not attempt to open files with unfamiliar extensions
> - Do not click on any ransom notes or links within them
> - Report any suspicious activity to the IT Security team immediately at [CONTACT]
> - You may be asked to reset your password -- only do so through official channels
>
> We will provide updates as the situation progresses. Thank you for your patience.
