# Playbook: Phishing Compromise Response (Credential Theft)

**Playbook ID:** PB-PHI-001
**Version:** 1.4
**Last Reviewed:** 2026-02-18
**Classification:** Internal Use
**NIST 800-61 Phase Coverage:** Detection & Analysis, Containment, Eradication, Recovery, Post-Incident

---

## 1. Objective

Define the response procedure when a user has interacted with a phishing email in a way that results in credential compromise. This includes scenarios where a user clicked a malicious link and entered credentials on a spoofed login page, opened an attachment that harvested credentials, or otherwise provided authentication material to an attacker.

This playbook assumes credentials have been **submitted or stolen**, not merely that a phishing email was received or a link was clicked without further action. For phishing emails that were reported but not interacted with, follow the standard email security triage process.

## 2. Scope & Applicability

- **Applies to:** All users, including standard users, privileged users, and service accounts if credentials are exposed.
- **Trigger conditions:**
  - User self-reports entering credentials on a suspicious page
  - Email security gateway retroactively flags a delivered URL as a credential phishing page
  - Impossible travel alert: authentication from two geographically distant locations in a short time
  - Conditional Access policy violation: sign-in from an anomalous location, device, or IP
  - Microsoft 365 / Google Workspace alert for suspicious sign-in activity
  - Help desk reports multiple users unable to access accounts (possible account takeover)
  - Detection of inbox rules automatically forwarding email to external addresses

## 3. Severity Classification

| Severity | Criteria | Response SLA |
|----------|----------|--------------|
| **P1 - Critical** | Privileged account compromised (admin, service account); confirmed attacker access to sensitive systems; BEC in progress | Immediate |
| **P2 - High** | Standard user account compromised with confirmed attacker sign-in; mailbox accessed by threat actor | 30 minutes |
| **P3 - Medium** | User submitted credentials but no confirmed attacker sign-in detected yet | 1 hour |
| **P4 - Low** | User clicked phishing link but did not enter credentials; URL now blocked | 4 hours |

---

## 4. Detection & Identification

### 4.1 Confirm the Compromise

1. **Interview the user (if they self-reported):**
   - What did the email ask you to do?
   - What URL did you visit? (Check browser history if the user cannot recall)
   - Did you enter your username and password?
   - Did the page ask for MFA codes or push approval?
   - Did you download or open any files?
   - When did this happen (approximate time)?

2. **Review the phishing email:**
   ```bash
   # Extract email headers for analysis
   # Check sender, return-path, SPF/DKIM/DMARC results, originating IP

   # Microsoft 365 -- search for the phishing email using Message Trace
   Get-MessageTrace -SenderAddress "attacker@phishing-domain.example" \
     -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

   # Identify all recipients who received the same email
   Get-MessageTrace -MessageId "<message-id-from-headers>" \
     -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
     Select-Object RecipientAddress, Status, Received
   ```

3. **Check for attacker sign-in activity:**
   ```powershell
   # Azure AD / Entra ID -- review sign-in logs for the compromised user
   Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'victim.user@corp.example.com'" |
     Select-Object CreatedDateTime, IpAddress, Location, ClientAppUsed,
       Status, ConditionalAccessStatus, DeviceDetail |
     Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize

   # Look for sign-ins from unexpected locations or IPs
   # Look for sign-ins using legacy authentication protocols (IMAP, POP, SMTP)
   # Look for sign-ins from non-corporate devices
   ```

   ```
   # Splunk query for Office 365 sign-in anomalies
   index=o365 sourcetype=o365:management:activity Operation=UserLoggedIn
     UserId="victim.user@corp.example.com"
     earliest=-7d
   | eval Country=mvindex(split(ActorIpAddress,"."),0)
   | table CreationTime, UserId, ActorIpAddress, ClientInfoString, ResultStatus
   | sort -CreationTime
   ```

4. **Check for adversary-in-the-middle (AiTM) phishing:**
   - AiTM phishing proxies can capture session tokens, bypassing MFA
   - Look for new sessions from unfamiliar IPs that did not go through the normal MFA flow
   - Check for sign-ins that reused a session token without interactive authentication

### 4.2 Assess the Blast Radius

Determine what the attacker could access and what they actually accessed:

```powershell
# Check Azure AD audit logs for actions taken by the compromised account
Get-AzureADAuditDirectoryLogs -Filter "initiatedBy/user/userPrincipalName eq 'victim.user@corp.example.com'" |
  Select-Object ActivityDateTime, ActivityDisplayName, Result |
  Sort-Object ActivityDateTime -Descending

# Check for mailbox rule modifications (common attacker action)
Get-InboxRule -Mailbox "victim.user@corp.example.com" |
  Select-Object Name, Description, Enabled, ForwardTo, ForwardAsAttachmentTo,
    RedirectTo, DeleteMessage, MoveToFolder

# Check for OAuth app consent grants (attacker may grant access to a malicious app)
Get-AzureADAuditDirectoryLogs -Filter "activityDisplayName eq 'Consent to application'" |
  Where-Object {$_.InitiatedBy.User.UserPrincipalName -eq "victim.user@corp.example.com"}

# Check for mail forwarding rules at the transport level
Get-Mailbox "victim.user@corp.example.com" |
  Select-Object ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
```

### 4.3 Check for Lateral Movement

If the attacker successfully accessed the account, check for signs of pivot:

- Did the compromised account send internal phishing emails to other employees?
- Were any SharePoint/OneDrive files accessed or downloaded in bulk?
- Were any password reset requests initiated from the compromised account?
- Did the attacker access any internal applications using SSO?
- Were there any VPN connections using the compromised credentials?

```
# Check if compromised account sent emails after the takeover
# Microsoft 365 Message Trace
Get-MessageTrace -SenderAddress "victim.user@corp.example.com" \
  -StartDate "<compromise_timestamp>" -EndDate (Get-Date) |
  Select-Object Received, RecipientAddress, Subject, Status
```

---

## 5. Containment

### 5.1 Immediate Account Actions

Execute all of the following as quickly as possible:

1. **Reset the user's password immediately:**
   ```powershell
   # Active Directory
   Set-ADAccountPassword -Identity "victim.user" \
     -NewPassword (ConvertTo-SecureString "TempP@ss$(Get-Random -Maximum 99999)!" -AsPlainText -Force) \
     -Reset

   # Azure AD / Entra ID
   Set-AzureADUserPassword -ObjectId "<user-object-id>" \
     -Password (ConvertTo-SecureString "TempP@ss$(Get-Random -Maximum 99999)!" -AsPlainText -Force) \
     -ForceChangePasswordNextLogin $true
   ```

2. **Revoke all active sessions and tokens:**
   ```powershell
   # Azure AD / Entra ID -- revoke all refresh tokens
   Revoke-AzureADUserAllRefreshToken -ObjectId "<user-object-id>"

   # This forces re-authentication on all devices and apps
   # Note: access tokens may remain valid for up to 1 hour after revocation
   ```

3. **Enforce MFA re-registration (if MFA was not enabled, enable it now):**
   ```powershell
   # If using Azure AD MFA, require re-registration
   # Reset MFA registration via Azure AD Portal or:
   Reset-MfaForUser -UserPrincipalName "victim.user@corp.example.com"

   # If the attacker registered their own MFA method, remove it
   Get-MsolUser -UserPrincipalName "victim.user@corp.example.com" |
     Get-MsolUserStrongAuthenticationPhoneAppDetail
   # Remove any unrecognized devices from the user's MFA methods
   ```

4. **Block sign-in temporarily (if P1 or active attacker access confirmed):**
   ```powershell
   # Azure AD -- block sign-in
   Set-AzureADUser -ObjectId "<user-object-id>" -AccountEnabled $false

   # On-premises AD
   Disable-ADAccount -Identity "victim.user"
   ```

### 5.2 Remove Attacker Persistence in Mailbox

Attackers commonly establish persistence in the mailbox so they retain access even after a password reset:

1. **Remove malicious inbox rules:**
   ```powershell
   # List all inbox rules
   Get-InboxRule -Mailbox "victim.user@corp.example.com" |
     Format-List Name, Description, Enabled, ForwardTo, ForwardAsAttachmentTo,
       RedirectTo, DeleteMessage, MarkAsRead, MoveToFolder

   # Remove suspicious rules (e.g., rules that forward, redirect, or delete)
   Remove-InboxRule -Mailbox "victim.user@corp.example.com" -Identity "Suspicious Rule Name" -Confirm:$false
   ```

2. **Remove mail forwarding:**
   ```powershell
   # Remove SMTP forwarding
   Set-Mailbox "victim.user@corp.example.com" \
     -ForwardingSmtpAddress $null \
     -ForwardingAddress $null \
     -DeliverToMailboxAndForward $false

   # Remove any transport rules that forward this user's mail
   Get-TransportRule | Where-Object {$_.Description -like "*victim.user*"} |
     Remove-TransportRule -Confirm:$false
   ```

3. **Remove malicious OAuth app consents:**
   ```powershell
   # List OAuth apps the user has consented to
   Get-AzureADUserOAuth2PermissionGrant -ObjectId "<user-object-id>" |
     Select-Object ClientId, Scope, ConsentType

   # Remove suspicious app consents
   Remove-AzureADOAuth2PermissionGrant -ObjectId "<grant-object-id>"

   # Disable the malicious application in the tenant
   Set-AzureADApplication -ObjectId "<app-object-id>" -AvailableToOtherTenants $false
   ```

4. **Check and remove mail delegates:**
   ```powershell
   # Check for delegated access added by the attacker
   Get-MailboxPermission "victim.user@corp.example.com" |
     Where-Object {$_.AccessRights -like "*FullAccess*" -and $_.IsInherited -eq $false}

   Get-RecipientPermission "victim.user@corp.example.com" |
     Where-Object {$_.AccessRights -like "*SendAs*"}
   ```

### 5.3 Block the Phishing Infrastructure

```bash
# Block the phishing URL/domain at the email gateway
# Block at the web proxy / DNS filter
# Report the phishing URL:
#   - Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/
#   - Microsoft: https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site
#   - PhishTank: https://www.phishtank.com/

# Remove the phishing email from all mailboxes that received it
# Microsoft 365 -- Purge using Content Search
New-ComplianceSearch -Name "Phish Purge $(Get-Date -Format yyyyMMdd)" \
  -ExchangeLocation All \
  -ContentMatchQuery "subject:'Urgent: Verify Your Account' AND from:attacker@phishing-domain.example"
Start-ComplianceSearch -Identity "Phish Purge $(Get-Date -Format yyyyMMdd)"
# After search completes:
New-ComplianceSearchAction -SearchName "Phish Purge $(Get-Date -Format yyyyMMdd)" -Purge -PurgeType HardDelete
```

---

## 6. Eradication

### 6.1 Verify All Attacker Footholds Are Removed

- [ ] Password reset completed and verified
- [ ] All sessions and tokens revoked
- [ ] MFA re-enrolled with verified contact methods
- [ ] All malicious inbox rules removed
- [ ] All mail forwarding removed
- [ ] All unauthorized OAuth app consents removed
- [ ] All unauthorized mailbox delegates removed
- [ ] Phishing email purged from all recipient mailboxes
- [ ] Phishing URL blocked at proxy, DNS, and email gateway
- [ ] If attacker accessed other systems via SSO, those sessions are also revoked

### 6.2 Scan for Secondary Payloads

If the phishing email contained an attachment or the phishing page delivered a download:

```powershell
# Check the user's Downloads folder and temp directories
Get-ChildItem "C:\Users\victim.user\Downloads" -Recurse |
  Where-Object {$_.LastWriteTime -gt "<compromise_timestamp>"}

# Check if any downloaded files were executed
# Review EDR process creation events for the user
# Sysmon Event ID 1, Security Event ID 4688
```

If malware execution is confirmed, pivot to the Malware Infection playbook (PB-MAL-001).

---

## 7. Recovery

### 7.1 Restore User Access

1. Re-enable the user account (if it was disabled)
2. Provide the user with a new temporary password via a secure channel (phone call, in-person) -- never via email
3. Walk the user through MFA setup with a verified phone number or hardware token
4. Verify the user can access all required systems

### 7.2 Verify Clean State

- Monitor sign-in logs for the user for the next 7 days
- Set up an alert for any new inbox rules created on this mailbox
- Verify no unauthorized changes were made to SharePoint, OneDrive, or other shared resources

### 7.3 Communication to Affected User

Send the following communication once remediation is complete:

> **Subject: Action Required -- Your Account Security Update**
>
> Dear [User],
>
> As discussed, your account was recently targeted by a phishing attack. We have taken the following steps to secure your account:
>
> - Your password has been reset. You will be prompted to create a new password at your next login.
> - All active sessions have been terminated. You will need to sign in again on all devices.
> - Multi-factor authentication has been re-enrolled. Please verify your MFA settings at [URL].
>
> **What you should do now:**
>
> 1. Log in and set a new, strong password (at least 16 characters, unique to this account).
> 2. Verify your MFA methods are correct (phone number, authenticator app).
> 3. Review your inbox rules: Settings > Mail > Rules. Delete any rules you do not recognize.
> 4. Review your email forwarding settings: Settings > Mail > Forwarding. Disable any forwarding you did not set up.
> 5. Check your Sent Items and Deleted Items for any emails you did not send.
> 6. If you used the same password on any personal accounts, change those passwords immediately.
>
> If you notice any suspicious activity, contact the IT Security team immediately at [CONTACT].
>
> Thank you for reporting this promptly. Your quick action helped us contain the incident.

---

## 8. Post-Incident Activity

### 8.1 Determine Additional Victims

```powershell
# Check if other users who received the same phishing email also clicked or submitted credentials
# Review email gateway logs for click tracking on the phishing URL
# Check Azure AD sign-in logs for the phishing source IP across all users

# Splunk query: find all users who authenticated from the known attacker IP
index=azure sourcetype=azure:aad:signin
  IpAddress="203.0.113.50"
  earliest=-7d
| stats count by UserPrincipalName, AppDisplayName, ResultType
| sort -count
```

If additional compromised accounts are found, repeat this playbook for each one.

### 8.2 Detection Improvements

- Add the phishing domain and sender address to email gateway block lists
- Create a SIEM alert for inbox rule creation with forwarding to external addresses:
  ```
  # Splunk -- detect suspicious inbox rule creation
  index=o365 sourcetype=o365:management:activity
    Operation="New-InboxRule"
    (Parameters{}.Value="*@*" AND
      (Parameters{}.Name="ForwardTo" OR Parameters{}.Name="ForwardAsAttachmentTo" OR
       Parameters{}.Name="RedirectTo"))
  | table CreationTime, UserId, Parameters{}.Name, Parameters{}.Value
  ```
- Review and tighten Conditional Access policies (block legacy auth, require managed devices, restrict by location)
- Consider deploying a phishing-resistant MFA method (FIDO2 keys, Windows Hello) for high-risk users

### 8.3 User Awareness

- Send the affected user targeted phishing awareness training
- If multiple users fell for the same campaign, send an organization-wide awareness notice
- Add the phishing email to the next phishing simulation exercise as a template
- Track repeat offenders for additional training or access restrictions

### 8.4 Documentation

- Complete the incident report using the standard template
- Log all IOCs (phishing URL, sender domain, source IPs) in the internal threat intelligence platform
- Update the incident ticket with final status and timeline

---

## Appendix A: Common Attacker Actions After Credential Theft

| Action | Where to Look | Why They Do It |
|--------|--------------|----------------|
| Set inbox forwarding rules | Inbox Rules, Transport Rules, Mailbox forwarding settings | Maintain access to emails even after password reset |
| Grant OAuth app consent | Azure AD app registrations and consents | Persistent API access that survives password changes |
| Send internal phishing from the compromised account | Sent Items, Message Trace | Leverage trust to compromise more accounts |
| Access SharePoint / OneDrive | Unified Audit Log, SharePoint access logs | Steal sensitive documents |
| Register new MFA methods | Azure AD authentication methods | Maintain access after password reset |
| Create mail delegates | Mailbox permissions | Read email through another account |
| Exfiltrate the Global Address List | Azure AD sign-in and audit logs | Harvest email addresses for future phishing |
| Attempt password resets for other accounts | Self-service password reset logs | Pivot to additional accounts |

## Appendix B: Phishing Analysis Quick Reference

```
# Header analysis fields to check:
# - From / Return-Path mismatch
# - SPF: check Authentication-Results header for "spf=fail"
# - DKIM: check for "dkim=fail" or missing DKIM signature
# - DMARC: check for "dmarc=fail"
# - X-Originating-IP: sender's real IP
# - Received: chain of mail servers (read bottom to top)

# URL analysis:
# - Defang the URL before sharing: hxxps://phishing-domain[.]example/login
# - Check URL reputation: VirusTotal, urlscan.io, PhishTank
# - Check domain registration: whois, DomainTools
# - Capture a screenshot: urlscan.io

# Attachment analysis:
# - Get file hash before opening
# - Submit to sandbox: any.run, Hybrid Analysis, Joe Sandbox
# - Check hash on VirusTotal
# - Analyze in isolated VM if manual analysis is needed
```
