# Common Phishing Indicators -- Reference Guide

A categorised reference of red flags commonly observed in phishing emails. Each category includes specific indicators, what to look for, and real-world examples of how attackers use them.

---

## 1. Header Anomalies

### 1.1 From / Return-Path Mismatch

The display name and From address suggest one organisation, but the Return-Path (envelope sender) points to a completely different domain.

**Example:**
```
From: "Chase Bank Security" <alerts@chase.com>
Return-Path: <bounce-8843@mail-svr.example.ru>
```

The recipient sees "Chase Bank Security" in their mail client, but the actual return path is a server in an unrelated domain.

### 1.2 Reply-To Redirect

The Reply-To header points to a different address than the From header, so that replies go to the attacker instead of the impersonated sender.

**Example:**
```
From: ceo@company.com
Reply-To: ceo.company.payments@gmail.com
```

This is extremely common in Business Email Compromise (BEC). The attacker hopes the recipient will hit Reply without noticing the address change.

### 1.3 SPF / DKIM / DMARC Failures

Authentication headers indicate the sending server was not authorised to send on behalf of the claimed domain.

**Example:**
```
Authentication-Results: mx.recipient.com;
    spf=fail (sender IP not in SPF record) smtp.mailfrom=attacker.example.net;
    dkim=fail (no valid signature);
    dmarc=fail (p=reject)
```

A triple-fail on a message claiming to be from a major bank or tech company is a near-certain indicator of spoofing.

### 1.4 Suspicious X-Mailer / User-Agent

Legitimate corporate email is typically sent via well-known MTAs (Exchange, Google Workspace). Seeing mass-mailer tools suggests a phishing campaign.

**Common phishing X-Mailer values:**
- `PHPMailer 5.x / 6.x`
- `Microsoft CDO for Windows 2000` (outdated library abused by phishing kits)
- `YMailNor498` or other random strings
- Custom Python or Perl scripts

### 1.5 Message-ID Domain Mismatch

The domain portion of the Message-ID should normally match the sending domain. A mismatch is a strong spoofing indicator.

**Example:**
```
From: support@microsoft.com
Message-ID: <a93b7f21.44e2@cheapvps.example.net>
```

---

## 2. Content and Social Engineering Tactics

### 2.1 Urgency and Deadline Pressure

Attackers create artificial time pressure to prevent the victim from thinking critically.

**Common phrases:**
- "Your account will be suspended within 24 hours"
- "Immediate action required"
- "Failure to respond will result in permanent data loss"
- "Verify your identity within 4 hours or access will be revoked"

### 2.2 Authority Impersonation

The message pretends to come from a trusted authority figure or department.

**Common impersonated entities:**
- IT Helpdesk / IT Security
- HR Department (benefits enrollment, policy updates)
- CEO or CFO (wire transfer requests)
- Banks and financial institutions
- Government agencies (IRS, tax authorities)
- Shipping companies (FedEx, UPS, DHL)
- Cloud services (Microsoft 365, Google, Dropbox)

### 2.3 Fear and Consequences

The email threatens negative consequences to motivate immediate action.

**Examples:**
- "Unusual sign-in detected from Moscow, Russia"
- "Your payment was declined"
- "Legal action will be taken if you do not respond"
- "Your tax return has been flagged for review"

### 2.4 Reward and Curiosity

Some campaigns use positive incentives instead of threats.

**Examples:**
- "You have received a $500 gift card"
- "Your refund of $2,847.00 is ready"
- "You have been selected for a salary increase"
- "Shared document: Q4 Bonus List.xlsx"

### 2.5 Generic Greetings

Phishing emails sent in bulk cannot personalise the greeting.

**Indicators:**
- "Dear Valued Customer"
- "Dear Account Holder"
- "Dear Sir/Madam"
- "Hello User"

Legitimate emails from services you have an account with will typically use your name.

### 2.6 Poor Grammar and Formatting

While sophisticated campaigns are now grammatically correct (especially with AI-generated text), many phishing emails still contain:
- Mixed fonts and sizes within the body
- Unusual capitalisation ("CLICK HERE to Verify YOUR Account")
- Spacing errors and inconsistent formatting
- Awkward phrasing ("We have been notified that your account has been the compromised")

---

## 3. URL Indicators

### 3.1 Domain Mismatch

The most common URL trick: the link points to a domain that is not owned by the impersonated organisation.

**Example:**
- Display text: `https://www.paypal.com/security/verify`
- Actual href: `https://paypal-security-verify.example.xyz/login.php`

### 3.2 Look-Alike (Typosquatting) Domains

Domains that visually resemble the target but differ by one or more characters.

**Examples:**
| Legitimate | Look-alike |
|---|---|
| microsoft.com | micros0ft.com, microsoft-support.com, microsofft.com |
| paypal.com | paypa1.com, paypal-login.com, paypai.com |
| amazon.com | arnazon.com (rn looks like m), amazom.com |
| google.com | g00gle.com, gooogle.com |

### 3.3 Homoglyph / IDN Attacks

Using Unicode characters that visually resemble ASCII letters. For example, the Cyrillic "a" (U+0430) looks identical to the Latin "a" (U+0061) in many fonts.

**Example:**
- `https://аpple.com` -- the first "a" is Cyrillic, not Latin.

Modern browsers display these as `xn--pple-43d.com` (Punycode) to mitigate this, but email clients may not.

### 3.4 Raw IP Addresses in URLs

Legitimate services almost never use raw IP addresses in their URLs.

**Example:**
- `http://198.51.100.77/login/microsoft365`

### 3.5 URL Shorteners

Shortened URLs hide the true destination.

**Common shortening services used in phishing:**
- bit.ly
- tinyurl.com
- t.co
- is.gd
- rb.gy
- shorturl.at

Always expand shortened URLs before clicking. Use `curl -sI <url>` and check the `Location` header.

### 3.6 Subdomain Abuse

Placing the trusted brand name as a subdomain of an attacker-controlled domain.

**Example:**
- `https://login.microsoft.com.attacker-domain.example.net/auth`

The victim sees "login.microsoft.com" and stops reading, missing that the actual domain is `attacker-domain.example.net`.

### 3.7 Data URIs and JavaScript in Links

Some phishing emails embed the entire phishing page as a `data:` URI or use `javascript:` schemes.

**Example:**
- `data:text/html;base64,PGh0bWw+...` -- decodes to an inline HTML phishing page.

### 3.8 Open Redirects

Abusing legitimate open redirect vulnerabilities on trusted domains to bounce through to a phishing page.

**Example:**
- `https://www.google.com/url?q=https://phishing-site.example.net/steal`

The URL starts with google.com, which may bypass security filters and build user trust.

---

## 4. Attachment Indicators

### 4.1 Macro-Enabled Office Documents

Extensions `.docm`, `.xlsm`, `.pptm` contain VBA macros. Many phishing campaigns instruct the user to "Enable Content" or "Enable Editing" to trigger the macro.

**Red flag phrases in the document body:**
- "This document was created in an earlier version of Microsoft Office. Please enable macros to view the content."
- "Protected View -- Click Enable Editing to access this document."

### 4.2 Password-Protected Archives

Attackers use password-protected .zip or .rar files to bypass email gateway scanning. The password is conveniently provided in the email body.

**Example email body:**
> Please find attached the invoice. The archive password is: **Invoice2024**

### 4.3 Double Extensions

Using a double extension to disguise an executable as a document.

**Examples:**
- `invoice.pdf.exe`
- `report.docx.scr`
- `photo.jpg.js`

Windows hides known extensions by default, so the user sees only `invoice.pdf`.

### 4.4 ISO and IMG Disk Images

Since Windows 10, double-clicking an `.iso` or `.img` file auto-mounts it as a virtual drive. Attackers use this to deliver executables and LNK files that bypass Mark-of-the-Web protections.

### 4.5 HTML Attachments

An attached `.html` file that opens a local phishing page in the browser. This technique bypasses URL-based email filtering because there is no external URL to scan.

**Common pattern:** The HTML file contains obfuscated JavaScript that renders a fake Microsoft 365 login page and sends credentials to an attacker-controlled server via an AJAX request.

### 4.6 OneNote Attachments

A newer technique (prevalent since 2023): `.one` files containing embedded scripts or executables behind fake "Double click to view" buttons.

---

## 5. Sender Behavioural Indicators

### 5.1 First-Time Sender

The sender has never emailed the recipient or the organisation before. Many email security tools flag this with a banner such as "[External] This is the first time you have received email from this sender."

### 5.2 Display Name Spoofing

The display name impersonates a known internal contact, but the email address is external.

**Example:**
```
From: "John Smith (CEO)" <john.smith8827@freemail.example.com>
```

### 5.3 Compromised Account

The email comes from a legitimate, known contact whose account has been compromised. This is harder to detect because authentication checks (SPF, DKIM) will pass.

**Indicators of compromised-account phishing:**
- The email content is uncharacteristic of the sender.
- The email was sent outside the sender's normal working hours.
- The email contains a link or attachment that is unusual for the sender's typical communications.
- Other recipients report similar unexpected messages from the same sender.

### 5.4 Newly Registered Domain

The sender domain was registered very recently (within the last 30 days). WHOIS lookups can reveal the registration date.

**How to check:**
```bash
whois suspiciousdomain.com | grep -i "creation date"
```

---

## 6. Infrastructure Indicators

### 6.1 Free Hosting and Dynamic DNS

Phishing pages hosted on free services that require no identity verification.

**Commonly abused platforms:**
- Cloudflare Pages / Workers
- GitHub Pages
- Firebase Hosting
- Netlify
- Weebly / Wix (free tier)
- Dynamic DNS providers (duckdns.org, no-ip.com, dynu.com)

### 6.2 Compromised Legitimate Websites

Attackers frequently upload phishing kits to hacked WordPress sites, placing the phishing page deep in the directory structure.

**Example:**
- `https://legitimate-bakery.com/wp-content/plugins/cache/office365/login.php`

The domain has a good reputation, which helps the URL bypass security filters.

### 6.3 Bulletproof Hosting

Some phishing campaigns use hosting providers that are known for ignoring abuse complaints. These providers are often located in jurisdictions with limited law enforcement cooperation.

### 6.4 Certificate Abuse

The presence of HTTPS (the lock icon) does NOT mean a site is safe. Free certificate authorities like Let's Encrypt issue certificates to anyone, including phishing sites. Check the certificate details -- phishing sites typically use Domain Validation (DV) certificates with no organisation information.

---

## 7. Quick Reference Checklist

Use this checklist during analysis to systematically evaluate an email:

```
HEADER CHECKS
[ ] From domain matches Return-Path domain
[ ] Reply-To matches From domain
[ ] SPF passes
[ ] DKIM passes
[ ] DMARC passes
[ ] Message-ID domain matches From domain
[ ] X-Mailer is a legitimate mail client/server
[ ] Originating IP belongs to the purported sender's organisation

CONTENT CHECKS
[ ] No artificial urgency or threatening language
[ ] No request for credentials or sensitive information
[ ] Personalised greeting (not generic)
[ ] Consistent formatting and grammar
[ ] No "enable macros" or "enable content" instructions

URL CHECKS
[ ] All URL domains match the purported sender
[ ] No look-alike or typosquatting domains
[ ] No raw IP addresses in URLs
[ ] No URL shorteners
[ ] No subdomain abuse
[ ] No open-redirect abuse

ATTACHMENT CHECKS
[ ] No macro-enabled Office files (.docm, .xlsm, .pptm)
[ ] No executable or script files (.exe, .js, .ps1, etc.)
[ ] No password-protected archives
[ ] No double extensions
[ ] No ISO/IMG disk images
[ ] File hash is clean on VirusTotal
```

If any box remains unchecked, the email warrants deeper investigation.
