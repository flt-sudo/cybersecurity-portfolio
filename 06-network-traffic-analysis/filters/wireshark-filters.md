# Wireshark Display Filter Reference

A categorized reference of Wireshark display filters organized by threat hunting
use case. Each filter includes an explanation of what it detects, why it matters,
and when to use it during an investigation.

All filters are display filters (applied after capture) and use Wireshark's
display filter syntax, not BPF/capture filter syntax.

---

## Table of Contents

1. [Reconnaissance Detection](#1-reconnaissance-detection)
2. [Malware and C2 Traffic](#2-malware-and-c2-traffic)
3. [Data Exfiltration](#3-data-exfiltration)
4. [Credential Theft](#4-credential-theft)
5. [Web Application Attacks](#5-web-application-attacks)
6. [Lateral Movement](#6-lateral-movement)
7. [General Utility Filters](#7-general-utility-filters)

---

## 1. Reconnaissance Detection

### Port Scans -- SYN Scan (Half-Open)

```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024
```

**What it catches:** TCP SYN packets with small window sizes, characteristic of
scanning tools like Nmap that use half-open scanning. Legitimate applications
typically advertise larger TCP windows.

### Port Scans -- Connect Scan

```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size > 1024
```

**What it catches:** Full TCP connect scans where the scanner completes the
three-way handshake. Look for a single source IP generating many of these to
different destination ports.

### Port Scans -- Many RST Responses (Closed Ports)

```
tcp.flags.reset == 1 && tcp.flags.ack == 1 && tcp.seq == 0
```

**What it catches:** RST/ACK responses to connection attempts on closed ports.
A burst of these from one target suggests that target is being port-scanned.

### Null Scan

```
tcp.flags == 0x000
```

**What it catches:** TCP packets with no flags set. This is invalid in normal
TCP operation and is used by Nmap's null scan (-sN) to probe firewalls.

### XMAS Scan

```
tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1
```

**What it catches:** TCP packets with FIN, PSH, and URG flags set simultaneously.
Used by Nmap's XMAS scan (-sX) for firewall evasion.

### ICMP Sweep (Ping Scan)

```
icmp.type == 8 || icmp.type == 13 || icmp.type == 17
```

**What it catches:** ICMP Echo Request (type 8), Timestamp Request (type 13),
and Address Mask Request (type 17). Attackers use these to discover live hosts.
Filter by a single source to find host sweeps.

### ICMP Sweep -- Single Source to Many Destinations

```
icmp.type == 8 && ip.src == 203.0.113.50
```

**What it catches:** Ping sweep from a specific suspicious source. Replace the
IP with the source under investigation.

### OS Fingerprinting Indicators

```
tcp.options.mss_val < 536 || (tcp.flags.syn == 1 && tcp.options.wscale_val == 0)
```

**What it catches:** Unusual TCP options that may indicate OS fingerprinting
tools like Nmap or p0f. Legitimate stacks rarely use very small MSS values.

### ARP Scanning

```
arp.opcode == 1
```

**What it catches:** ARP requests. A high volume from a single MAC address
indicates ARP-based host discovery on the local network segment.

---

## 2. Malware and C2 Traffic

### Beaconing -- Regular Interval Connections to a Single Host

```
ip.dst == 198.51.100.99 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**What it catches:** New TCP connections to a suspected C2 server. Apply this
filter, then use Statistics > IO Graph to visualize connection timing and
identify regular intervals.

### DNS Tunneling -- Long DNS Queries

```
dns.qry.name.len > 50
```

**What it catches:** DNS queries with names longer than 50 characters. Legitimate
DNS queries are typically shorter. Tunneling tools encode data in subdomain
labels, producing unusually long query names.

### DNS Tunneling -- TXT Record Queries

```
dns.qry.type == 16
```

**What it catches:** DNS TXT record queries. While TXT records have legitimate
uses (SPF, DKIM), a high volume of TXT queries to unusual domains can indicate
DNS tunneling (iodine, dnscat2).

### DNS Tunneling -- High Volume to Single Domain

```
dns.qry.name contains "suspicious-domain.com"
```

**What it catches:** All DNS queries to a specific domain under investigation.
Replace with the actual domain name.

### Unusual DNS -- Non-Standard DNS Port

```
dns && !(udp.port == 53) && !(tcp.port == 53)
```

**What it catches:** DNS traffic on non-standard ports. Some malware uses
alternate ports for DNS to bypass security controls.

### HTTP Beaconing -- Regular POST Requests

```
http.request.method == "POST" && ip.dst == 198.51.100.99
```

**What it catches:** HTTP POST requests to a suspected C2 server. C2 frameworks
often use POST to exfiltrate data or receive commands.

### Suspicious User-Agent Strings

```
http.user_agent contains "python" || http.user_agent contains "curl" || http.user_agent contains "wget" || http.user_agent contains "PowerShell"
```

**What it catches:** HTTP requests with user-agent strings associated with
scripting tools rather than browsers. Malware and attack tools often use
default library user-agents.

### Self-Signed or Unusual TLS Certificates

```
tls.handshake.type == 11 && tls.handshake.certificate
```

**What it catches:** TLS certificate exchanges. Combine with "Export Objects"
to extract and inspect certificates. C2 servers often use self-signed certs.

### TLS with Unusual SNI

```
tls.handshake.extensions_server_name contains "example"
```

**What it catches:** TLS Client Hello messages with a specific Server Name
Indication. Useful for identifying connections to suspicious domains even
when the traffic is encrypted.

### IRC-Based C2

```
tcp.port == 6667 || tcp.port == 6697 || irc
```

**What it catches:** IRC traffic which is uncommon in corporate environments.
Older botnets and some current malware families still use IRC for C2.

### Suspicious ICMP -- Possible ICMP Tunnel

```
icmp && data.len > 48
```

**What it catches:** ICMP packets with large data payloads. Normal ICMP Echo
uses small payloads (32-64 bytes). Large ICMP payloads may indicate an ICMP
tunnel (ptunnel, icmpsh).

---

## 3. Data Exfiltration

### Large Outbound Transfers

```
ip.src == 10.0.0.0/8 && tcp.len > 1400 && frame.len > 1400
```

**What it catches:** Large outbound packets from internal hosts. Combine with
Statistics > Conversations to identify flows with high byte counts leaving
the network.

### FTP Data Transfers

```
ftp-data
```

**What it catches:** FTP data channel traffic. FTP is cleartext and should not
be used in most environments. Outbound FTP data transfers warrant investigation.

### Outbound SMB (Should Not Leave the Network)

```
tcp.dstport == 445 && !(ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16)
```

**What it catches:** SMB traffic directed at non-RFC1918 addresses. SMB should
never traverse the internet. This can indicate misconfiguration or exfiltration.

### DNS Exfiltration -- Large Responses

```
dns.resp.len > 512
```

**What it catches:** DNS responses larger than the traditional 512-byte UDP
limit. Very large DNS responses can indicate data being returned through DNS
tunneling.

### Outbound Traffic on Unusual Ports

```
ip.src == 10.0.0.0/8 && tcp.dstport > 10000 && !(tcp.dstport == 443 || tcp.dstport == 8443 || tcp.dstport == 8080)
```

**What it catches:** Internal hosts connecting outbound on high ports that are
not common services. Attackers may use high ports to evade basic firewall rules.

### HTTP File Uploads

```
http.request.method == "POST" && http.content_type contains "multipart"
```

**What it catches:** HTTP multipart file uploads. Useful for detecting data
being uploaded to cloud storage, paste sites, or attacker infrastructure.

---

## 4. Credential Theft

### Cleartext Credentials -- HTTP Basic Auth

```
http.authorization contains "Basic"
```

**What it catches:** HTTP Basic Authentication headers which transmit
base64-encoded (not encrypted) credentials. These can be trivially decoded.

### Cleartext Credentials -- FTP Login

```
ftp.request.command == "USER" || ftp.request.command == "PASS"
```

**What it catches:** FTP username and password commands sent in cleartext.

### Cleartext Credentials -- Telnet

```
telnet
```

**What it catches:** Any Telnet traffic. Telnet transmits everything including
credentials in cleartext and should not be in use.

### Cleartext Credentials -- SMTP Auth

```
smtp.req.command == "AUTH"
```

**What it catches:** SMTP authentication attempts, which may contain cleartext
or base64-encoded credentials if not wrapped in TLS.

### NTLM Authentication

```
ntlmssp
```

**What it catches:** NTLM Security Support Provider messages. Useful for
identifying NTLM authentication attempts, relay attacks, and hash capture.

### NTLM -- Challenge-Response Capture

```
ntlmssp.messagetype == 0x00000002 || ntlmssp.messagetype == 0x00000003
```

**What it catches:** NTLM Challenge (Type 2) and Authenticate (Type 3) messages.
These contain the challenge-response pairs that can be used for offline cracking.

### Kerberos Traffic

```
kerberos
```

**What it catches:** All Kerberos authentication traffic. Useful for
investigating Kerberoasting, Golden/Silver Ticket attacks, and authentication
anomalies.

### Kerberos -- TGS Requests (Kerberoasting Indicator)

```
kerberos.msg_type == 13
```

**What it catches:** Kerberos TGS-REQ messages (msg-type 13). A burst of TGS
requests for different service principals from a single host may indicate
Kerberoasting (requesting service tickets to crack offline).

### Kerberos -- AS-REP Without Pre-Auth (AS-REP Roasting)

```
kerberos.msg_type == 11 && kerberos.error_code == 0
```

**What it catches:** Successful AS-REP responses. When correlated with accounts
that have pre-authentication disabled, this can indicate AS-REP Roasting.

### LDAP Cleartext Bind

```
ldap.bindRequest && !(tls)
```

**What it catches:** LDAP bind requests not wrapped in TLS. Cleartext LDAP
binds expose Active Directory credentials on the wire.

---

## 5. Web Application Attacks

### SQL Injection Attempts in HTTP

```
http.request.uri contains "UNION" || http.request.uri contains "SELECT" || http.request.uri contains "DROP" || http.request.uri contains "INSERT" || http.request.uri contains "1=1" || http.request.uri contains "OR+1" || http.request.uri contains "%27"
```

**What it catches:** Common SQL injection patterns in URL parameters. The %27
is a URL-encoded single quote. Note: sophisticated SQLi may use encoding to
bypass this.

### SQL Injection -- In POST Body

```
http.request.method == "POST" && (http.file_data contains "UNION" || http.file_data contains "SELECT" || http.file_data contains "1=1")
```

**What it catches:** SQL injection patterns in HTTP POST request bodies.

### Cross-Site Scripting (XSS) Attempts

```
http.request.uri contains "<script" || http.request.uri contains "javascript:" || http.request.uri contains "%3Cscript" || http.request.uri contains "onerror=" || http.request.uri contains "onload="
```

**What it catches:** Common XSS payload patterns in URL parameters. %3C is a
URL-encoded less-than sign.

### Directory Traversal

```
http.request.uri contains ".." || http.request.uri contains "%2e%2e"
```

**What it catches:** Path traversal attempts trying to access files outside the
web root using ../ sequences.

### Web Shell Access Patterns

```
http.request.uri contains "cmd=" || http.request.uri contains "exec=" || http.request.uri contains "command=" || http.request.uri contains "shell"
```

**What it catches:** URL parameters commonly used by web shells for command
execution. Combines well with filtering for suspicious POST requests.

### HTTP Response Codes -- Server Errors (Possible Attack Probing)

```
http.response.code >= 500
```

**What it catches:** HTTP 5xx server errors that may indicate successful
injection attacks causing application errors, or active exploitation attempts.

### HTTP Response Codes -- 401/403 Brute Force Indicators

```
http.response.code == 401 || http.response.code == 403
```

**What it catches:** Authentication failures and access denied responses. A
high volume from one source suggests brute force or credential stuffing.

---

## 6. Lateral Movement

### SMB/CIFS Traffic

```
smb || smb2
```

**What it catches:** All SMB protocol traffic. Essential for investigating
file shares, remote execution, and lateral movement via SMB.

### SMB -- Named Pipe Access (PsExec, Remote Service)

```
smb2.filename == "svcctl" || smb2.filename == "PSEXESVC" || smb2.filename contains "PIPE"
```

**What it catches:** SMB named pipe access associated with PsExec and remote
service control. PsExec is commonly used for lateral movement.

### SMB -- Admin Share Access

```
smb2.tree contains "ADMIN$" || smb2.tree contains "C$" || smb2.tree contains "IPC$"
```

**What it catches:** Access to administrative shares (ADMIN$, C$) and IPC$.
These are used by PsExec, WMI, and other remote administration and attack tools.

### RDP Traffic

```
tcp.port == 3389 || rdp
```

**What it catches:** Remote Desktop Protocol traffic. Monitor for RDP from
unexpected sources, to unexpected destinations, or at unusual times.

### RDP -- From Non-Jump-Server Source

```
tcp.dstport == 3389 && !(ip.src == 10.0.0.10)
```

**What it catches:** RDP connections from hosts other than the authorized jump
server (replace 10.0.0.10 with your actual jump server IP). Unauthorized RDP
sources may indicate lateral movement.

### WMI Remote Execution

```
tcp.dstport == 135 || dce_rpc
```

**What it catches:** DCOM/RPC traffic on port 135, used by WMI for remote
execution. WMI is a common living-off-the-land technique for lateral movement.

### WinRM / PowerShell Remoting

```
tcp.dstport == 5985 || tcp.dstport == 5986
```

**What it catches:** Windows Remote Management traffic (HTTP on 5985, HTTPS on
5986). Used by PowerShell Remoting and increasingly by attackers for fileless
lateral movement.

### SSH -- Unexpected Internal Connections

```
tcp.dstport == 22 && ip.src == 10.0.0.0/8 && ip.dst == 10.0.0.0/8
```

**What it catches:** Internal SSH connections. While SSH is legitimate, unexpected
internal SSH connections between workstations (not servers) may indicate lateral
movement.

### Pass-the-Hash / Overpass-the-Hash Indicators

```
ntlmssp.auth.username && ntlmssp.auth.domain
```

**What it catches:** NTLM authentication with domain context. Look for the same
account authenticating from multiple workstations in a short time frame, which
may indicate stolen credential reuse.

---

## 7. General Utility Filters

### Exclude Noise -- ARP, STP, CDP

```
!(arp || stp || cdp || lldp)
```

**What it catches:** Removes common layer-2 broadcast/multicast noise to focus
on relevant IP traffic.

### Show Only TCP Errors

```
tcp.analysis.flags
```

**What it catches:** TCP analysis flags including retransmissions, duplicate
ACKs, zero windows, and out-of-order segments. Useful for performance analysis
and detecting network issues.

### Conversations Between Two Hosts

```
(ip.src == 10.0.0.50 && ip.dst == 198.51.100.99) || (ip.src == 198.51.100.99 && ip.dst == 10.0.0.50)
```

**What it catches:** All traffic between two specific IP addresses in both
directions.

### Time-Based Filter (Specific Window)

```
frame.time >= "2026-03-06 14:00:00" && frame.time <= "2026-03-06 15:00:00"
```

**What it catches:** Packets within a specific time window. Essential for
correlating network evidence with other log sources.

### Packets Containing a Specific String

```
frame contains "password" || frame contains "admin"
```

**What it catches:** Any packet containing the specified string in any protocol
layer. Useful for keyword searches across all traffic.

### GeoIP -- Traffic to Specific Countries

```
ip.geoip.dst_country == "RU" || ip.geoip.dst_country == "CN" || ip.geoip.dst_country == "KP"
```

**What it catches:** Traffic destined for specific countries. Requires Wireshark
GeoIP database configuration. Useful for identifying connections to high-risk
geographies.
