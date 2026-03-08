# Traffic Analysis Write-Up 01: C2 Beaconing Detection

## Classification

| Field | Value |
|-------|-------|
| **Date** | 2026-03-05 |
| **Analyst** | SOC Tier 2 |
| **Severity** | High |
| **Status** | Confirmed - Escalated to IR |
| **MITRE ATT&CK** | T1071.001 (Web Protocols), T1573 (Encrypted Channel), T1041 (Exfiltration Over C2 Channel) |

---

## 1. Scenario

At 14:22 UTC on 2026-03-05, the SIEM generated an alert based on a custom
detection rule: **"Periodic Outbound HTTPS -- Fixed Interval"**. The rule
triggers when a single internal host makes outbound TCP/443 connections to the
same external IP at intervals within a 15% jitter tolerance over a sliding
60-minute window, with a minimum of 10 connections.

The alert identified host **10.0.0.75** (workstation WS-MARKETING-12, assigned
to a marketing department employee) making outbound HTTPS connections to
**198.51.100.99** approximately every 60 seconds. The destination IP was not
categorized by the web proxy and did not match any known CDN, SaaS provider, or
business-related infrastructure.

## 2. Investigation

### Step 1: Isolate the Traffic Flow

Applied a Wireshark display filter to isolate the conversation between the
suspected compromised host and the external destination:

```
(ip.src == 10.0.0.75 && ip.dst == 198.51.100.99) || (ip.src == 198.51.100.99 && ip.dst == 10.0.0.75)
```

**Observation:** Over the 2-hour pcap window (13:00-15:00 UTC), there were
**127 TCP connections** between these two hosts, all on port 443. The
connections followed a consistent pattern -- new TCP SYN approximately every
58-62 seconds.

### Step 2: Verify Beaconing Timing

Filtered for SYN packets only to measure connection intervals:

```
ip.src == 10.0.0.75 && ip.dst == 198.51.100.99 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Exported the packet timestamps and calculated inter-arrival times:

| Connection # | Timestamp (UTC) | Interval (seconds) |
|:------------:|:---------------:|:-------------------:|
| 1 | 13:01:12.443 | -- |
| 2 | 13:02:11.891 | 59.4 |
| 3 | 13:03:13.217 | 61.3 |
| 4 | 13:04:12.004 | 58.8 |
| 5 | 13:05:11.556 | 59.6 |
| 6 | 13:06:12.887 | 61.3 |
| ... | ... | ... |
| 120 | 14:59:58.102 | 60.1 |

**Mean interval:** 60.2 seconds
**Standard deviation:** 1.8 seconds
**Jitter:** 3.0% (well within the 15% threshold)

**Assessment:** This timing pattern is not consistent with human-initiated
browsing behavior. The regularity strongly suggests automated callback -- a
hallmark of C2 beaconing.

### Step 3: DNS Resolution Analysis

Checked what domain name resolved to 198.51.100.99:

```
dns.a == 198.51.100.99
```

**Finding:** The DNS A record response showed that **update-cdn-assets.example.net**
resolved to 198.51.100.99. The query originated from 10.0.0.75 at 13:00:58 UTC,
approximately 14 seconds before the first connection.

Investigated the domain further:

```
dns.qry.name contains "update-cdn-assets"
```

**Observations:**
- Domain was only queried by 10.0.0.75 -- no other internal host queried it
- The domain uses a naming convention designed to look legitimate ("update",
  "cdn", "assets") but is not associated with any known CDN provider
- WHOIS lookup (performed outside Wireshark) showed the domain was registered
  14 days prior through a privacy-protected registrar

### Step 4: TLS Certificate Inspection

Examined the TLS handshake for certificate details:

```
ip.dst == 198.51.100.99 && tls.handshake.type == 11
```

Exported the server certificate from the TLS handshake and inspected it:

| Certificate Field | Value |
|-------------------|-------|
| **Subject CN** | update-cdn-assets.example.net |
| **Issuer** | update-cdn-assets.example.net (self-signed) |
| **Valid From** | 2026-02-19 |
| **Valid To** | 2027-02-19 |
| **Serial** | Random / non-sequential |
| **Key Size** | RSA 2048 |

**Assessment:** The certificate is **self-signed**, not issued by a trusted CA.
Legitimate CDN services use certificates from well-known certificate
authorities. Self-signed certificates on internet-facing servers used for
HTTPS are a strong indicator of attacker infrastructure.

### Step 5: Payload Size Analysis

Analyzed the size of data transferred in each beacon cycle using the TCP
payload lengths:

```
ip.src == 10.0.0.75 && ip.dst == 198.51.100.99 && tcp.len > 0
```

**Outbound (client to server) payload sizes:**
- Minimum: 84 bytes
- Maximum: 142 bytes
- Mean: 98 bytes
- Standard deviation: 12 bytes

**Inbound (server to client) payload sizes:**
- Minimum: 62 bytes
- Maximum: 4,218 bytes
- Mean: 189 bytes
- Most responses: 62-78 bytes (likely "sleep" / "no task" responses)
- Occasional larger responses: 2,000-4,200 bytes (likely commands or payloads)

**Assessment:** The small, consistent outbound payloads are characteristic of
C2 check-in messages (host info, heartbeat). The mostly small inbound responses
with occasional larger payloads match a tasking pattern where the C2 server
usually returns "no tasks" but periodically sends commands.

One session at 14:17:33 UTC showed:
- Outbound: 138 bytes (check-in)
- Inbound: 4,218 bytes (large response -- possible command download)
- Followed by outbound: 3,891 bytes approximately 8 seconds later (possible
  command output exfiltration)

### Step 6: Correlation with Endpoint Telemetry

Cross-referenced the network activity with endpoint detection and response
(EDR) logs for WS-MARKETING-12:

- **14:17:41 UTC** -- EDR recorded `powershell.exe` spawned by `svchost.exe`
  (unusual parent process)
- **14:17:43 UTC** -- PowerShell executed an encoded command
  (`-EncodedCommand` flag detected)
- **14:17:45 UTC** -- PowerShell made a WMI query for installed antivirus
  products (`SELECT * FROM AntiVirusProduct`)
- **14:17:48 UTC** -- Network connection from `powershell.exe` back to
  198.51.100.99:443 (result exfiltration)

The encoded PowerShell command, when decoded, performed host reconnaissance:
hostname, username, domain membership, running processes, and installed security
software.

**Assessment:** This confirms the network beaconing is associated with active
C2 command execution, not just passive callbacks.

## 3. Findings

### Confirmed: Command and Control Beaconing

Host **10.0.0.75** (WS-MARKETING-12) has been compromised and is actively
communicating with C2 infrastructure at **198.51.100.99** via HTTPS on port 443.

**Indicators of Compromise (IOCs):**

| IOC Type | Value |
|----------|-------|
| Destination IP | 198.51.100.99 |
| Domain | update-cdn-assets.example.net |
| Beacon Interval | ~60 seconds |
| Protocol | HTTPS (TCP/443) |
| Certificate | Self-signed, CN=update-cdn-assets.example.net |
| Source Host | 10.0.0.75 / WS-MARKETING-12 |

**Confidence:** High. The combination of regular-interval beaconing, self-signed
certificate, recently registered domain, consistent payload sizes matching a
check-in/tasking pattern, and corroborating EDR evidence of command execution
provides strong evidence of C2 activity.

## 4. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| Application Layer Protocol: Web Protocols | T1071.001 | C2 communication over HTTPS |
| Encrypted Channel | T1573 | TLS encryption to hide C2 traffic content |
| Exfiltration Over C2 Channel | T1041 | Reconnaissance results sent back over same channel |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell execution on endpoint |
| System Information Discovery | T1082 | WMI query for AV products, host reconnaissance |

## 5. Response Actions

1. **Containment (Immediate)**
   - Isolated WS-MARKETING-12 from the network via EDR network quarantine
   - Added 198.51.100.99 to firewall block list (all ports, both directions)
   - Added update-cdn-assets.example.net to DNS sinkhole

2. **Scoping**
   - Searched proxy logs and DNS logs for any other internal hosts querying
     update-cdn-assets.example.net or connecting to 198.51.100.99
   - Result: No other hosts affected (single-host compromise)
   - Searched for the self-signed certificate hash across all TLS inspection
     logs -- no additional matches

3. **Evidence Preservation**
   - Full packet capture preserved: `evidence/case-2026-0305-c2/full_capture.pcap`
   - EDR timeline exported for WS-MARKETING-12
   - Memory image acquired before reimaging

4. **Eradication**
   - Escalated to Incident Response team for full forensic analysis
   - Pending: identify initial access vector (likely phishing based on
     user's role and timing)
   - Pending: reimage WS-MARKETING-12 after forensic analysis

5. **Monitoring**
   - Created permanent SIEM detection rule for the identified IOCs
   - Added JA3 hash of the C2 server's TLS configuration to threat intelligence
     platform for ongoing matching

## 6. Lessons Learned

- The SIEM beaconing detection rule correctly identified the threat. The
  60-second interval with low jitter is a default configuration in many C2
  frameworks. Adversaries with operational security awareness randomize
  intervals more aggressively.
- Self-signed certificates on HTTPS traffic to internet destinations should
  be flagged automatically by TLS inspection infrastructure.
- The domain naming convention ("update-cdn-assets") was designed to blend in
  with legitimate traffic during casual log review. Automated analysis caught
  what manual review might have missed.
- Endpoint and network telemetry correlation was critical for confirming the
  finding and understanding the scope of compromise.
