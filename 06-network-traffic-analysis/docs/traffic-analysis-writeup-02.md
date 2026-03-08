# Traffic Analysis Write-Up 02: Port Scan Detection and Analysis

## Classification

| Field | Value |
|-------|-------|
| **Date** | 2026-03-04 |
| **Analyst** | SOC Tier 2 |
| **Severity** | Medium |
| **Status** | Confirmed - Mitigated |
| **MITRE ATT&CK** | T1046 (Network Service Discovery), T1595.001 (Active Scanning: Scanning IP Blocks) |

---

## 1. Scenario

At 09:47 UTC on 2026-03-04, the network IDS (Suricata) generated multiple
alerts:

```
[1:2010935:3] ET SCAN Suspicious inbound to mySQL port 3306
[1:2010937:3] ET SCAN Suspicious inbound to MSSQL port 1433
[1:2002911:6] ET SCAN Potential VNC Scan 5900-5920
[1:2010939:3] ET SCAN Suspicious inbound to PostgreSQL port 5432
```

All alerts originated from a single external IP: **203.0.113.200**. The target
IPs were in the DMZ subnet **10.0.0.16/28** (10.0.0.17 through 10.0.0.30),
which hosts the organization's public-facing web servers, mail relay, and DNS
server.

The IDS generated 47 alerts in a 12-minute window (09:47-09:59 UTC),
indicating systematic probing across multiple ports and hosts.

## 2. Investigation

### Step 1: Scope the Activity

Retrieved the relevant pcap from the DMZ sensor and applied an initial filter
to isolate all traffic from the scanning source:

```
ip.src == 203.0.113.200
```

**Initial observations:**
- 1,247 packets from 203.0.113.200 during the capture window
- All packets were TCP
- Destination IPs spanned the full DMZ range (10.0.0.17 through 10.0.0.30)
- Destination ports varied widely

### Step 2: Identify the Scan Type via TCP Flag Analysis

Filtered for the TCP flags to determine the scanning technique:

```
ip.src == 203.0.113.200 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Result:** 1,193 of 1,247 packets (95.7%) were SYN-only packets (no ACK flag).
This is the signature of a **TCP SYN scan** (also called a half-open scan or
stealth scan), commonly performed with `nmap -sS`.

Verified by checking for completed three-way handshakes:

```
ip.src == 203.0.113.200 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

**Result:** 0 packets. The scanner never sent SYN-ACK. It initiated connections
but never completed the handshake, confirming half-open scanning.

Checked for additional scan techniques mixed in:

```
ip.src == 203.0.113.200 && tcp.flags == 0x000
```

**Result:** 0 packets (no null scan).

```
ip.src == 203.0.113.200 && tcp.flags.fin == 1 && tcp.flags.push == 1 && tcp.flags.urg == 1
```

**Result:** 0 packets (no XMAS scan).

**Assessment:** The attacker used a pure SYN scan, the most common and reliable
port scanning technique. No evasion techniques such as fragmentation, null, or
XMAS scans were observed.

### Step 3: Analyze Target Hosts and Ports

Identified which DMZ hosts were targeted:

```
ip.src == 203.0.113.200 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Used Statistics > Endpoints (IPv4 tab, filtered for destination) to enumerate
targets:

| Target IP | SYN Packets Received | Open Ports Found |
|-----------|:--------------------:|:----------------:|
| 10.0.0.17 | 142 | 3 (22, 80, 443) |
| 10.0.0.18 | 138 | 2 (25, 587) |
| 10.0.0.19 | 145 | 2 (53, 953) |
| 10.0.0.20 | 131 | 1 (443) |
| 10.0.0.21 | 127 | 1 (80) |
| 10.0.0.22 | 134 | 0 |
| 10.0.0.23 | 140 | 0 |
| 10.0.0.24 | 136 | 0 |
| 10.0.0.25-30 | 0 | N/A (hosts not active) |

The scanner probed 8 of the 14 possible host addresses in the /28 subnet,
suggesting it performed an initial host discovery phase before the port scan.

### Step 4: Determine Which Ports Were Scanned

Used Statistics > Conversations (TCP tab) to list all destination ports:

```
ip.src == 203.0.113.200 && tcp.flags.syn == 1
```

The scanner targeted **the Nmap default top 100 ports** based on the port
selection pattern. Key ports probed included:

```
21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443 (and approximately 77 others)
```

This matches the output of `nmap --top-ports 100`, confirming a default Nmap
configuration.

### Step 5: Identify Open Ports (Scanner's Perspective)

A SYN scan identifies open ports by receiving SYN-ACK responses. Filtered for
responses from DMZ hosts back to the scanner:

```
ip.dst == 203.0.113.200 && tcp.flags.syn == 1 && tcp.flags.ack == 1
```

**Open ports discovered by the scanner:**

| Target | Port | Service | SYN-ACK Response Time |
|--------|:----:|---------|:---------------------:|
| 10.0.0.17 | 22 | SSH | 0.3 ms |
| 10.0.0.17 | 80 | HTTP | 0.2 ms |
| 10.0.0.17 | 443 | HTTPS | 0.2 ms |
| 10.0.0.18 | 25 | SMTP | 0.4 ms |
| 10.0.0.18 | 587 | SMTP Submission | 0.3 ms |
| 10.0.0.19 | 53 | DNS | 0.2 ms |
| 10.0.0.19 | 953 | RNDC | 0.3 ms |
| 10.0.0.20 | 443 | HTTPS | 0.2 ms |
| 10.0.0.21 | 80 | HTTP | 0.3 ms |

**Concern:** Port 953 (RNDC -- BIND remote name daemon control) on 10.0.0.19
should not be accessible from external sources. This indicates a firewall rule
gap.

Ports that returned RST-ACK (closed):

```
ip.dst == 203.0.113.200 && tcp.flags.reset == 1 && tcp.flags.ack == 1
```

**Result:** 312 RST-ACK packets, confirming the target hosts were live but those
ports were closed.

Ports with no response (filtered by firewall):

The remaining ~870 SYN packets received no response, indicating they were
silently dropped by the firewall. This is the expected behavior for the
perimeter firewall's default deny rule.

### Step 6: Timing Analysis

Analyzed the scan timing to understand the scanner's speed and methodology:

```
ip.src == 203.0.113.200 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

| Metric | Value |
|--------|-------|
| First SYN packet | 09:47:12.331 UTC |
| Last SYN packet | 09:59:48.917 UTC |
| Total duration | 756.6 seconds (~12.6 minutes) |
| Total SYN packets | 1,193 |
| Average rate | 1.58 packets/second |
| Source port range | 40,000 - 60,000 (randomized) |

**Assessment:** The scan rate of ~1.6 packets/second is moderate -- faster than
a "sneaky" scan designed to evade detection but slower than an aggressive scan.
This is consistent with Nmap's default timing template (`-T3`). The randomized
source ports are standard Nmap behavior.

The scan appeared to proceed host-by-host (all ports for 10.0.0.17 before
moving to 10.0.0.18), which is Nmap's default behavior without the
`--randomize-hosts` flag.

### Step 7: Source IP Investigation

Performed external lookups on 203.0.113.200:

- **WHOIS:** Registered to an ISP in Eastern Europe. The /24 block has appeared
  in multiple threat intelligence feeds associated with scanning activity.
- **Threat Intelligence:** IP was listed in 3 of 5 checked blocklists:
  - AbuseIPDB: 87% confidence score, 142 reports in last 30 days
  - Shodan: Associated with mass scanning activity
  - GreyNoise: Classified as "malicious" scanner
- **Reverse DNS:** No PTR record configured
- **Historical:** First observed scanning the organization's IP space; no
  prior connections in 90-day firewall logs

## 3. Findings

### Confirmed: External SYN Port Scan of DMZ

An external host at **203.0.113.200** performed a TCP SYN scan of the
organization's DMZ subnet, probing the top 100 TCP ports across 8 active hosts
over a 12.6-minute window. The scan identified 9 open ports across 5 hosts.

**Key concern:** The scan revealed that port **953 (RNDC)** on the DNS server
(10.0.0.19) is accessible from external sources. RNDC provides administrative
control over the BIND DNS server and should never be exposed to the internet.

**Indicators of Compromise (IOCs):**

| IOC Type | Value |
|----------|-------|
| Source IP | 203.0.113.200 |
| Scan Type | TCP SYN (half-open) |
| Target Subnet | 10.0.0.16/28 (DMZ) |
| Ports Scanned | Nmap top 100 |
| Duration | 09:47 - 09:59 UTC |
| Scan Rate | ~1.6 pps |

## 4. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| Network Service Discovery | T1046 | SYN scan of top 100 ports across DMZ hosts |
| Active Scanning: Scanning IP Blocks | T1595.001 | Sequential scanning of /28 subnet |

**Likely next steps in kill chain (to monitor for):**
- T1190 -- Exploit Public-Facing Application (targeting discovered services)
- T1133 -- External Remote Services (SSH on 10.0.0.17)
- T1078 -- Valid Accounts (brute force against discovered SSH/SMTP)

## 5. Response Actions

### Immediate (completed within 1 hour)

1. **Firewall block:** Added 203.0.113.200 to the perimeter firewall deny list
   with a 30-day expiration and logging enabled.

   ```
   # Firewall rule added
   deny ip host 203.0.113.200 any log
   ```

2. **RNDC exposure remediation:** Created emergency change request and
   implemented a firewall rule to block external access to port 953 on
   10.0.0.19. Verified RNDC is now only accessible from the management VLAN
   (10.0.1.0/24).

   ```
   # Firewall rule added
   deny tcp any host 10.0.0.19 eq 953 log
   permit tcp 10.0.1.0/24 host 10.0.0.19 eq 953
   ```

3. **Verification:** Confirmed the block is effective by checking that no
   further traffic from 203.0.113.200 appeared in firewall logs after the rule
   was applied.

### Short-Term (completed within 24 hours)

4. **Firewall audit:** Initiated a review of all DMZ firewall rules to
   identify other unintended exposures. Methodology: compared allowed inbound
   ports against the documented DMZ service inventory.

5. **Service hardening review:** Verified that all services discovered as
   open by the scan are patched and configured according to hardening baselines:
   - SSH (10.0.0.17): Key-only auth, no root login, fail2ban active
   - HTTP/HTTPS (10.0.0.17, 10.0.0.20, 10.0.0.21): WAF in front, current patches
   - SMTP (10.0.0.18): TLS required, rate limiting enabled
   - DNS (10.0.0.19): BIND version hidden, recursion disabled for external queries

6. **Threat intelligence enrichment:** Submitted 203.0.113.200 to the
   organization's threat intelligence platform and shared IOCs with the
   sector ISAC.

### Monitoring (ongoing)

7. **Enhanced monitoring:** Created a SIEM correlation rule to alert if
   203.0.113.200 (or any IP from the 203.0.113.0/24 block) attempts any
   connection to the environment.

8. **Follow-up scan watch:** Created a detection rule for any external host
   sending SYN packets to more than 10 different ports on DMZ hosts within a
   5-minute window.

## 6. Impact Assessment

- **Data exposure:** None. The scan was reconnaissance only; no exploitation
  attempts were observed following the scan within the analysis window.
- **Service disruption:** None. The scan rate was low enough to not impact
  service availability.
- **Information leakage:** The scanner now knows which ports are open on the
  DMZ hosts. This information could be used to plan targeted exploitation.
  The RNDC exposure was the most significant finding, as it could have allowed
  DNS server manipulation if the RNDC key were compromised or weak.

## 7. Analyst Notes

Port scanning is the most common form of reconnaissance observed against
internet-facing infrastructure. While a single scan is typically low severity,
the value of this investigation was:

1. **Discovery of the RNDC exposure** -- The scan inadvertently served as a
   free external penetration test. The firewall gap for port 953 was not
   identified in the last quarterly vulnerability assessment because the
   assessment was conducted from the internal network.

2. **Validation of detection capability** -- The IDS correctly detected and
   alerted on the scan. The 12-minute window between scan start and alert
   generation is acceptable for a moderate-speed scan.

3. **Process improvement** -- This incident prompted a review of the firewall
   change management process to include automated verification that new rules
   do not accidentally expose management ports (such as 953, 161, 5900) to
   external networks.

**Recommendation:** Implement automated external port scanning (using a service
like Shodan Monitor or a scheduled Nmap scan from an external vantage point) to
continuously verify that only intended ports are externally accessible. This
would catch configuration drift before an adversary does.
