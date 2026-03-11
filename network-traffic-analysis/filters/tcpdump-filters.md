# tcpdump / BPF Filter Reference

A practical reference for tcpdump capture filters organized by common incident
response and threat hunting scenarios. These filters use Berkeley Packet Filter
(BPF) syntax which operates at the kernel level during capture, reducing disk
and memory usage by discarding irrelevant packets before they reach userspace.

**Key distinction:** These are *capture* filters (BPF syntax), not *display*
filters (Wireshark syntax). Capture filters are less expressive but run at wire
speed. Use them to scope captures during live incidents, then apply Wireshark
display filters for detailed analysis.

---

## Table of Contents

1. [Basic Capture Commands](#1-basic-capture-commands)
2. [Host and Network Filters](#2-host-and-network-filters)
3. [Protocol and Port Filters](#3-protocol-and-port-filters)
4. [TCP Flag Filters](#4-tcp-flag-filters)
5. [Reconnaissance Detection](#5-reconnaissance-detection)
6. [C2 and Malware Scenarios](#6-c2-and-malware-scenarios)
7. [Data Exfiltration Scenarios](#7-data-exfiltration-scenarios)
8. [Credential and Authentication Capture](#8-credential-and-authentication-capture)
9. [Lateral Movement Scenarios](#9-lateral-movement-scenarios)
10. [Performance and Troubleshooting](#10-performance-and-troubleshooting)
11. [Common Operational Recipes](#11-common-operational-recipes)

---

## 1. Basic Capture Commands

### Capture to file with rotation

```bash
tcpdump -i eth0 -w /tmp/capture_%Y%m%d_%H%M%S.pcap -G 3600 -C 100 -Z root
```

- `-G 3600` -- Rotate files every 3600 seconds (1 hour)
- `-C 100` -- Rotate when file reaches 100 MB
- `-Z root` -- Drop privileges after opening capture device

### Capture with timestamps and no DNS resolution

```bash
tcpdump -i eth0 -nn -tttt -c 1000 -w capture.pcap
```

- `-nn` -- No DNS or port name resolution (faster, avoids DNS traffic from tcpdump itself)
- `-tttt` -- Print timestamps in human-readable format
- `-c 1000` -- Stop after 1000 packets

### Read an existing pcap with filter

```bash
tcpdump -r capture.pcap -nn 'host 198.51.100.10'
```

### Verbose output for protocol details

```bash
tcpdump -i eth0 -nn -vvv -X 'port 53'
```

- `-vvv` -- Maximum verbosity
- `-X` -- Print packet contents in hex and ASCII

---

## 2. Host and Network Filters

### Traffic to or from a specific host

```
host 198.51.100.10
```

### Traffic from a specific source

```
src host 10.0.0.50
```

### Traffic to a specific destination

```
dst host 203.0.113.25
```

### Traffic from a subnet

```
src net 10.0.0.0/24
```

### Traffic between two hosts (bidirectional)

```
host 10.0.0.50 and host 198.51.100.99
```

### All traffic except a specific host (reduce noise from a chatty server)

```
not host 10.0.0.1
```

### External-only traffic (exclude RFC1918)

```
not (src net 10.0.0.0/8 and dst net 10.0.0.0/8) and not (src net 172.16.0.0/12 and dst net 172.16.0.0/12) and not (src net 192.168.0.0/16 and dst net 192.168.0.0/16)
```

**Use case:** Capture only traffic crossing the network boundary, excluding
internal-to-internal flows.

---

## 3. Protocol and Port Filters

### TCP traffic only

```
tcp
```

### UDP traffic only

```
udp
```

### ICMP traffic only

```
icmp
```

### Specific port (both directions)

```
port 443
```

### Specific destination port

```
dst port 22
```

### Port range

```
portrange 8000-9000
```

### Multiple ports

```
port 80 or port 443 or port 8080 or port 8443
```

### DNS traffic

```
port 53
```

### HTTP traffic (including common alternate ports)

```
tcp port 80 or tcp port 8080 or tcp port 8443 or tcp port 443
```

### Non-standard port traffic (exclude common services)

```
tcp and not port 22 and not port 80 and not port 443 and not port 53 and not port 25 and not portrange 135-139 and not port 445
```

**Use case:** Find traffic on unexpected ports that may indicate backdoors,
tunnels, or misconfigured services.

---

## 4. TCP Flag Filters

BPF accesses TCP flags at byte offset 13 in the TCP header (0-indexed). The
flag bits are:

| Bit | Flag | Value |
|-----|------|-------|
| 0   | FIN  | 0x01  |
| 1   | SYN  | 0x02  |
| 2   | RST  | 0x04  |
| 3   | PSH  | 0x08  |
| 4   | ACK  | 0x10  |
| 5   | URG  | 0x20  |

### SYN packets only (new connections)

```
'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

### SYN-ACK packets (connection responses)

```
'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'
```

### RST packets (connection resets)

```
'tcp[tcpflags] & tcp-rst != 0'
```

### FIN packets (connection teardown)

```
'tcp[tcpflags] & tcp-fin != 0'
```

### Null scan (no flags)

```
'tcp[tcpflags] == 0'
```

### XMAS scan (FIN + PSH + URG)

```
'tcp[tcpflags] & (tcp-fin|tcp-push|tcp-urg) == (tcp-fin|tcp-push|tcp-urg)'
```

### PSH-ACK (data transfer)

```
'tcp[tcpflags] & (tcp-push|tcp-ack) == (tcp-push|tcp-ack)'
```

---

## 5. Reconnaissance Detection

### Capture potential SYN scan from an external source

```bash
tcpdump -i eth0 -nn -w syn_scan.pcap \
  'src host 203.0.113.200 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

**Scenario:** IDS alerted on SYN scan from 203.0.113.200. This captures only
the scanning traffic for analysis.

### Capture all ICMP (ping sweeps, traceroute, tunneling)

```bash
tcpdump -i eth0 -nn -w icmp_traffic.pcap 'icmp'
```

### Capture ARP traffic (host discovery on LAN)

```bash
tcpdump -i eth0 -nn -w arp_traffic.pcap 'arp'
```

### Capture RST responses (indicates probing of closed ports)

```bash
tcpdump -i eth0 -nn -w resets.pcap \
  'tcp[tcpflags] & tcp-rst != 0 and src net 10.0.0.0/24'
```

**Scenario:** A burst of RST packets from DMZ hosts may indicate they are being
scanned.

---

## 6. C2 and Malware Scenarios

### Capture traffic to a suspected C2 IP

```bash
tcpdump -i eth0 -nn -w c2_traffic.pcap \
  'host 198.51.100.99'
```

### Capture DNS queries to investigate tunneling

```bash
tcpdump -i eth0 -nn -w dns_queries.pcap \
  'udp port 53 and src net 10.0.0.0/8'
```

### Capture DNS queries with response (full conversation)

```bash
tcpdump -i eth0 -nn -vvv -w dns_full.pcap \
  'port 53'
```

### DNS queries larger than 512 bytes (possible tunneling)

```bash
tcpdump -i eth0 -nn -w large_dns.pcap \
  'udp port 53 and udp[4:2] > 512'
```

**Explanation:** `udp[4:2]` reads 2 bytes at offset 4 in the UDP header, which
is the UDP length field. DNS over UDP responses larger than 512 bytes are
unusual without EDNS and can indicate tunneling.

### HTTP POST requests (C2 check-in / data exfil)

```bash
tcpdump -i eth0 -nn -A -w http_posts.pcap \
  'tcp dst port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
```

**Explanation:** This matches the ASCII string "POST" at the start of the TCP
payload. `tcp[12:1] & 0xf0 >> 2` calculates the TCP data offset (header length)
to find where the payload begins.

### ICMP with large payloads (ICMP tunneling)

```bash
tcpdump -i eth0 -nn -w icmp_tunnel.pcap \
  'icmp and (ip[2:2] > 100)'
```

**Explanation:** `ip[2:2]` is the IP total length field. Normal ICMP echo
packets are small (typically 64-84 bytes total). Packets over 100 bytes may
carry tunneled data.

### Traffic on known malicious ports

```bash
tcpdump -i eth0 -nn -w suspicious_ports.pcap \
  'dst port 4444 or dst port 5555 or dst port 1337 or dst port 31337 or dst port 12345'
```

---

## 7. Data Exfiltration Scenarios

### Large outbound transfers from internal hosts

```bash
tcpdump -i eth0 -nn -w large_outbound.pcap \
  'src net 10.0.0.0/8 and dst net not 10.0.0.0/8 and ip[2:2] > 1000'
```

**Use case:** Capture outbound packets with IP total length over 1000 bytes.
Review the destinations for unexpected external hosts receiving large data
transfers.

### Outbound FTP data channel

```bash
tcpdump -i eth0 -nn -w ftp_exfil.pcap \
  'src net 10.0.0.0/8 and (dst port 20 or dst port 21)'
```

### Outbound SMB (should not leave the network)

```bash
tcpdump -i eth0 -nn -w smb_outbound.pcap \
  'dst port 445 and dst net not 10.0.0.0/8 and dst net not 172.16.0.0/12 and dst net not 192.168.0.0/16'
```

### Unusual outbound protocol (non TCP/UDP)

```bash
tcpdump -i eth0 -nn -w unusual_proto.pcap \
  'src net 10.0.0.0/8 and not tcp and not udp and not icmp and not arp'
```

**Use case:** Capture GRE, ESP, or other unusual IP protocols leaving the
network. These can be used for covert channels.

---

## 8. Credential and Authentication Capture

### Cleartext FTP credentials

```bash
tcpdump -i eth0 -nn -A -w ftp_creds.pcap \
  'tcp port 21'
```

The `-A` flag prints ASCII content, making USER and PASS commands visible in
the output.

### Cleartext Telnet sessions

```bash
tcpdump -i eth0 -nn -A -w telnet.pcap \
  'tcp port 23'
```

### HTTP Basic Authentication

```bash
tcpdump -i eth0 -nn -A -w http_auth.pcap \
  'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)'
```

**Explanation:** Captures HTTP GET and POST requests. Review output for
`Authorization: Basic` headers.

### Kerberos traffic

```bash
tcpdump -i eth0 -nn -w kerberos.pcap \
  'tcp port 88 or udp port 88'
```

### LDAP cleartext

```bash
tcpdump -i eth0 -nn -w ldap.pcap \
  'tcp port 389'
```

### NTLM over SMB

```bash
tcpdump -i eth0 -nn -w ntlm_smb.pcap \
  'tcp port 445'
```

---

## 9. Lateral Movement Scenarios

### SMB traffic between workstations (not to/from file server)

```bash
tcpdump -i eth0 -nn -w smb_lateral.pcap \
  'tcp port 445 and not host 10.0.0.5 and src net 10.0.0.0/24 and dst net 10.0.0.0/24'
```

**Scenario:** 10.0.0.5 is the legitimate file server. SMB between any other
workstations on the same subnet may indicate lateral movement.

### RDP connections

```bash
tcpdump -i eth0 -nn -w rdp.pcap \
  'tcp port 3389'
```

### RDP from unauthorized sources

```bash
tcpdump -i eth0 -nn -w rdp_unauth.pcap \
  'tcp dst port 3389 and not src host 10.0.0.10'
```

**Scenario:** 10.0.0.10 is the approved jump box. Any other RDP sources
are suspicious.

### WinRM / PowerShell Remoting

```bash
tcpdump -i eth0 -nn -w winrm.pcap \
  'tcp port 5985 or tcp port 5986'
```

### RPC / WMI lateral execution

```bash
tcpdump -i eth0 -nn -w rpc_wmi.pcap \
  'tcp port 135 and src net 10.0.0.0/24'
```

### SSH between internal hosts

```bash
tcpdump -i eth0 -nn -w internal_ssh.pcap \
  'tcp port 22 and src net 10.0.0.0/8 and dst net 10.0.0.0/8'
```

---

## 10. Performance and Troubleshooting

### TCP retransmissions (duplicate sequence numbers)

```bash
tcpdump -i eth0 -nn -w retransmissions.pcap \
  'tcp and (tcp[tcpflags] & tcp-push != 0)'
```

Review in Wireshark using the `tcp.analysis.retransmission` display filter for
actual retransmission identification.

### Packets with IP fragmentation

```bash
tcpdump -i eth0 -nn -w fragments.pcap \
  '((ip[6:2] & 0x1fff) != 0 or (ip[6:2] & 0x2000) != 0)'
```

**Explanation:** Checks the fragment offset and More Fragments flag in the IP
header. Fragmentation can indicate MTU issues or evasion attempts.

### DHCP traffic

```bash
tcpdump -i eth0 -nn -w dhcp.pcap \
  'udp port 67 or udp port 68'
```

### NTP traffic

```bash
tcpdump -i eth0 -nn -w ntp.pcap \
  'udp port 123'
```

---

## 11. Common Operational Recipes

### Incident response: capture everything from a compromised host

```bash
tcpdump -i eth0 -nn -s 0 -w /evidence/host_10.0.0.75_$(date +%Y%m%d_%H%M%S).pcap \
  'host 10.0.0.75'
```

- `-s 0` -- Capture full packet (no truncation)
- Filename includes timestamp for evidence chain

### Incident response: capture without generating extra DNS traffic

```bash
tcpdump -i eth0 -nn -w capture.pcap \
  'not port 53 or (port 53 and host 10.0.0.75)'
```

Captures all non-DNS traffic plus only DNS from the host of interest. Prevents
tcpdump's own DNS lookups from cluttering the capture.

### Threat hunt: look for beaconing to a suspect IP

```bash
tcpdump -i eth0 -nn -c 500 -w beacon_check.pcap \
  'dst host 198.51.100.99 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

Captures the first 500 SYN packets to the suspect host, then import into
Wireshark to analyze timing intervals.

### Extract HTTP host headers from live traffic

```bash
tcpdump -i eth0 -nn -A -s 0 'tcp dst port 80' | grep -i 'Host:'
```

Quick live extraction of HTTP Host headers without writing to disk.

### Monitor DNS queries in real time

```bash
tcpdump -i eth0 -nn -l 'udp dst port 53' | awk '{print $NF}'
```

The `-l` flag line-buffers output so it appears immediately. Useful for
real-time monitoring of DNS lookups during incident response.
