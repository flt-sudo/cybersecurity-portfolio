# Usage Guide -- Security Automation Toolkit

Detailed usage examples, sample output, and integration tips for each script in the toolkit.

---

## Table of Contents

1. [Log Parser](#1-log-parser)
2. [Hash Checker](#2-hash-checker)
3. [Port Monitor](#3-port-monitor)
4. [IP Reputation Checker](#4-ip-reputation-checker)
5. [File Integrity Monitor](#5-file-integrity-monitor)
6. [Integration Tips](#6-integration-tips)

---

## 1. Log Parser

**Script**: `scripts/log_parser.py`

### Supported Log Formats

| Format | Source | Example Path |
|---|---|---|
| auth.log | SSH authentication events | `/var/log/auth.log` |
| Access log | Apache / Nginx combined format | `/var/log/apache2/access.log` |
| Syslog | Generic syslog messages | `/var/log/syslog` |

### Basic Usage

```bash
# Analyze the included sample log
python3 scripts/log_parser.py logs/sample-auth.log
```

### Sample Output

```
========================================================================
                     SECURITY LOG ANALYSIS REPORT
========================================================================

---------------------------------------------------- Summary -----------
  Total lines processed : 41
  Unparsed lines        : 0
  Failed SSH logins     : 22
  Accepted SSH logins   : 6
  Sudo events           : 10
  HTTP requests         : 0
  Syslog entries        : 0

---------------------------------------------- Top Source IPs ----------
  203.0.113.45              11 events
  198.51.100.22              6 events
  10.0.1.50                  4 events
  192.0.2.100                4 events
  45.33.32.156               3 events

---------------------------------------- Failed Logins by User --------
  root                       10 failures
  test                        1 failures
  admin                       4 failures
  guest                       1 failures

------------------------------------ Failed Logins by Source IP --------
  203.0.113.45              11 failures ** BRUTE-FORCE CANDIDATE
  198.51.100.22              6 failures ** BRUTE-FORCE CANDIDATE
  192.0.2.100                4 failures
  45.33.32.156               3 failures

------------------------------ ALERT: Potential Brute-Force Sources ----
  [!] 203.0.113.45 -- 11 failed attempts
  [!] 198.51.100.22 -- 6 failed attempts

------------------------------------- Privilege Escalation (sudo) ------
  [2026-03-05T06:22:03] admin -> /usr/bin/systemctl status nginx
  [2026-03-05T08:32:11] developer -> /usr/bin/apt update
  [2026-03-05T15:31:22] developer -> /usr/bin/chmod 777 /var/www/html/uploads
  [2026-03-05T17:01:30] admin -> /usr/sbin/useradd -m temp_contractor
```

### Time Range Filtering

```bash
# Only analyze events between 07:00 and 12:00 on March 5
python3 scripts/log_parser.py logs/sample-auth.log \
    --start "2026-03-05 07:00" \
    --end "2026-03-05 12:00"
```

### JSON Export

```bash
python3 scripts/log_parser.py logs/sample-auth.log --json analysis.json
```

The JSON output contains the full structured report:

```json
{
  "summary": {
    "total_lines_processed": 41,
    "failed_logins": 22,
    "accepted_logins": 6,
    "sudo_events": 10
  },
  "alerts": {
    "potential_brute_force_ips": {
      "203.0.113.45": 11,
      "198.51.100.22": 6
    },
    "sudo_commands": [...]
  },
  "timeline": {...}
}
```

### Multiple Log Files

```bash
python3 scripts/log_parser.py /var/log/auth.log /var/log/apache2/access.log /var/log/syslog
```

---

## 2. Hash Checker

**Script**: `scripts/hash_checker.py`

### Compute Hashes

```bash
python3 scripts/hash_checker.py /usr/bin/curl
```

**Output:**

```
============================================================
                     FILE HASH CHECKER
============================================================

  File : /usr/bin/curl
  Size : 256,128 bytes
  MD5   : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
  SHA1  : 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
  SHA256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
============================================================
```

### VirusTotal Lookup

```bash
export VIRUSTOTAL_API_KEY="your_api_key"
python3 scripts/hash_checker.py /path/to/suspicious_file --check
```

**Output (malicious file):**

```
  --- VirusTotal Results ---------------------------------
  File Name       : malware_sample.exe
  File Type       : Win32 EXE
  File Size       : 143,360 bytes
  Detection Ratio : 54/71
    Malicious     : 54
    Suspicious    : 2
    Undetected    : 12
    Harmless      : 3
  Reputation      : -89
  Verdict         : *** MALICIOUS ***
```

### Check a Raw Hash (No File Needed)

```bash
python3 scripts/hash_checker.py \
    --hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f \
    --check
```

### Offline Mode with Known-Bad List

Create a text file with known malicious hashes:

```
# known_bad_hashes.txt
# Format: hash  description
44d88612fea8a8f36de82e1278abb02f  EICAR-Test-File
e99a18c428cb38d5f260853678922e03  known-ransomware-variant
```

```bash
python3 scripts/hash_checker.py /path/to/file --check --bad-hashes known_bad_hashes.txt
```

### JSON Export

```bash
python3 scripts/hash_checker.py /path/to/file --check --json results.json
```

---

## 3. Port Monitor

**Script**: `scripts/port_monitor.py`

### Initial Baseline Scan

```bash
python3 scripts/port_monitor.py --target 192.168.1.1 --ports 1-1024
```

**Output:**

```
============================================================
                     PORT STATE MONITOR
============================================================
  Target   : 192.168.1.1 (192.168.1.1)
  Ports    : 1024 ports
  Timeout  : 1.0s per port
  Baseline : port_baseline.json

[2026-03-05 14:22:01] No baseline found. Performing initial scan...
[2026-03-05 14:22:35] Baseline created: 4 open port(s)

  --- Baseline Open Ports --------------------------------
    22/SSH
    80/HTTP
    443/HTTPS
    3306/MySQL

[+] Baseline saved. Run again to detect changes.
```

### Detect Changes

Run the same command again after the target changes:

```bash
python3 scripts/port_monitor.py --target 192.168.1.1 --ports 1-1024
```

**Output (changes detected):**

```
[2026-03-05 15:30:00] Loaded baseline (taken 2026-03-05T14:22:35, 4 open ports)
[2026-03-05 15:30:34] Scan #1 starting against 192.168.1.1...
[2026-03-05 15:30:34] *** CHANGES DETECTED ***
[2026-03-05 15:30:34]   [NEW OPEN]   8080/HTTP-Alt
[2026-03-05 15:30:34]   [NOW CLOSED] 3306/MySQL
[2026-03-05 15:30:34] Baseline updated to current state.
```

### Specific Ports

```bash
python3 scripts/port_monitor.py --target 10.0.0.5 --ports 22,80,443,3306,5432,8080,8443
```

### Continuous Monitoring

```bash
# Scan every 5 minutes with logging
python3 scripts/port_monitor.py \
    --target 192.168.1.1 \
    --ports 1-1024 \
    --monitor \
    --interval 300 \
    --logfile logs/port_changes.log
```

Press Ctrl+C to stop monitoring.

### Custom Baseline Location

```bash
python3 scripts/port_monitor.py \
    --target 10.0.0.5 \
    --ports 1-65535 \
    --baseline baselines/webserver_ports.json \
    --timeout 0.5
```

---

## 4. IP Reputation Checker

**Script**: `scripts/ip_reputation.py`

### Single IP Lookup (AbuseIPDB)

```bash
export ABUSEIPDB_API_KEY="your_api_key"
python3 scripts/ip_reputation.py 185.220.101.1
```

**Output:**

```
============================================================
                   IP REPUTATION CHECKER
============================================================
  Mode: AbuseIPDB API (online)
  IPs to check: 1

  [1] 185.220.101.1
    Abuse Score    : 100% (HIGH)
    Country        : DE
    ISP            : Tor Exit Node
    Domain         : torproject.org
    Total Reports  : 4,821
    Reporters      : 1,230
    Last Reported  : 2026-03-05T12:00:00+00:00
    Usage Type     : Reserved
    Tor Exit Node  : YES

--- Summary ------------------------------------------------
  Total IPs checked : 1
  High threat       : 1
============================================================
```

### Multiple IPs

```bash
python3 scripts/ip_reputation.py 8.8.8.8 1.1.1.1 203.0.113.45
```

### Bulk Lookup from File

Create a file with one IP per line:

```
# suspicious_ips.txt
203.0.113.45
198.51.100.22
45.33.32.156
192.0.2.100
```

```bash
python3 scripts/ip_reputation.py --file suspicious_ips.txt --csv results.csv
```

### Offline Mode with Local Threat Feeds

Threat feed files can be plain text (one IP per line) or CSV with an `ip` column:

```
# blocklist.txt - plain text format
203.0.113.45
198.51.100.22
45.33.32.156
```

```csv
ip,category,description
203.0.113.45,scanner,Port scanning activity
198.51.100.22,brute-force,SSH brute force attacks
```

```bash
python3 scripts/ip_reputation.py \
    --file suspicious_ips.txt \
    --feed blocklist.txt \
    --feed threat_intel.csv
```

### JSON Output

```bash
python3 scripts/ip_reputation.py 203.0.113.45 --json result.json
```

---

## 5. File Integrity Monitor

**Script**: `scripts/file_integrity_monitor.py`

### Create a Baseline

```bash
python3 scripts/file_integrity_monitor.py --init --target /etc/nginx --baseline nginx_baseline.json
```

**Output:**

```
[*] Scanning /etc/nginx ...
[+] Baseline created: 12 files indexed
[+] Saved to nginx_baseline.json
```

### Check for Changes

```bash
python3 scripts/file_integrity_monitor.py --check --target /etc/nginx --baseline nginx_baseline.json
```

**Output (no changes):**

```
========================================================================
            FILE INTEGRITY MONITOR -- CHANGE REPORT
========================================================================
  Target Directory : /etc/nginx
  Check Time       : 2026-03-05 16:00:00
  Unchanged Files  : 12
  Total Changes    : 0

  [OK] No changes detected. All files match the baseline.
========================================================================
```

**Output (changes detected):**

```
========================================================================
            FILE INTEGRITY MONITOR -- CHANGE REPORT
========================================================================
  Target Directory : /etc/nginx
  Check Time       : 2026-03-05 18:30:00
  Unchanged Files  : 9
  Total Changes    : 4

--- NEW FILES (not in baseline) ----------------------------------------
  [+] sites-enabled/malicious.conf
      SHA256: a1b2c3...
      Size:   342 bytes
      Perms:  -rw-r--r--

--- DELETED FILES (missing from disk) ----------------------------------
  [-] sites-available/old-app.conf
      SHA256: d4e5f6...
      Size:   128 bytes

--- MODIFIED FILES (content changed) -----------------------------------
  [*] nginx.conf
      Old SHA256 : 1234abcd...
      New SHA256 : 5678efgh...
      Size Delta : +45 bytes
      Old mtime  : 2026-03-01T12:00:00
      New mtime  : 2026-03-05T18:25:00

--- PERMISSION CHANGES -------------------------------------------------
  [!] sites-enabled/default
      Perms: -rw-r--r-- -> -rwxrwxrwx

========================================================================
```

### Check and Update Baseline

```bash
python3 scripts/file_integrity_monitor.py \
    --update \
    --target /etc/nginx \
    --baseline nginx_baseline.json \
    --report changes.json
```

### Exclude Directories

```bash
python3 scripts/file_integrity_monitor.py \
    --init \
    --target /var/www \
    --baseline www_baseline.json \
    --exclude cache \
    --exclude tmp \
    --exclude sessions
```

### Monitor Critical System Paths

```bash
# Configuration files
python3 scripts/file_integrity_monitor.py --init --target /etc --baseline etc_baseline.json

# Web application root
python3 scripts/file_integrity_monitor.py --init --target /var/www --baseline www_baseline.json

# System binaries
python3 scripts/file_integrity_monitor.py --init --target /usr/bin --baseline usrbin_baseline.json
```

---

## 6. Integration Tips

### Cron Job for Automated FIM Checks

Run file integrity checks every hour and log alerts:

```cron
0 * * * * /usr/bin/python3 /path/to/file_integrity_monitor.py --check --target /etc --baseline /var/lib/fim/etc.json --report /var/log/fim/$(date +\%Y\%m\%d-\%H).json 2>&1 | logger -t fim
```

### Combining Scripts in an Incident Response Workflow

```bash
#!/bin/bash
# incident_response.sh -- Automated IOC triage

SUSPECT_IP="$1"
LOG_DIR="/var/log"
REPORT_DIR="./ir_reports/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "[*] Starting automated triage for $SUSPECT_IP"

# 1. Check IP reputation
python3 scripts/ip_reputation.py "$SUSPECT_IP" --json "$REPORT_DIR/ip_rep.json"

# 2. Search logs for the IP
python3 scripts/log_parser.py "$LOG_DIR/auth.log" "$LOG_DIR/syslog" \
    --json "$REPORT_DIR/log_analysis.json"

# 3. Check file integrity of critical paths
python3 scripts/file_integrity_monitor.py --check --target /etc \
    --baseline baselines/etc.json --report "$REPORT_DIR/fim_changes.json"

echo "[+] Reports saved to $REPORT_DIR"
```

### Piping Output to Other Tools

```bash
# Parse logs and pipe JSON to jq for specific field extraction
python3 scripts/log_parser.py /var/log/auth.log --json /dev/stdout 2>/dev/null | \
    jq '.alerts.potential_brute_force_ips | keys[]' -r | \
    while read ip; do
        python3 scripts/ip_reputation.py "$ip"
    done
```

### Syslog Integration

Forward script output to syslog:

```bash
python3 scripts/port_monitor.py --target 10.0.0.5 --ports 1-1024 2>&1 | \
    logger -t port_monitor -p local0.warning
```

### SOAR / Webhook Integration

All scripts support JSON output, making them straightforward to integrate with SOAR platforms. Pipe JSON results into `curl` for webhook delivery:

```bash
python3 scripts/ip_reputation.py --file iocs.txt --json /dev/stdout 2>/dev/null | \
    curl -X POST -H "Content-Type: application/json" \
    -d @- https://soar.example.com/api/v1/ingest
```

### Environment Variable Management

Store API keys in a `.env` file and source it before running scripts:

```bash
# .env (do not commit to version control)
export VIRUSTOTAL_API_KEY="your_vt_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

```bash
source .env
python3 scripts/hash_checker.py /path/to/file --check
```

---

## Exit Codes

All scripts follow standard conventions:

| Code | Meaning |
|---|---|
| `0` | Success / no issues found |
| `1` | Changes or issues detected (FIM, parse errors) |
| `2` | CLI argument error |

The non-zero exit code from `file_integrity_monitor.py` when changes are detected is intentional -- it allows shell scripts and CI pipelines to branch on the result.
