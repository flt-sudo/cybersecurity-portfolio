# SIEM Home Lab: Wazuh Deployment on Ubuntu Server

## Overview

This project documents a fully functional SIEM home lab built to develop hands-on experience with threat detection, log analysis, and incident response. The environment uses **Wazuh 4.7** (open-source SIEM/XDR platform) deployed as a single-node installation on Ubuntu Server 22.04 LTS, monitoring a Kali Linux endpoint acting as both an attack surface and adversary simulation host.

The lab was used to generate, detect, triage, and document real security events mapped to the MITRE ATT&CK framework.

## Objectives

- Deploy and configure a production-representative SIEM stack (Wazuh Manager, Indexer, Dashboard)
- Enroll endpoints via the Wazuh agent and configure log collection, file integrity monitoring (FIM), and active response
- Author custom detection rules for SSH brute-force attacks, SQL injection, and cross-site scripting (XSS)
- Simulate adversary techniques, observe resulting telemetry, and perform structured alert triage
- Document findings using SOC-style playbooks and detection logs with MITRE ATT&CK references

## Network Architecture

```
 +==============================================================+
 |                    Home Lab Network (10.0.0.0/24)             |
 |                                                               |
 |   +-------------------------+    +-------------------------+  |
 |   |  WAZUH SERVER           |    |  KALI LINUX ENDPOINT    |  |
 |   |  Ubuntu Server 22.04   |    |  Kali 2024.1            |  |
 |   |  10.0.0.10              |    |  10.0.0.20              |  |
 |   |                         |    |                         |  |
 |   |  Components:            |    |  Components:            |  |
 |   |  - Wazuh Manager 4.7   |    |  - Wazuh Agent 4.7     |  |
 |   |  - Wazuh Indexer        |    |  - Apache 2.4 (target) |  |
 |   |  - Wazuh Dashboard      |    |  - OpenSSH Server      |  |
 |   |  - Filebeat             |    |  - auditd               |  |
 |   |                         |    |                         |  |
 |   |  Ports:                 |    |  Agent -> Manager:     |  |
 |   |  443  - Dashboard UI   |    |  1514/TCP (enrollment)  |  |
 |   |  1514 - Agent comms    |    |  1515/TCP (events)      |  |
 |   |  1515 - Enrollment     |    |                         |  |
 |   |  9200 - Indexer API    |    |                         |  |
 |   +----------+--------------+    +----------+--------------+  |
 |               |                              |                |
 |               +----------+-------------------+                |
 |                          |                                    |
 |                    [Virtual Switch]                           |
 |                     (NAT / Bridge)                            |
 +==============================================================+
                            |
                    +-------+--------+
                    |  HOST MACHINE  |
                    |  VirtualBox /  |
                    |  VMware        |
                    +----------------+
```

## Project Structure

```
01-siem-home-lab/
|-- README.md                          # This file
|-- configs/
|   +-- ossec.conf                     # Wazuh agent configuration (endpoint)
|-- rules/
|   |-- custom-brute-force.xml         # SSH brute-force detection rules
|   +-- custom-web-attacks.xml         # SQL injection and XSS detection rules
|-- docs/
|   |-- setup-guide.md                 # Full installation and configuration walkthrough
|   |-- alert-triage-playbook.md       # SOC-style triage procedures
|   +-- detection-log.md              # Documented detection scenarios with ATT&CK mapping
+-- screenshots/                       # Dashboard and alert screenshots
    |-- wazuh-dashboard-overview.png
    |-- ssh-brute-force-alert.png
    |-- fim-alert-etc-passwd.png
    +-- sqli-detection-alert.png
```

## Key Technical Skills Demonstrated

| Skill Area | Details |
|---|---|
| SIEM Deployment | Single-node Wazuh 4.7 installation (Manager, Indexer, Dashboard) on Ubuntu Server |
| Log Collection | Syslog, auth.log, Apache access/error logs, audit logs via Wazuh agent |
| File Integrity Monitoring | Real-time FIM on /etc, /var/www with syscheck |
| Detection Engineering | Custom XML rules with frequency-based correlation and severity escalation |
| Threat Simulation | SSH brute force (Hydra), SQL injection (sqlmap), XSS payloads, unauthorized file modification |
| Alert Triage | Structured investigation workflow following SOC analyst methodology |
| MITRE ATT&CK | Mapped detections to T1110.001, T1190, T1059.004, T1565.001 |
| Active Response | Configured automatic IP blocking on brute-force threshold via firewall-drop |

## Detection Scenarios Tested

1. **SSH Brute Force** -- Simulated with Hydra; custom rule triggered escalating alerts at 5, 10, and 20 failed attempts. Active response blocked attacker IP after threshold. (MITRE ATT&CK: T1110.001)

2. **SQL Injection via Web Application** -- Sent crafted SQLi payloads against Apache; custom rule matched UNION SELECT, OR 1=1, and other injection patterns in access logs. (MITRE ATT&CK: T1190)

3. **Unauthorized File Modification** -- Modified /etc/passwd and files under /var/www/html; Wazuh FIM (syscheck) generated real-time alerts with file diff, user attribution, and SHA-256 hash comparison. (MITRE ATT&CK: T1565.001)

4. **Suspicious Process Execution** -- Executed netcat reverse shell and base64-encoded commands; Wazuh command monitoring rules detected anomalous process behavior. (MITRE ATT&CK: T1059.004)

## Screenshots

> Note: Screenshots are stored in the `screenshots/` directory. Representative captures include:

- **Wazuh Dashboard Overview** (`screenshots/wazuh-dashboard-overview.png`) -- Main dashboard showing active agents, alert volume, and security event timeline
- **SSH Brute Force Alert** (`screenshots/ssh-brute-force-alert.png`) -- Custom rule 100002 firing after 5+ failed SSH login attempts
- **File Integrity Alert** (`screenshots/fim-alert-etc-passwd.png`) -- Syscheck alert showing modification to /etc/passwd with diff output
- **SQL Injection Detection** (`screenshots/sqli-detection-alert.png`) -- Custom rule 100100 detecting UNION-based SQL injection in Apache access logs

## Lessons Learned

- **Tuning is essential.** The default Wazuh ruleset generates a high volume of low-severity alerts. Writing custom rules with appropriate frequency thresholds and severity levels dramatically reduced noise and improved signal quality.
- **Log source configuration matters.** Missing or misconfigured log paths (e.g., Apache logging to a non-default location) create blind spots. Validating log ingestion immediately after agent enrollment prevents gaps.
- **FIM requires baselining.** File integrity monitoring generates false positives during system updates (apt upgrades, config management). Establishing a known-good baseline and using syscheck's `<ignore>` directive for expected changes is critical.
- **MITRE ATT&CK mapping adds context.** Tagging detections with technique IDs transforms raw alerts into actionable intelligence and demonstrates structured thinking during triage.

## Tools and Technologies

- **Wazuh 4.7** -- SIEM / XDR platform (Manager, Indexer, Dashboard)
- **Ubuntu Server 22.04 LTS** -- Wazuh server host OS
- **Kali Linux 2024.1** -- Monitored endpoint and adversary simulation
- **Apache 2.4** -- Target web server for web attack simulations
- **Hydra** -- SSH brute-force simulation
- **sqlmap** -- Automated SQL injection testing
- **VirtualBox 7.0** -- Virtualization platform
- **MITRE ATT&CK Framework** -- Threat classification and mapping

## References

- [Wazuh Documentation](https://documentation.wazuh.com/current/)
- [Wazuh Ruleset Reference](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [MITRE ATT&CK Matrix](https://attack.mitre.org/)
- [Wazuh Custom Rules Guide](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
