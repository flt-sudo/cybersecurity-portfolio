# Security Automation Toolkit

A collection of Python-based security automation scripts designed for SOC analysts, incident responders, and security engineers. Every script uses only the Python standard library -- no external dependencies required -- making them easy to deploy on any system with Python 3.8+.

## Overview

| Script | Purpose | Key Capability |
|---|---|---|
| `log_parser.py` | Multi-format log analysis | Parses auth.log, Apache/Nginx access logs, and syslog; detects brute-force, privilege escalation, error spikes |
| `hash_checker.py` | File hash computation and reputation lookup | Computes MD5/SHA1/SHA256, queries VirusTotal API or checks offline known-bad list |
| `port_monitor.py` | Network port state change detection | Baselines open ports and alerts on new/closed ports over time |
| `ip_reputation.py` | IP address threat intelligence | Queries AbuseIPDB API or local threat feeds; bulk lookups with CSV output |
| `file_integrity_monitor.py` | File integrity monitoring (FIM) | Baselines file hashes, permissions, and timestamps; detects unauthorized changes |

## Structure

```
security-automation/
├── README.md                       # This file
├── scripts/
│   ├── log_parser.py               # Multi-format security log analyzer
│   ├── hash_checker.py             # File hash calculator & reputation checker
│   ├── port_monitor.py             # Port state change monitor
│   ├── ip_reputation.py            # IP reputation & threat intel lookup
│   └── file_integrity_monitor.py   # File integrity monitor (FIM)
├── docs/
│   └── usage-guide.md              # Detailed usage examples and sample output
└── logs/
    └── sample-auth.log             # Realistic sample log for testing log_parser.py
```

## Quick Start

All scripts include built-in help via `--help`:

```bash
python3 scripts/log_parser.py --help
python3 scripts/hash_checker.py --help
python3 scripts/port_monitor.py --help
python3 scripts/ip_reputation.py --help
python3 scripts/file_integrity_monitor.py --help
```

### 1. Analyze Security Logs

Parse an auth.log file and generate a summary report with brute-force detection:

```bash
python3 scripts/log_parser.py logs/sample-auth.log
```

Filter by time range and export JSON:

```bash
python3 scripts/log_parser.py /var/log/auth.log \
    --start "2026-03-01" --end "2026-03-05" \
    --json report.json
```

### 2. Check File Hashes

Compute hashes for a suspicious file:

```bash
python3 scripts/hash_checker.py /path/to/suspicious_binary
```

Check against VirusTotal (requires free API key):

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
python3 scripts/hash_checker.py /path/to/file --check
```

Offline mode with a local known-bad hash list:

```bash
python3 scripts/hash_checker.py /path/to/file --check --bad-hashes known_bad_hashes.txt
```

### 3. Monitor Port Changes

Baseline a host and detect new services:

```bash
# Initial baseline
python3 scripts/port_monitor.py --target 192.168.1.1 --ports 1-1024

# Subsequent check (compares to baseline)
python3 scripts/port_monitor.py --target 192.168.1.1 --ports 1-1024

# Continuous monitoring every 5 minutes
python3 scripts/port_monitor.py --target 192.168.1.1 --ports 1-1024 --monitor --interval 300
```

### 4. IP Reputation Lookup

Check a single IP against AbuseIPDB:

```bash
export ABUSEIPDB_API_KEY="your_key_here"
python3 scripts/ip_reputation.py 185.220.101.1
```

Bulk check from a file with CSV output:

```bash
python3 scripts/ip_reputation.py --file suspicious_ips.txt --csv results.csv
```

Offline mode using local threat feeds:

```bash
python3 scripts/ip_reputation.py --file ips.txt --feed blocklist.txt --feed threat_intel.csv
```

### 5. File Integrity Monitoring

Create a baseline and detect changes:

```bash
# Create baseline
python3 scripts/file_integrity_monitor.py --init --target /etc --baseline etc_baseline.json

# Check for changes
python3 scripts/file_integrity_monitor.py --check --target /etc --baseline etc_baseline.json

# Check and update baseline
python3 scripts/file_integrity_monitor.py --update --target /etc --baseline etc_baseline.json --report changes.json
```

## API Keys

Some scripts integrate with external threat intelligence APIs. These are optional -- each script includes offline fallback modes.

| Service | Environment Variable | Free Tier |
|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | 500 lookups/day |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1,000 lookups/day |

## Use Cases

- **Incident Response**: Rapidly triage log files, check IOC hashes, and validate IP reputation during an active investigation.
- **Threat Hunting**: Identify brute-force patterns, detect unauthorized port openings, and flag modified system files.
- **Compliance Monitoring**: Maintain file integrity baselines for critical configuration directories (`/etc`, web roots).
- **SOC Automation**: Integrate scripts into SOAR playbooks or cron jobs for continuous monitoring and alerting.

## Requirements

- Python 3.8 or later
- No third-party packages (standard library only)
- Network access for API-based lookups (optional)
- Appropriate file system permissions for log reading and FIM scanning

## License

MIT License.
