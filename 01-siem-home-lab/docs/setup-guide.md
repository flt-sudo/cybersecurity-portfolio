# Wazuh SIEM Home Lab: Setup Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Wazuh Server Installation (Single-Node)](#wazuh-server-installation-single-node)
3. [Wazuh Agent Installation (Kali Linux Endpoint)](#wazuh-agent-installation-kali-linux-endpoint)
4. [Agent Enrollment](#agent-enrollment)
5. [Dashboard Access and Verification](#dashboard-access-and-verification)
6. [Post-Installation Configuration](#post-installation-configuration)
7. [Custom Rule Deployment](#custom-rule-deployment)
8. [Validation and Testing](#validation-and-testing)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU (Host) | 4 cores | 6+ cores |
| RAM (Host) | 8 GB | 16 GB |
| Disk (Host) | 50 GB free | 100 GB free |
| Wazuh Server VM | 2 vCPU, 4 GB RAM, 30 GB disk | 4 vCPU, 8 GB RAM, 50 GB disk |
| Kali VM | 2 vCPU, 2 GB RAM, 20 GB disk | 2 vCPU, 4 GB RAM, 30 GB disk |

### Software Requirements

- VirtualBox 7.0+ or VMware Workstation/Player
- Ubuntu Server 22.04 LTS ISO
- Kali Linux 2024.1 ISO
- Internet access for package downloads during installation

### Network Configuration

Both VMs should be on the same virtual network:
- **Network mode:** NAT Network or Internal Network with outbound NAT
- **Subnet:** 10.0.0.0/24
- **Wazuh Server:** 10.0.0.10 (static)
- **Kali Endpoint:** 10.0.0.20 (static)

Set static IPs on Ubuntu Server by editing the Netplan configuration:

```yaml
# /etc/netplan/00-installer-config.yaml (Wazuh Server)
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      addresses:
        - 10.0.0.10/24
      routes:
        - to: default
          via: 10.0.0.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```

Apply the configuration:

```bash
sudo netplan apply
```

---

## Wazuh Server Installation (Single-Node)

The single-node deployment installs all three Wazuh components (Manager, Indexer, Dashboard) on one host. This is suitable for lab environments and small deployments.

### Step 1: System Preparation

```bash
# Update the system
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install -y curl apt-transport-https unzip wget

# Set the hostname
sudo hostnamectl set-hostname wazuh-server

# Add the hostname to /etc/hosts
echo "10.0.0.10 wazuh-server" | sudo tee -a /etc/hosts

# Verify system time is accurate (important for log correlation)
timedatectl
sudo timedatectl set-timezone America/New_York
```

### Step 2: Run the Wazuh Installation Assistant

Wazuh provides an automated installation script for single-node deployments. This installs and configures the Indexer, Manager, and Dashboard.

```bash
# Download the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Download the configuration file
curl -sO https://packages.wazuh.com/4.7/config.yml
```

### Step 3: Edit the Configuration File

```yaml
# config.yml
nodes:
  indexer:
    - name: node-1
      ip: 10.0.0.10

  server:
    - name: wazuh-1
      ip: 10.0.0.10

  dashboard:
    - name: dashboard
      ip: 10.0.0.10
```

### Step 4: Run the Installer

```bash
# Run the installation (this takes 10-15 minutes)
sudo bash wazuh-install.sh -a

# The installer will output the admin credentials at the end.
# SAVE THESE CREDENTIALS. Example output:
#
#   User: admin
#   Password: S3cur3P@ssw0rd*
#
# You will need these to access the Wazuh Dashboard.
```

### Step 5: Verify All Services Are Running

```bash
# Check Wazuh Manager status
sudo systemctl status wazuh-manager

# Check Wazuh Indexer status
sudo systemctl status wazuh-indexer

# Check Wazuh Dashboard status
sudo systemctl status wazuh-dashboard

# Check Filebeat status (ships alerts from Manager to Indexer)
sudo systemctl status filebeat
```

All four services should show `active (running)`.

### Step 6: Configure the Firewall

```bash
# Allow agent communication
sudo ufw allow 1514/tcp   # Agent event transport
sudo ufw allow 1515/tcp   # Agent enrollment
sudo ufw allow 443/tcp    # Dashboard web UI
sudo ufw allow 9200/tcp   # Indexer API (restrict in production)
sudo ufw allow 55000/tcp  # Wazuh API

sudo ufw enable
sudo ufw status
```

---

## Wazuh Agent Installation (Kali Linux Endpoint)

### Step 1: Prepare the Endpoint

```bash
# Update the system
sudo apt update && sudo apt upgrade -y

# Set static IP (Kali uses NetworkManager by default)
sudo nmcli con mod "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 10.0.0.20/24 \
  ipv4.gateway 10.0.0.1 \
  ipv4.dns "8.8.8.8 8.8.4.4"

sudo nmcli con up "Wired connection 1"

# Verify connectivity to the Wazuh server
ping -c 4 10.0.0.10
```

### Step 2: Install the Wazuh Agent

```bash
# Import the Wazuh GPG key
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
  chmod 644 /usr/share/keyrings/wazuh.gpg

# Add the Wazuh repository
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

# Install the agent, specifying the manager IP
sudo WAZUH_MANAGER="10.0.0.10" apt install -y wazuh-agent
```

### Step 3: Install Target Services for Monitoring

```bash
# Install Apache (target web server for attack simulation)
sudo apt install -y apache2
sudo systemctl enable apache2
sudo systemctl start apache2

# Install and enable OpenSSH server
sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# Install auditd for detailed system call logging
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd
```

---

## Agent Enrollment

### Method 1: Automatic Enrollment (Recommended)

If `WAZUH_MANAGER` was set during installation, the agent auto-enrolls on first start:

```bash
# Start the agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Verify the agent is connected
sudo /var/ossec/bin/wazuh-control status
```

Expected output:

```
wazuh-agentd is running...
wazuh-logcollector is running...
wazuh-syscheckd is running...
wazuh-modulesd is running...
```

### Method 2: Manual Enrollment with Agent Key

On the **Wazuh Server**:

```bash
# Add the agent
sudo /var/ossec/bin/manage_agents -a 10.0.0.20 -n kali-endpoint

# Extract the key
sudo /var/ossec/bin/manage_agents -e <AGENT_ID>
# Copy the output key string
```

On the **Kali Endpoint**:

```bash
# Import the key
sudo /var/ossec/bin/manage_agents -i <PASTE_KEY_HERE>

# Restart the agent
sudo systemctl restart wazuh-agent
```

### Verify Enrollment on the Server

```bash
# On the Wazuh Server, list connected agents
sudo /var/ossec/bin/manage_agents -l

# Expected output:
# Available agents:
#    ID: 001, Name: kali-endpoint, IP: 10.0.0.20, Active
```

---

## Dashboard Access and Verification

### Step 1: Access the Dashboard

Open a browser on your host machine and navigate to:

```
https://10.0.0.10:443
```

Accept the self-signed certificate warning. Log in with the admin credentials provided during installation.

### Step 2: Verify Agent Visibility

1. Navigate to **Agents** in the left sidebar
2. Confirm the Kali endpoint (001 - kali-endpoint) appears with a **green "Active"** status
3. Click the agent to view its details: OS, IP, agent version, last keep-alive timestamp

### Step 3: Verify Log Ingestion

1. Navigate to **Modules > Security Events**
2. Set the time range to the last 15 minutes
3. Confirm events are flowing in from the Kali endpoint
4. Common initial events include:
   - Rule 502: Ossec server started
   - Rule 503: Agent started / connected
   - Rule 550: File integrity monitoring started

### Step 4: Explore Key Dashboard Sections

| Section | Purpose |
|---|---|
| Security Events | All triggered rules and alerts |
| Integrity Monitoring | FIM events (file changes, new files, deletions) |
| Vulnerabilities | CVE detection on monitored endpoints |
| MITRE ATT&CK | Alerts mapped to ATT&CK techniques |
| Agents | Agent status, OS info, last activity |

---

## Post-Installation Configuration

### Configure the Agent (ossec.conf)

The agent configuration file at `/var/ossec/etc/ossec.conf` on the Kali endpoint controls which logs are collected and what is monitored. See `configs/ossec.conf` in this repository for the full configuration used in this lab.

Key configuration areas:

```bash
# Edit the agent configuration
sudo nano /var/ossec/etc/ossec.conf

# After making changes, restart the agent
sudo systemctl restart wazuh-agent
```

### Enable File Integrity Monitoring

In the agent `ossec.conf`, the `<syscheck>` block defines FIM targets:

```xml
<syscheck>
  <frequency>300</frequency>
  <directories realtime="yes" check_all="yes">/etc</directories>
  <directories realtime="yes" check_all="yes">/var/www</directories>
</syscheck>
```

### Enable Active Response (Server-Side)

On the **Wazuh Server**, edit `/var/ossec/etc/ossec.conf` to enable automatic IP blocking:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100003</rules_id>
  <timeout>600</timeout>
</active-response>
```

This blocks the source IP for 600 seconds (10 minutes) when custom rule 100003 (SSH brute-force high severity) fires.

---

## Custom Rule Deployment

### Step 1: Copy Custom Rules to the Server

Custom rules must be placed on the **Wazuh Server** in the local rules directory:

```bash
# On the Wazuh Server
sudo cp custom-brute-force.xml /var/ossec/etc/rules/custom-brute-force.xml
sudo cp custom-web-attacks.xml /var/ossec/etc/rules/custom-web-attacks.xml

# Set correct ownership and permissions
sudo chown wazuh:wazuh /var/ossec/etc/rules/custom-*.xml
sudo chmod 640 /var/ossec/etc/rules/custom-*.xml
```

### Step 2: Validate the Rules

```bash
# Test the ruleset for syntax errors
sudo /var/ossec/bin/wazuh-logtest

# In the logtest shell, paste a sample log line to verify rule matching:
# Example input:
# Mar  5 14:23:01 kali sshd[4521]: Failed password for root from 10.0.0.50 port 44312 ssh2

# Expected output should show the rule ID and severity level
```

### Step 3: Restart the Manager

```bash
sudo systemctl restart wazuh-manager

# Verify the manager is running without errors
sudo systemctl status wazuh-manager
sudo tail -20 /var/ossec/logs/ossec.log
```

---

## Validation and Testing

### Test 1: SSH Brute Force Detection

```bash
# From the Kali endpoint (or another host), attempt multiple failed SSH logins
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.20 -t 4 -f -V

# Or manually:
for i in $(seq 1 10); do
  sshpass -p 'wrongpassword' ssh root@10.0.0.20 2>/dev/null
done
```

Check the Wazuh Dashboard under Security Events for alerts from rules 100001, 100002, 100003.

### Test 2: File Integrity Monitoring

```bash
# On the Kali endpoint, modify a monitored file
echo "testuser:x:1001:1001::/home/testuser:/bin/bash" | sudo tee -a /etc/passwd

# Wait up to 5 minutes (or the configured syscheck frequency)
# Check the Dashboard under Integrity Monitoring for the change
```

### Test 3: SQL Injection Detection

```bash
# Send a crafted SQLi request to Apache
curl "http://10.0.0.20/index.html?id=1'+UNION+SELECT+username,password+FROM+users--"

# Check the Dashboard for web attack alerts (rule 100100-100105)
```

### Test 4: Verify Active Response

After the SSH brute-force threshold is reached, verify the attacker IP was blocked:

```bash
# On the Kali endpoint, check iptables
sudo iptables -L INPUT -n | grep DROP
```

---

## Troubleshooting

### Agent Not Connecting

```bash
# On the agent, check the log
sudo tail -50 /var/ossec/logs/ossec.log

# Common issues:
# - Firewall blocking port 1514/1515 on the server
# - Incorrect WAZUH_MANAGER IP in ossec.conf
# - Time skew between agent and server (check with 'date' on both)
```

### No Events Appearing in Dashboard

```bash
# On the server, check Filebeat is shipping events
sudo filebeat test output

# Check the Indexer is receiving data
curl -k -u admin:PASSWORD https://10.0.0.10:9200/_cat/indices?v

# Look for wazuh-alerts-* indices with non-zero doc counts
```

### Custom Rules Not Firing

```bash
# Validate rule syntax
sudo /var/ossec/bin/wazuh-logtest
# Paste the exact log line that should trigger the rule

# Check that the rule file is loaded
sudo grep -r "custom-brute-force" /var/ossec/logs/ossec.log

# Ensure rule IDs do not conflict with existing rules (use 100000+)
```

### Syscheck (FIM) Not Generating Alerts

```bash
# Force a syscheck scan
sudo /var/ossec/bin/wazuh-control restart

# Verify syscheck is scanning the expected directories
sudo /var/ossec/bin/agent_control -r -u 001

# Check that the directories are listed in ossec.conf <syscheck> block
grep -A 10 "<syscheck>" /var/ossec/etc/ossec.conf
```

---

## References

- [Wazuh 4.7 Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Wazuh Agent Enrollment](https://documentation.wazuh.com/current/user-manual/agent-enrollment/index.html)
- [Wazuh Syscheck Configuration](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
