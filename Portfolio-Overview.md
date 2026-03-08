# Cybersecurity Portfolio Overview

&nbsp;

---

&nbsp;

## Project 1: SIEM Home Lab (Wazuh)

&nbsp;

This project demonstrates the deployment and operation of a Security Information and Event Management (SIEM) system in a home lab environment. Using Wazuh, an open-source SIEM platform, I built a single-node deployment on Ubuntu Server that monitors a Kali Linux endpoint in real time. The lab ingests logs from authentication systems, syslog, and web server access logs, providing centralized visibility into security events across the environment.

&nbsp;

I wrote custom detection rules targeting specific attack patterns including SSH brute-force attempts, SQL injection in web traffic, and cross-site scripting (XSS) payloads. Each rule uses Wazuh's XML rule syntax with escalating severity levels that trigger at defined thresholds. For example, the brute-force rule fires at severity 5 after three failed logins, escalates to severity 10 after five failures, and reaches severity 12 after ten failures within sixty seconds.

&nbsp;

The project includes an alert triage playbook that documents my process for investigating triggered alerts: verifying the alert source, correlating with other log data, determining true or false positive status, and escalating when necessary. I tested the lab against four real attack scenarios including brute-force authentication, web application attacks, unauthorized file modification, and suspicious process execution. Each scenario is documented with timestamps, investigation steps, findings, and MITRE ATT&CK technique mappings. This project reflects the core daily work of a SOC Analyst: monitoring alerts, triaging events, and documenting findings.

&nbsp;

---

&nbsp;

## Project 2: Phishing Analysis Playbook

&nbsp;

Phishing remains the most common initial attack vector in cybersecurity incidents. This project provides a complete toolkit and methodology for analyzing suspected phishing emails, a task that SOC analysts perform daily. The centerpiece is a Python-based email header analyzer that parses raw .eml files and extracts critical forensic data including sender information, mail server hops from Received headers, and authentication results from SPF, DKIM, and DMARC checks.

&nbsp;

A second Python script focuses on Indicator of Compromise (IOC) extraction. It takes any block of text, such as an email body, log entry, or threat report, and automatically identifies and categorizes IOCs including IPv4 addresses, domains, URLs, email addresses, and file hashes in MD5, SHA1, and SHA256 formats. The script supports defanging and refanging of indicators, a standard practice in threat intelligence sharing to prevent accidental clicks on malicious links.

&nbsp;

The project also includes a step-by-step phishing analysis playbook that mirrors real SOC standard operating procedures. It covers initial triage, header analysis, URL and attachment investigation, threat intelligence lookups, determination criteria for classifying emails as malicious or legitimate, and response actions such as blocking senders and notifying affected users. A reference guide of common phishing indicators rounds out the documentation. Together, these components demonstrate both the technical scripting ability and the analytical methodology that employers expect from a security operations candidate.

&nbsp;

---

&nbsp;

## Project 3: Vulnerability Assessment Report

&nbsp;

This project showcases the full vulnerability assessment lifecycle from scoping through remediation recommendations. I built Python automation around Nmap to streamline the scanning process, supporting multiple scan profiles ranging from quick top-100-port sweeps to comprehensive full-port scans with vulnerability detection scripts. The scanner parses Nmap's XML output to extract open ports, running services, version information, and OS detection results, then assigns severity ratings based on service risk profiles.

&nbsp;

A companion report generator script transforms raw scan data into professional Markdown assessment reports. These reports include an executive summary written for non-technical stakeholders, detailed findings tables sorted by severity with CVSS v3.1 scores, specific remediation recommendations for each finding, and a prioritized remediation roadmap.

&nbsp;

The sample assessment report demonstrates a complete evaluation of a fictional small business network. It documents ten findings ranging from critical to informational severity, including outdated software versions, unnecessary exposed services, weak encryption configurations, and missing security headers. Each finding includes a description of the risk, evidence from the scan, the CVSS score breakdown, and actionable remediation steps. The methodology documentation covers the entire engagement process including pre-engagement authorization, reconnaissance, vulnerability identification, risk analysis, and reporting standards. This project demonstrates that I can not only run security tools but also communicate findings effectively to both technical teams and business leadership.

&nbsp;

---

&nbsp;

## Project 4: Security Automation Scripts

&nbsp;

Automation is essential in modern security operations where analysts face thousands of alerts daily. This project is a collection of five Python tools that automate common SOC tasks, reducing manual effort and response time. Each script is built with Python's standard library to ensure portability across any environment without dependency management.

&nbsp;

The log parser analyzes authentication logs, web server access logs, and syslog entries to detect patterns such as failed login clusters, privilege escalation attempts, and error spikes. The hash checker computes file hashes and queries the VirusTotal API to determine if files are known malware. The port monitor establishes a baseline of open ports on a target system and alerts when new ports appear or existing ones close, indicating potential compromise or unauthorized changes. The IP reputation checker queries the AbuseIPDB API to assess whether source IPs appearing in logs have been reported for malicious activity. The file integrity monitor tracks changes to critical directories by comparing file hashes, permissions, and timestamps against a stored baseline.

&nbsp;

Each script follows consistent design patterns: argparse-based command-line interfaces, structured JSON output for integration with other tools, clear error handling, and detailed help text. The accompanying usage guide provides examples and sample output for every tool. These scripts demonstrate practical Python proficiency applied to real security operations workflows, showing that I can build tools that save analyst time and improve detection capabilities.

&nbsp;

---

&nbsp;

## Project 5: Incident Response Write-ups

&nbsp;

This project documents my understanding of the incident response lifecycle as defined by NIST Special Publication 800-61. It contains three complete IR playbooks covering the most common incident types that SOC teams encounter: malware infections, ransomware attacks, and phishing compromises. Each playbook follows the four-phase NIST framework of Preparation, Detection and Analysis, Containment Eradication and Recovery, and Post-Incident Activity.

&nbsp;

The playbooks go beyond theory by including specific commands, tools, and decision points at each step. For example, the ransomware playbook includes a decision tree for containment prioritization, guidance on variant identification using file extensions and ransom notes, and steps for checking available decryptors before considering other options. The phishing compromise playbook covers critical but often overlooked steps like checking for attacker-created email forwarding rules and auditing OAuth application grants.

&nbsp;

Two detailed scenario write-ups apply these playbooks to simulated incidents. The first documents an SSH brute-force attack detected through SIEM alerts, traced through log analysis, and resolved through account lockout and firewall rules. The second covers a data exfiltration incident discovered through anomalous DNS traffic patterns. Both scenarios include full timelines with timestamps, investigation methodologies, MITRE ATT&CK technique mappings, and lessons learned. A professional incident report template provides the documentation framework used throughout. This project proves I can handle security incidents methodically and document them to a professional standard.

&nbsp;

---

&nbsp;

## Project 6: Network Traffic Analysis

&nbsp;

Understanding network traffic is fundamental to detecting threats that bypass endpoint security controls. This project demonstrates packet-level analysis skills using Wireshark, tcpdump, and custom Python scripts. The centerpiece is a pcap analyzer script that parses packet capture files to generate traffic statistics including top source and destination addresses, port distribution, and protocol breakdown. It also flags suspicious patterns such as port scanning behavior, beaconing at regular intervals that may indicate command-and-control communication, and DNS tunneling indicators based on query length analysis.

&nbsp;

A dedicated DNS analyzer script examines DNS query logs for signs of abuse. It calculates domain name entropy to detect algorithmically generated domains used by malware, identifies unusually long subdomain labels that suggest data exfiltration through DNS tunneling, and flags high-frequency lookups to single domains that may indicate beaconing.

&nbsp;

The project includes comprehensive reference guides for both Wireshark display filters and tcpdump BPF capture filters, organized by threat category. These cover reconnaissance detection, malware traffic identification, data exfiltration patterns, credential theft indicators, and lateral movement signatures. Two analysis write-ups walk through complete investigations: one examining command-and-control beaconing over HTTPS, and another investigating a SYN port scan against a DMZ network. Each write-up includes the specific filters applied, the analytical reasoning at each step, and MITRE ATT&CK mappings for identified techniques.

&nbsp;

---

&nbsp;

## Project 7: NIST Compliance Checker Tool

&nbsp;

Governance, Risk, and Compliance (GRC) is a growing segment of cybersecurity with strong demand for analysts who understand compliance frameworks. This project is a Python-based assessment tool built around the NIST Cybersecurity Framework (CSF), which organizes security controls into five core functions: Identify, Protect, Detect, Respond, and Recover.

&nbsp;

The compliance checker evaluates an organization's security posture against approximately thirty CSF controls through either an interactive questionnaire or a pre-filled JSON input file. Each control is assessed as Compliant, Partially Compliant, Non-Compliant, or Not Applicable. The tool calculates weighted compliance scores per function and overall, then assigns a maturity tier rating from Tier 1 (Partial) through Tier 4 (Adaptive) based on the NIST implementation tier model.

&nbsp;

A report generator transforms assessment results into professional compliance reports featuring ASCII-based score visualizations, function-by-function breakdowns, gap analysis highlighting non-compliant controls, and prioritized remediation recommendations with suggested timelines. The sample report demonstrates a fictional small business assessment scoring sixty-two percent overall, with strong scores in Identify and Protect functions but gaps in Detect and Recover capabilities.

&nbsp;

Supporting documentation explains the NIST CSF framework, implementation tiers, and how this tool maps to real-world GRC assessment workflows. This project demonstrates skills that apply directly to GRC Analyst and Compliance Analyst roles, showing that I can evaluate organizational security against established frameworks and communicate findings to stakeholders through professional deliverables.

&nbsp;

---

&nbsp;

*Portfolio created by flt | flt@ifly.app*
