# Phishing Analysis Toolkit

A collection of scripts, playbooks, and reference materials for analyzing suspected phishing emails in a Security Operations Center (SOC) environment. This project demonstrates practical skills in email header forensics, indicator-of-compromise (IOC) extraction, and structured incident response.

## Project Structure

```
02-phishing-analysis/
├── README.md
├── scripts/
│   ├── email_header_analyzer.py   # Parse and analyze raw .eml files
│   └── ioc_extractor.py           # Extract IOCs from arbitrary text
├── samples/
│   └── sample-phishing-email.eml  # Educational phishing email sample
└── docs/
    ├── phishing-analysis-playbook.md  # Step-by-step SOC playbook
    └── common-indicators.md           # Reference guide for phishing indicators
```

## Tools

### Email Header Analyzer

Parses a raw `.eml` file and produces a structured analysis report covering:

- **Envelope information** -- From, To, Subject, Date, Return-Path, Message-ID
- **Mail server hops** -- Ordered list of Received headers showing the path the message took from origin to destination
- **Authentication results** -- SPF, DKIM, and DMARC verdicts extracted from the Authentication-Results header
- **URL extraction** -- Every URL found in the message body (plain text and HTML parts)
- **Attachment analysis** -- File names, MIME types, and SHA-256 hashes for every attachment

```bash
python3 scripts/email_header_analyzer.py samples/sample-phishing-email.eml
python3 scripts/email_header_analyzer.py --json samples/sample-phishing-email.eml
```

### IOC Extractor

Accepts text input (via file or stdin) and extracts, deduplicates, and categorizes indicators of compromise:

- IPv4 addresses
- Domain names
- URLs
- Email addresses
- File hashes (MD5, SHA-1, SHA-256)
- File names with common executable/document extensions

Supports defanging (safe representation) and refanging (operational representation) of indicators.

```bash
# Extract IOCs from a file
python3 scripts/ioc_extractor.py -f report.txt

# Pipe text directly
cat alert.log | python3 scripts/ioc_extractor.py

# Output as JSON or CSV
python3 scripts/ioc_extractor.py -f report.txt --format json
python3 scripts/ioc_extractor.py -f report.txt --format csv -o iocs.csv

# Refang defanged indicators in input
python3 scripts/ioc_extractor.py -f defanged_report.txt --refang

# Defang output for safe sharing
python3 scripts/ioc_extractor.py -f report.txt --defang
```

## Playbook and Reference Material

- **[Phishing Analysis Playbook](docs/phishing-analysis-playbook.md)** -- End-to-end procedure for triaging, analyzing, and responding to a reported phishing email.
- **[Common Phishing Indicators](docs/common-indicators.md)** -- Reference table of red flags with real-world examples, organized by category (header anomalies, content tactics, URL tricks, attachment risks).

## Requirements

- Python 3.8 or later
- Standard library only -- no third-party packages required

## Intended Audience

This toolkit is built for SOC analysts (Tier 1 and Tier 2) who handle phishing reports as part of daily operations. It is also useful as a portfolio demonstration of email forensics and incident response skills.

## Disclaimer

All samples, domains, and indicators included in this project are fictional and intended solely for educational purposes. Do not use these tools against systems or emails without proper authorization.
