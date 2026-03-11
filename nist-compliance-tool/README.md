# NIST CSF Compliance Checker Tool

A command-line tool for conducting NIST Cybersecurity Framework (CSF) v1.1 compliance assessments. Designed for SOC analysts, GRC professionals, and security consultants to perform structured gap assessments, calculate compliance scores, and generate professional remediation reports.

---

## Overview

This tool automates the core workflow of a NIST CSF compliance assessment:

1. **Load Controls** -- Reads the NIST CSF control catalog (5 functions, 23 categories, 43 subcategories) from a structured JSON template.
2. **Collect Responses** -- Gathers compliance responses (Yes / No / Partial / N-A) either interactively via the command line or from a pre-filled JSON input file.
3. **Calculate Scores** -- Computes weighted compliance scores at the control, category, function, and overall levels. Maps the overall score to a NIST implementation tier (Tier 1-4).
4. **Identify Gaps** -- Extracts non-compliant and partially compliant controls, prioritizes them by risk weight, and classifies them as High / Medium / Low priority.
5. **Generate Reports** -- Produces a professional Markdown compliance report with executive summary, score dashboard, gap analysis, and prioritized remediation roadmap.

### NIST CSF Alignment

The tool covers all five NIST CSF core functions:

| Function | ID | Focus Area |
|----------|----|-----------|
| **Identify** | ID | Asset management, risk assessment, governance, supply chain |
| **Protect** | PR | Access control, training, data security, configuration mgmt |
| **Detect** | DE | Continuous monitoring, anomaly detection, detection processes |
| **Respond** | RS | Incident response planning, analysis, containment, lessons learned |
| **Recover** | RC | Recovery planning, improvements, crisis communications |

Each function contains 4-6 control categories with specific assessment questions mapped to real NIST CSF subcategories (e.g., ID.AM-1, PR.AC-3, DE.CM-4).

---

## Structure

```
nist-compliance-tool/
|-- README.md                              # This file
|-- src/
|   |-- compliance_checker.py              # Main assessment engine
|   |-- report_generator.py                # Report generation from JSON results
|-- templates/
|   |-- nist-csf-controls.json             # NIST CSF control catalog
|   |-- sample-assessment-input.json       # Sample input (fictional company)
|-- reports/
|   |-- sample-compliance-report.md        # Sample output report
|-- docs/
|   |-- nist-csf-overview.md               # NIST CSF quick reference guide
```

---

## Requirements

- Python 3.7 or later
- Standard library only -- no external dependencies (uses `json`, `argparse`, `datetime`, `os`, `sys`)

---

## Usage

### Quick Start

Run an assessment using the sample input file:

```bash
# Generate JSON results and Markdown report
python3 src/compliance_checker.py \
  --input templates/sample-assessment-input.json \
  --output reports/results.json \
  --report reports/compliance-report.md
```

### Interactive Mode

Run an interactive assessment that prompts for each control:

```bash
python3 src/compliance_checker.py --interactive --report reports/my-assessment.md
```

The tool will prompt for organization metadata, then walk through each control:

```
======================================================================
  NIST Cybersecurity Framework (CSF) v1.1 - Interactive Assessment
======================================================================

Organization name: Acme Corp
Assessor name: Jane Smith
Assessment scope (brief description): Corporate IT environment

For each control, enter one of: Yes / No / Partial / N/A
----------------------------------------------------------------------

======================================================================
  FUNCTION: IDENTIFY (ID)
  Develop an organizational understanding to manage cybersecurity risk...
======================================================================

  --- Asset Management (ID.AM) ---

  [ID.AM-1] Does the organization maintain a current inventory of all
  physical devices and systems?
    Answer [Yes/No/Partial/N-A]: Partial
    Notes (optional): Spreadsheet-based, not automated
```

### File-Based Mode

Prepare a JSON input file (see `templates/sample-assessment-input.json` for format) and run:

```bash
python3 src/compliance_checker.py \
  --input my-assessment.json \
  --output results.json \
  --report report.md
```

### Generate Report from Existing Results

If you already have JSON results, use the report generator directly:

```bash
python3 src/report_generator.py \
  --input reports/results.json \
  --output reports/detailed-report.md
```

### Output to stdout

Print JSON results to stdout (useful for piping):

```bash
python3 src/compliance_checker.py \
  --input templates/sample-assessment-input.json \
  --json-only
```

---

## CLI Reference

### compliance_checker.py

```
usage: compliance_checker.py [-h] (-i | --input FILE) [-o FILE] [-r FILE]
                             [--controls FILE] [--json-only]

NIST Cybersecurity Framework (CSF) v1.1 Compliance Checker

options:
  -h, --help            show this help message and exit
  -i, --interactive     Run interactive assessment
  --input FILE          Path to JSON input file with assessment answers
  -o, --output FILE     Path to save JSON results
  -r, --report FILE     Path to save Markdown report
  --controls FILE       Path to controls template (auto-detected if omitted)
  --json-only           Output JSON to stdout instead of file
```

### report_generator.py

```
usage: report_generator.py [-h] -i FILE [-o FILE] [--stdout]

Generate a professional NIST CSF compliance report from assessment results.

options:
  -h, --help            show this help message and exit
  -i, --input FILE      Path to JSON results from compliance_checker.py
  -o, --output FILE     Path to save Markdown report
  --stdout              Print report to stdout
```

---

## Input File Format

The assessment input JSON file has two sections:

```json
{
  "assessment_metadata": {
    "organization_name": "Company Name",
    "assessment_date": "2025-11-15",
    "assessor_name": "Assessor Name",
    "scope": "Description of assessment scope",
    "industry": "Industry sector",
    "employee_count": 100
  },
  "responses": {
    "ID.AM-1": {
      "answer": "Yes",
      "notes": "Optional assessor notes and evidence references"
    },
    "ID.AM-2": {
      "answer": "Partial",
      "notes": "Software inventory exists but does not cover SaaS"
    },
    "ID.AM-3": {
      "answer": "No",
      "notes": "No data flow diagrams documented"
    }
  }
}
```

Valid answer values: `Yes`, `No`, `Partial`, `N/A`

---

## Sample Output

### Console Summary

```
============================================================
  NIST CSF COMPLIANCE ASSESSMENT - SUMMARY
============================================================

  Overall Compliance Score:  62.3%
  Maturity Tier:             Tier 3 - Repeatable

  Controls Assessed:  43 / 43
    Compliant:        19
    Partial:          15
    Non-Compliant:    9
    Not Applicable:   0

  Function Scores:
    Identify    [#####################--------------] 60.7%
    Protect     [########################-----------] 70.0%
    Detect      [######################-------------] 62.5%
    Respond     [###########################--------] 78.1%
    Recover     [########---------------------------] 21.5%

  Gaps Identified: 24
    High Priority: 9

============================================================
```

### Report Sections

The generated Markdown report includes:

1. **Title page** with assessment metadata and classification
2. **Executive summary** with key findings, risk posture overview, and compliance distribution chart
3. **Compliance score dashboard** with ASCII bar charts for overall and function-level scores, plus a category heat map
4. **Maturity level assessment** with current tier, tier definitions, and path to next tier
5. **Function-by-function breakdown** with category scores and individual control pass/fail status
6. **Gap analysis** with prioritized findings table, distribution by function, and detailed finding descriptions with assessor notes
7. **Remediation roadmap** organized into three phases (0-90 days, 90-180 days, 180-365 days) with effort estimates and resource summary
8. **Methodology appendix** explaining the scoring system, priority classification, and limitations

See `reports/sample-compliance-report.md` for a complete example.

---

## Scoring Methodology

### Control Scoring

| Response | Score | Description |
|----------|-------|-------------|
| Yes | 1.0 | Fully implemented and operating effectively |
| Partial | 0.5 | Partially implemented or inconsistently applied |
| No | 0.0 | Not implemented |
| N/A | -- | Not applicable (excluded from scoring) |

### Aggregation

Scores are aggregated using weighted averages:
- **Category score** = weighted average of applicable controls in that category
- **Function score** = weighted average of applicable controls across all categories in that function
- **Overall score** = weighted average of all applicable controls

### Maturity Tiers

| Tier | Name | Score Range | Description |
|------|------|-------------|-------------|
| Tier 1 | Partial | 0-29% | Ad-hoc, reactive practices |
| Tier 2 | Risk Informed | 30-59% | Management-approved but inconsistent |
| Tier 3 | Repeatable | 60-79% | Formally approved and regularly updated |
| Tier 4 | Adaptive | 80%+ | Adaptive, predictive, culturally embedded |

### Gap Priority

| Priority | Criteria |
|----------|----------|
| High | Non-compliant (No) with weight >= 0.9, or Partial with weight >= 1.0 |
| Medium | Weight >= 0.7 and not classified as High |
| Low | All remaining gaps |

---

## Customization

### Custom Controls Template

Create your own controls template to assess against a tailored control set:

```json
{
  "framework": "Custom Framework",
  "version": "1.0",
  "functions": [
    {
      "id": "FUNC1",
      "name": "Function Name",
      "description": "Function description",
      "categories": [
        {
          "id": "FUNC1.CAT1",
          "name": "Category Name",
          "description": "Category description"
        }
      ],
      "controls": [
        {
          "id": "FUNC1.CAT1-1",
          "category": "FUNC1.CAT1",
          "description": "Control description",
          "question": "Assessment question?",
          "weight": 1.0
        }
      ]
    }
  ]
}
```

Use the `--controls` flag to specify your custom template:

```bash
python3 src/compliance_checker.py --input answers.json --controls my-controls.json
```

---

## Architecture

The tool is built with clean object-oriented design:

```
Assessment
  |-- Functions (Identify, Protect, Detect, Respond, Recover)
       |-- Categories (ID.AM, PR.AC, DE.CM, ...)
            |-- Controls (ID.AM-1, PR.AC-3, DE.CM-4, ...)
                 |-- answer, notes, weight, score
```

**Key classes:**

- `Control` -- Represents a single NIST CSF subcategory with answer, notes, weight, and scoring logic
- `Category` -- Aggregates controls and computes category-level weighted scores
- `Function` -- Aggregates categories and computes function-level weighted scores
- `Assessment` -- Top-level orchestrator: loads controls, collects answers, computes results, generates output
- `ReportGenerator` -- Takes JSON results and produces a formatted Markdown report with all sections

---

## Use Cases

- **Self-assessment:** Small and mid-size organizations conducting internal NIST CSF gap assessments
- **Consulting engagements:** GRC consultants performing compliance assessments for clients
- **Baseline measurement:** Establishing an initial compliance baseline before implementing a security program
- **Progress tracking:** Running periodic assessments to measure compliance improvement over time

---

## License

MIT License. This tool is provided for educational and professional development purposes.

---

## Further Reading

- See `docs/nist-csf-overview.md` for a comprehensive NIST CSF quick reference guide
- See `reports/sample-compliance-report.md` for a complete sample assessment report
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
