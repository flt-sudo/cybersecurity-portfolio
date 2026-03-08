#!/usr/bin/env python3
"""
NIST CSF Compliance Report Generator

Reads the JSON output produced by compliance_checker.py and generates a
professional, GRC-ready Markdown compliance assessment report. Includes:

  - Executive summary with risk posture overview
  - Compliance score dashboard with ASCII bar charts
  - Function-by-function and category-level breakdown
  - Gap analysis with prioritized findings
  - Remediation roadmap with timeline recommendations
  - Maturity level assessment and improvement path

Author: Security Portfolio Project
License: MIT
"""

import json
import argparse
import datetime
import os
import sys
import textwrap


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def bar_chart(value, max_value=100, width=40, fill_char="#", empty_char="-"):
    """Generate an ASCII bar chart string."""
    if value is None:
        return " " * width
    ratio = min(value / max_value, 1.0)
    filled = int(width * ratio)
    return fill_char * filled + empty_char * (width - filled)


def severity_label(score_percent):
    """Return a severity label for a compliance score."""
    if score_percent is None:
        return "N/A"
    if score_percent >= 80:
        return "Strong"
    if score_percent >= 60:
        return "Moderate"
    if score_percent >= 40:
        return "Weak"
    return "Critical"


def wrap_text(text, width=80, indent=""):
    """Wrap long text with optional indentation."""
    return textwrap.fill(text, width=width, initial_indent=indent,
                         subsequent_indent=indent)


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates a professional Markdown compliance report from JSON results."""

    def __init__(self, results_data):
        self.data = results_data
        self.meta = results_data.get("assessment_metadata", {})
        self.overall = results_data.get("overall_score_percent", 0)
        self.tier = results_data.get("maturity_tier", {})
        self.functions = results_data.get("functions", [])
        self.gaps = results_data.get("gaps", [])
        self.summary = results_data.get("summary", {})
        self.generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self):
        """Build the complete report as a Markdown string."""
        sections = [
            self._title_page(),
            self._table_of_contents(),
            self._executive_summary(),
            self._score_dashboard(),
            self._maturity_assessment(),
            self._function_breakdown(),
            self._gap_analysis(),
            self._remediation_roadmap(),
            self._appendix_methodology(),
            self._footer(),
        ]
        return "\n".join(sections)

    # ---- Section generators ---- #

    def _title_page(self):
        org = self.meta.get("organization_name", "Organization")
        date = self.meta.get("assessment_date", "N/A")
        return "\n".join([
            f"# NIST Cybersecurity Framework Compliance Report",
            f"",
            f"## {org}",
            f"",
            f"| | |",
            f"|---|---|",
            f"| **Report Date** | {self.generated_at} |",
            f"| **Assessment Date** | {date} |",
            f"| **Assessor** | {self.meta.get('assessor_name', 'N/A')} |",
            f"| **Scope** | {self.meta.get('scope', 'N/A')} |",
            f"| **Framework** | NIST Cybersecurity Framework (CSF) v1.1 |",
            f"| **Overall Score** | {self.overall}% |",
            f"| **Maturity Tier** | {self.tier.get('tier', 'N/A')} - {self.tier.get('label', 'N/A')} |",
            f"",
            f"**Classification: CONFIDENTIAL**",
            f"",
            f"---",
            f"",
        ])

    def _table_of_contents(self):
        return "\n".join([
            "## Table of Contents",
            "",
            "1. [Executive Summary](#executive-summary)",
            "2. [Compliance Score Dashboard](#compliance-score-dashboard)",
            "3. [Maturity Level Assessment](#maturity-level-assessment)",
            "4. [Function-by-Function Breakdown](#function-by-function-breakdown)",
            "5. [Gap Analysis](#gap-analysis)",
            "6. [Remediation Roadmap](#remediation-roadmap)",
            "7. [Appendix: Methodology](#appendix-methodology)",
            "",
            "---",
            "",
        ])

    def _executive_summary(self):
        s = self.summary
        total_applicable = s.get("applicable_controls", 0)
        compliant = s.get("compliant", 0)
        partial = s.get("partial", 0)
        non_compliant = s.get("non_compliant", 0)
        high_gaps = sum(1 for g in self.gaps if g.get("priority") == "High")
        med_gaps = sum(1 for g in self.gaps if g.get("priority") == "Medium")

        # Determine the weakest function
        weakest = None
        weakest_score = 101
        strongest = None
        strongest_score = -1
        for f in self.functions:
            fp = f.get("score_percent")
            if fp is not None:
                if fp < weakest_score:
                    weakest_score = fp
                    weakest = f
                if fp > strongest_score:
                    strongest_score = fp
                    strongest = f

        lines = [
            "## Executive Summary",
            "",
            f"This report presents the findings of a NIST Cybersecurity Framework (CSF) v1.1 "
            f"compliance assessment conducted for **{self.meta.get('organization_name', 'the organization')}** "
            f"on **{self.meta.get('assessment_date', 'the assessment date')}**.",
            "",
            f"### Key Findings",
            "",
            f"- **Overall compliance score: {self.overall}%** -- classified as "
            f"**{severity_label(self.overall)}** posture.",
            f"- **Maturity tier: {self.tier.get('tier', 'N/A')} ({self.tier.get('label', 'N/A')})** -- "
            f"{self.tier.get('description', '')}",
            f"- **{total_applicable}** controls were assessed, of which **{compliant}** are fully compliant, "
            f"**{partial}** are partially compliant, and **{non_compliant}** are non-compliant.",
            f"- **{len(self.gaps)} gaps** were identified, including **{high_gaps} high-priority** and "
            f"**{med_gaps} medium-priority** findings.",
        ]

        if strongest:
            lines.append(f"- **Strongest function:** {strongest['name']} ({strongest['id']}) at "
                         f"{strongest['score_percent']}%.")
        if weakest:
            lines.append(f"- **Weakest function:** {weakest['name']} ({weakest['id']}) at "
                         f"{weakest['score_percent']}% -- requires immediate attention.")

        lines.extend([
            "",
            "### Risk Posture Overview",
            "",
            "The assessment reveals a security program that has foundational elements in place but ",
            "exhibits significant gaps in several critical areas. The organization demonstrates ",
            "strength in operational security controls but needs improvement in governance, ",
            "recovery planning, and continuous monitoring capabilities.",
            "",
            "### Compliance Distribution",
            "",
            "```",
            f"  Compliant (Yes)      {compliant:3d}  "
            f"[{bar_chart(compliant, total_applicable if total_applicable else 1, 30)}]",
            f"  Partial              {partial:3d}  "
            f"[{bar_chart(partial, total_applicable if total_applicable else 1, 30)}]",
            f"  Non-Compliant (No)   {non_compliant:3d}  "
            f"[{bar_chart(non_compliant, total_applicable if total_applicable else 1, 30)}]",
            "```",
            "",
            "---",
            "",
        ])
        return "\n".join(lines)

    def _score_dashboard(self):
        lines = [
            "## Compliance Score Dashboard",
            "",
            "### Overall Score",
            "",
            "```",
            f"  {self.overall}%  [{bar_chart(self.overall, 100, 50)}]",
            "```",
            "",
            "### Function Scores",
            "",
            "```",
        ]

        for f in self.functions:
            fp = f.get("score_percent", 0)
            rating = severity_label(fp)
            if fp is not None:
                lines.append(
                    f"  {f['name']:10s} ({f['id']:2s})  [{bar_chart(fp, 100, 40)}] {fp:5.1f}%  ({rating})"
                )
            else:
                lines.append(f"  {f['name']:10s} ({f['id']:2s})  [ No Data ]")

        lines.extend([
            "```",
            "",
            "### Category Heat Map",
            "",
            "| Function | Category | Score | Rating |",
            "|----------|----------|-------|--------|",
        ])

        for f in self.functions:
            for cat in f.get("categories", []):
                cs = cat.get("score_percent")
                cs_str = f"{cs}%" if cs is not None else "N/A"
                rating = severity_label(cs)
                lines.append(f"| {f['name']} | {cat['name']} ({cat['id']}) | {cs_str} | {rating} |")

        lines.extend(["", "---", ""])
        return "\n".join(lines)

    def _maturity_assessment(self):
        tier_definitions = [
            ("Tier 4", "Adaptive", "80%+",
             "Risk management is part of organizational culture. Practices are adapted based on "
             "lessons learned and predictive indicators. Real-time continuous monitoring and "
             "automated response capabilities are in place."),
            ("Tier 3", "Repeatable", "60-79%",
             "Formally approved policies and procedures exist, are regularly updated, and address "
             "anticipated cyber events. Risk-informed decisions are consistently applied across "
             "the organization."),
            ("Tier 2", "Risk Informed", "30-59%",
             "Management-approved practices exist but may not be consistently applied across the "
             "organization. Risk awareness is present but processes are not fully formalized or "
             "organization-wide."),
            ("Tier 1", "Partial", "0-29%",
             "Cybersecurity risk management is ad-hoc and reactive. Practices are implemented in "
             "an irregular fashion. Limited organizational awareness of cybersecurity risk."),
        ]

        current = self.tier.get("tier", "N/A")

        lines = [
            "## Maturity Level Assessment",
            "",
            f"**Current Maturity: {current} - {self.tier.get('label', 'N/A')}**",
            "",
            "| Tier | Name | Score Range | Description | Current |",
            "|------|------|-------------|-------------|---------|",
        ]

        for t_name, t_label, t_range, t_desc in tier_definitions:
            marker = "<<<" if t_name == current else ""
            lines.append(f"| {t_name} | {t_label} | {t_range} | {t_desc} | {marker} |")

        # Improvement path
        lines.extend([
            "",
            "### Path to Next Tier",
            "",
        ])

        if current == "Tier 4":
            lines.append("The organization has achieved the highest maturity tier. "
                         "Focus on maintaining this level through continuous improvement, "
                         "advanced threat detection, and predictive analytics.")
        elif current == "Tier 3":
            deficit = 80 - (self.overall or 0)
            lines.append(f"To advance from Tier 3 to **Tier 4 (Adaptive)**, the organization needs "
                         f"to improve by approximately **{deficit:.0f} percentage points**. Key actions:")
            lines.append("")
            lines.append("- Implement predictive cybersecurity analytics and threat modeling")
            lines.append("- Establish automated, real-time response capabilities")
            lines.append("- Embed cybersecurity risk management into organizational culture")
            lines.append("- Develop metrics-driven continuous improvement processes")
        elif current == "Tier 2":
            deficit = 60 - (self.overall or 0)
            lines.append(f"To advance from Tier 2 to **Tier 3 (Repeatable)**, the organization needs "
                         f"to improve by approximately **{deficit:.0f} percentage points**. Key actions:")
            lines.append("")
            lines.append("- Formalize all cybersecurity policies and procedures")
            lines.append("- Implement organization-wide risk management practices")
            lines.append("- Establish regular assessment and update cycles")
            lines.append("- Build dedicated security operations capabilities")
        else:
            deficit = 30 - (self.overall or 0)
            lines.append(f"To advance from Tier 1 to **Tier 2 (Risk Informed)**, the organization needs "
                         f"to improve by approximately **{max(deficit, 0):.0f} percentage points**. Key actions:")
            lines.append("")
            lines.append("- Establish foundational cybersecurity policies")
            lines.append("- Conduct a formal risk assessment")
            lines.append("- Implement basic security controls and monitoring")
            lines.append("- Assign cybersecurity roles and responsibilities")

        lines.extend(["", "---", ""])
        return "\n".join(lines)

    def _function_breakdown(self):
        lines = [
            "## Function-by-Function Breakdown",
            "",
        ]

        for f in self.functions:
            fp = f.get("score_percent", 0)
            rating = severity_label(fp)
            lines.append(f"### {f['name']} ({f['id']}) -- {fp}% ({rating})")
            lines.append("")
            lines.append(f"*{f['description']}*")
            lines.append("")
            lines.append("```")
            lines.append(f"  Score: [{bar_chart(fp, 100, 40)}] {fp}%")
            lines.append("```")
            lines.append("")

            for cat in f.get("categories", []):
                cs = cat.get("score_percent")
                cs_str = f"{cs}%" if cs is not None else "N/A"
                lines.append(f"#### {cat['name']} ({cat['id']}) -- {cs_str}")
                lines.append("")

                controls = cat.get("controls", [])
                if controls:
                    lines.append("| Control | Description | Status | Notes |")
                    lines.append("|---------|-------------|--------|-------|")
                    for ctrl in controls:
                        answer = ctrl.get("answer", "N/A")
                        status_map = {
                            "Yes": "PASS",
                            "Partial": "PARTIAL",
                            "No": "FAIL",
                            "N/A": "N/A",
                        }
                        status = status_map.get(answer, "?")
                        notes = ctrl.get("notes", "")
                        # Truncate long notes for table readability
                        if len(notes) > 100:
                            notes = notes[:97] + "..."
                        lines.append(
                            f"| {ctrl['id']} | {ctrl['description']} | "
                            f"{status} | {notes} |"
                        )
                    lines.append("")
                else:
                    lines.append("*No controls assessed in this category.*")
                    lines.append("")

            lines.extend(["---", ""])

        return "\n".join(lines)

    def _gap_analysis(self):
        lines = [
            "## Gap Analysis",
            "",
        ]

        if not self.gaps:
            lines.append("No compliance gaps were identified in this assessment.")
            lines.extend(["", "---", ""])
            return "\n".join(lines)

        high = [g for g in self.gaps if g.get("priority") == "High"]
        med = [g for g in self.gaps if g.get("priority") == "Medium"]
        low = [g for g in self.gaps if g.get("priority") == "Low"]

        lines.extend([
            f"A total of **{len(self.gaps)} compliance gaps** were identified:",
            "",
            f"- **High Priority:** {len(high)}",
            f"- **Medium Priority:** {len(med)}",
            f"- **Low Priority:** {len(low)}",
            "",
            "### Top Gaps by Priority",
            "",
            "| Rank | Control | Function | Status | Priority | Finding |",
            "|------|---------|----------|--------|----------|---------|",
        ])

        for i, gap in enumerate(self.gaps[:15], 1):
            lines.append(
                f"| {i} | {gap['control_id']} | {gap['function']} | "
                f"{gap['answer']} | {gap['priority']} | {gap['description']} |"
            )

        if len(self.gaps) > 15:
            lines.append(f"| ... | *{len(self.gaps) - 15} additional gaps omitted* "
                         f"| | | | |")

        lines.extend([
            "",
            "### Gap Distribution by Function",
            "",
            "```",
        ])

        func_gap_counts = {}
        for gap in self.gaps:
            func_name = gap.get("function", "Unknown")
            func_gap_counts[func_name] = func_gap_counts.get(func_name, 0) + 1

        max_gaps = max(func_gap_counts.values()) if func_gap_counts else 1
        for func_name, count in func_gap_counts.items():
            bar = bar_chart(count, max_gaps, 25)
            lines.append(f"  {func_name:10s}  [{bar}] {count} gaps")

        lines.extend([
            "```",
            "",
            "### Detailed Gap Findings",
            "",
        ])

        for i, gap in enumerate(self.gaps, 1):
            lines.extend([
                f"#### Finding #{i}: {gap['control_id']} -- {gap['priority']} Priority",
                "",
                f"- **Control:** {gap['description']}",
                f"- **Function:** {gap['function']}",
                f"- **Current Status:** {gap['answer']}",
                f"- **Assessment Question:** {gap['question']}",
            ])
            if gap.get("notes"):
                lines.append(f"- **Assessor Notes:** {gap['notes']}")
            lines.append("")

        lines.extend(["---", ""])
        return "\n".join(lines)

    def _remediation_roadmap(self):
        lines = [
            "## Remediation Roadmap",
            "",
            "The following remediation plan is organized into three phases based on risk priority, "
            "implementation complexity, and potential security impact.",
            "",
        ]

        high = [g for g in self.gaps if g.get("priority") == "High"]
        med = [g for g in self.gaps if g.get("priority") == "Medium"]
        low = [g for g in self.gaps if g.get("priority") == "Low"]

        # Phase 1
        lines.extend([
            "### Phase 1: Immediate Actions (0-90 Days)",
            "",
            "**Objective:** Address high-priority gaps that represent the greatest risk to the organization.",
            "",
        ])
        if high:
            lines.append("| # | Control | Action | Effort Estimate |")
            lines.append("|---|---------|--------|-----------------|")
            for i, g in enumerate(high, 1):
                action = "Implement" if g["answer"] == "No" else "Enhance and formalize"
                effort = "High" if g.get("weight", 0) >= 1.0 else "Medium"
                lines.append(f"| {i} | {g['control_id']} | {action}: {g['description']} | {effort} |")
            lines.append("")
            lines.append(f"**Estimated Resource Requirement:** {len(high) * 40}-{len(high) * 80} person-hours")
        else:
            lines.append("*No high-priority gaps identified.*")
        lines.append("")

        # Phase 2
        lines.extend([
            "### Phase 2: Short-Term Improvements (90-180 Days)",
            "",
            "**Objective:** Strengthen partially implemented controls and address medium-priority gaps.",
            "",
        ])
        if med:
            lines.append("| # | Control | Action | Effort Estimate |")
            lines.append("|---|---------|--------|-----------------|")
            for i, g in enumerate(med, 1):
                action = "Implement" if g["answer"] == "No" else "Enhance and document"
                lines.append(f"| {i} | {g['control_id']} | {action}: {g['description']} | Medium |")
            lines.append("")
            lines.append(f"**Estimated Resource Requirement:** {len(med) * 30}-{len(med) * 60} person-hours")
        else:
            lines.append("*No medium-priority gaps identified.*")
        lines.append("")

        # Phase 3
        lines.extend([
            "### Phase 3: Long-Term Maturity (180-365 Days)",
            "",
            "**Objective:** Build organizational maturity and address remaining gaps to advance to the next tier.",
            "",
        ])
        if low:
            lines.append("| # | Control | Action | Effort Estimate |")
            lines.append("|---|---------|--------|-----------------|")
            for i, g in enumerate(low, 1):
                action = "Implement" if g["answer"] == "No" else "Formalize and document"
                lines.append(f"| {i} | {g['control_id']} | {action}: {g['description']} | Low |")
            lines.append("")
            lines.append(f"**Estimated Resource Requirement:** {len(low) * 20}-{len(low) * 40} person-hours")
        else:
            lines.append("*No low-priority gaps identified.*")

        # Budget estimate
        total_gaps = len(self.gaps)
        lines.extend([
            "",
            "### Resource Summary",
            "",
            f"| Phase | Gaps | Timeline | Est. Hours |",
            f"|-------|------|----------|------------|",
            f"| Phase 1 (Immediate) | {len(high)} | 0-90 days | "
            f"{len(high) * 40}-{len(high) * 80} |",
            f"| Phase 2 (Short-term) | {len(med)} | 90-180 days | "
            f"{len(med) * 30}-{len(med) * 60} |",
            f"| Phase 3 (Long-term) | {len(low)} | 180-365 days | "
            f"{len(low) * 20}-{len(low) * 40} |",
            f"| **Total** | **{total_gaps}** | **12 months** | "
            f"**{total_gaps * 30}-{total_gaps * 60}** |",
            "",
            "### Key Success Metrics",
            "",
            "To track remediation progress, monitor the following KPIs:",
            "",
            "- **Gap closure rate:** Percentage of identified gaps remediated per quarter",
            "- **Overall compliance score:** Target progression toward next maturity tier",
            "- **Mean time to remediate (MTTR):** Average days from gap identification to closure",
            "- **Recurrence rate:** Percentage of previously closed gaps that reopen",
            "- **Assessment coverage:** Percentage of controls assessed in subsequent reviews",
            "",
            "---",
            "",
        ])

        return "\n".join(lines)

    def _appendix_methodology(self):
        return "\n".join([
            "## Appendix: Methodology",
            "",
            "### Assessment Framework",
            "",
            "This assessment was conducted using the **NIST Cybersecurity Framework (CSF) v1.1**, "
            "published by the National Institute of Standards and Technology. The CSF provides a "
            "structured approach for organizations to manage and reduce cybersecurity risk.",
            "",
            "### Scoring Methodology",
            "",
            "Each control was assessed using the following scale:",
            "",
            "| Response | Score | Description |",
            "|----------|-------|-------------|",
            "| Yes | 1.0 | Control is fully implemented and operating effectively |",
            "| Partial | 0.5 | Control is partially implemented or not consistently applied |",
            "| No | 0.0 | Control is not implemented |",
            "| N/A | -- | Control is not applicable to the organization's environment |",
            "",
            "Scores are weighted by control importance and aggregated at the category, function, "
            "and overall levels using weighted averages.",
            "",
            "### Priority Classification",
            "",
            "Gaps are prioritized based on control weight and compliance status:",
            "",
            "- **High:** Non-compliant controls with weight >= 0.9, or partially compliant controls "
            "with weight >= 1.0",
            "- **Medium:** Controls with weight >= 0.7 not classified as High",
            "- **Low:** All remaining gaps",
            "",
            "### Maturity Tiers",
            "",
            "The NIST CSF defines four implementation tiers that describe the degree of rigor "
            "and sophistication of an organization's cybersecurity risk management practices:",
            "",
            "- **Tier 1 (Partial, 0-29%):** Ad-hoc, reactive practices",
            "- **Tier 2 (Risk Informed, 30-59%):** Management-approved but inconsistent practices",
            "- **Tier 3 (Repeatable, 60-79%):** Formally approved and regularly updated practices",
            "- **Tier 4 (Adaptive, 80%+):** Practices adapted based on predictive indicators",
            "",
            "### Limitations",
            "",
            "- This assessment reflects a point-in-time evaluation based on information provided "
            "by the organization.",
            "- Self-assessment responses were not independently validated through technical testing.",
            "- Scores represent compliance posture, not security effectiveness.",
            "- Remediation timelines are estimates and depend on organizational resources and priorities.",
            "",
            "---",
            "",
        ])

    def _footer(self):
        return "\n".join([
            f"*Report generated on {self.generated_at} by NIST CSF Compliance Checker v1.0.0*",
            "",
            f"*This document is classified as CONFIDENTIAL and intended for authorized recipients only.*",
            "",
        ])


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a professional NIST CSF compliance report from assessment results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report from compliance checker JSON output
  %(prog)s --input results.json --output report.md

  # Print report to stdout
  %(prog)s --input results.json --stdout
        """,
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        metavar="FILE",
        help="Path to JSON results file from compliance_checker.py",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="Path to save the Markdown report (default: <input_basename>_report.md)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the report to stdout instead of saving to a file",
    )

    args = parser.parse_args()

    # Load JSON results
    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            results = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in input file: {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate required fields
    required_keys = ["overall_score_percent", "maturity_tier", "functions", "gaps", "summary"]
    missing = [k for k in required_keys if k not in results]
    if missing:
        print(f"Error: Input JSON is missing required fields: {', '.join(missing)}", file=sys.stderr)
        print("Ensure the input was generated by compliance_checker.py.", file=sys.stderr)
        sys.exit(1)

    # Generate report
    generator = ReportGenerator(results)
    report = generator.generate()

    if args.stdout:
        print(report)
        return

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        base = os.path.splitext(os.path.basename(args.input))[0]
        output_path = f"{base}_report.md"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"Report generated: {output_path}")
    print(f"  Overall Score: {results.get('overall_score_percent', 'N/A')}%")
    print(f"  Maturity Tier: {results.get('maturity_tier', {}).get('tier', 'N/A')}")
    print(f"  Gaps Found: {len(results.get('gaps', []))}")


if __name__ == "__main__":
    main()
