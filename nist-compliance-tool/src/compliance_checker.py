#!/usr/bin/env python3
"""
NIST Cybersecurity Framework (CSF) Compliance Checker

A command-line tool for assessing organizational compliance against the
NIST Cybersecurity Framework v1.1. Supports interactive assessments and
file-based input, producing structured JSON output and Markdown reports.

Author: Security Portfolio Project
License: MIT
"""

import json
import argparse
import datetime
import os
import sys
from collections import OrderedDict


# ---------------------------------------------------------------------------
# Data model classes
# ---------------------------------------------------------------------------

class Control:
    """Represents a single NIST CSF control (subcategory)."""

    VALID_ANSWERS = {"Yes", "No", "Partial", "N/A"}
    SCORE_MAP = {"Yes": 1.0, "Partial": 0.5, "No": 0.0, "N/A": None}

    def __init__(self, control_id, category, description, question, weight=1.0):
        self.id = control_id
        self.category = category
        self.description = description
        self.question = question
        self.weight = weight
        self.answer = None
        self.notes = ""

    def set_answer(self, answer, notes=""):
        """Set the assessment answer for this control."""
        normalised = answer.strip().title()
        # Handle common aliases
        alias = {"Y": "Yes", "N": "No", "P": "Partial", "Na": "N/A",
                 "N-A": "N/A", "N/A": "N/A", "Yes": "Yes", "No": "No",
                 "Partial": "Partial"}
        normalised = alias.get(normalised, normalised)
        if normalised not in self.VALID_ANSWERS:
            raise ValueError(
                f"Invalid answer '{answer}' for {self.id}. "
                f"Valid options: {', '.join(sorted(self.VALID_ANSWERS))}"
            )
        self.answer = normalised
        self.notes = notes

    @property
    def score(self):
        """Numeric score for this control (None if N/A)."""
        if self.answer is None:
            return None
        return self.SCORE_MAP.get(self.answer)

    @property
    def is_applicable(self):
        return self.answer is not None and self.answer != "N/A"

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "description": self.description,
            "question": self.question,
            "weight": self.weight,
            "answer": self.answer,
            "notes": self.notes,
            "score": self.score,
        }


class Category:
    """Represents a NIST CSF category (e.g., ID.AM, PR.AC)."""

    def __init__(self, category_id, name, description):
        self.id = category_id
        self.name = name
        self.description = description
        self.controls = []

    def add_control(self, control):
        self.controls.append(control)

    @property
    def applicable_controls(self):
        return [c for c in self.controls if c.is_applicable]

    @property
    def score(self):
        """Weighted average score for this category."""
        applicable = self.applicable_controls
        if not applicable:
            return None
        total_weight = sum(c.weight for c in applicable)
        if total_weight == 0:
            return None
        weighted_sum = sum(c.score * c.weight for c in applicable)
        return weighted_sum / total_weight

    @property
    def score_percent(self):
        s = self.score
        return round(s * 100, 1) if s is not None else None

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "score": self.score,
            "score_percent": self.score_percent,
            "controls": [c.to_dict() for c in self.controls],
        }


class Function:
    """Represents a NIST CSF function (Identify, Protect, Detect, Respond, Recover)."""

    def __init__(self, function_id, name, description):
        self.id = function_id
        self.name = name
        self.description = description
        self.categories = OrderedDict()

    def add_category(self, category):
        self.categories[category.id] = category

    def get_category(self, category_id):
        return self.categories.get(category_id)

    @property
    def all_controls(self):
        controls = []
        for cat in self.categories.values():
            controls.extend(cat.controls)
        return controls

    @property
    def applicable_controls(self):
        return [c for c in self.all_controls if c.is_applicable]

    @property
    def score(self):
        """Weighted average score across all categories in this function."""
        applicable = self.applicable_controls
        if not applicable:
            return None
        total_weight = sum(c.weight for c in applicable)
        if total_weight == 0:
            return None
        weighted_sum = sum(c.score * c.weight for c in applicable)
        return weighted_sum / total_weight

    @property
    def score_percent(self):
        s = self.score
        return round(s * 100, 1) if s is not None else None

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "score": self.score,
            "score_percent": self.score_percent,
            "categories": [cat.to_dict() for cat in self.categories.values()],
        }


class Assessment:
    """
    Top-level assessment object. Loads the NIST CSF control structure,
    collects answers (interactively or from file), and produces results.
    """

    TIER_THRESHOLDS = [
        (0.80, "Tier 4", "Adaptive",
         "The organization adapts its cybersecurity practices based on lessons learned and predictive indicators. "
         "Risk management is part of organizational culture."),
        (0.60, "Tier 3", "Repeatable",
         "Formally approved risk management practices are regularly updated based on business requirements "
         "and a changing threat landscape."),
        (0.30, "Tier 2", "Risk Informed",
         "Risk management practices are approved by management but may not be organization-wide. "
         "Cybersecurity awareness exists but is not consistently applied."),
        (0.00, "Tier 1", "Partial",
         "Cybersecurity risk management is ad-hoc and reactive. Limited awareness of cybersecurity risk "
         "at the organizational level."),
    ]

    def __init__(self):
        self.functions = OrderedDict()
        self.metadata = {}
        self._controls_by_id = {}

    # ----- Loading controls from JSON template ----- #

    def load_controls(self, controls_path):
        """Load control definitions from the NIST CSF controls JSON template."""
        if not os.path.isfile(controls_path):
            raise FileNotFoundError(f"Controls file not found: {controls_path}")

        with open(controls_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        for func_data in data.get("functions", []):
            func = Function(func_data["id"], func_data["name"], func_data["description"])

            # Build category lookup
            cat_lookup = {}
            for cat_data in func_data.get("categories", []):
                cat = Category(cat_data["id"], cat_data["name"], cat_data["description"])
                func.add_category(cat)
                cat_lookup[cat_data["id"]] = cat

            # Add controls to their categories
            for ctrl_data in func_data.get("controls", []):
                ctrl = Control(
                    control_id=ctrl_data["id"],
                    category=ctrl_data["category"],
                    description=ctrl_data["description"],
                    question=ctrl_data["question"],
                    weight=ctrl_data.get("weight", 1.0),
                )
                cat = cat_lookup.get(ctrl_data["category"])
                if cat:
                    cat.add_control(ctrl)
                self._controls_by_id[ctrl.id] = ctrl

            self.functions[func.id] = func

    # ----- Input methods ----- #

    def load_answers_from_file(self, input_path):
        """Load assessment answers from a JSON input file."""
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with open(input_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        self.metadata = data.get("assessment_metadata", {})
        responses = data.get("responses", {})

        loaded = 0
        warnings = []
        for ctrl_id, response in responses.items():
            ctrl = self._controls_by_id.get(ctrl_id)
            if ctrl is None:
                warnings.append(f"  Warning: Control '{ctrl_id}' in input file not found in template, skipping.")
                continue

            answer = response if isinstance(response, str) else response.get("answer", "")
            notes = "" if isinstance(response, str) else response.get("notes", "")

            try:
                ctrl.set_answer(answer, notes)
                loaded += 1
            except ValueError as exc:
                warnings.append(f"  Warning: {exc}")

        # Report any controls not covered by input
        unanswered = [cid for cid, c in self._controls_by_id.items() if c.answer is None]

        print(f"Loaded {loaded} responses from {input_path}")
        if warnings:
            for w in warnings:
                print(w, file=sys.stderr)
        if unanswered:
            print(f"  Note: {len(unanswered)} controls have no response and will be excluded from scoring.",
                  file=sys.stderr)

    def run_interactive(self):
        """Run an interactive assessment, prompting for each control."""
        print("=" * 72)
        print("  NIST Cybersecurity Framework (CSF) v1.1 - Interactive Assessment")
        print("=" * 72)
        print()

        # Collect metadata
        self.metadata["organization_name"] = input("Organization name: ").strip() or "Unnamed Organization"
        self.metadata["assessor_name"] = input("Assessor name: ").strip() or "Assessor"
        self.metadata["assessment_date"] = datetime.date.today().isoformat()
        self.metadata["scope"] = input("Assessment scope (brief description): ").strip() or "Full IT environment"
        print()
        print("For each control, enter one of: Yes / No / Partial / N/A")
        print("You may also enter shorthand: Y / N / P / NA")
        print("Press Enter with no input to skip (treated as unanswered).")
        print("-" * 72)

        for func in self.functions.values():
            print(f"\n{'=' * 72}")
            print(f"  FUNCTION: {func.name.upper()} ({func.id})")
            print(f"  {func.description}")
            print(f"{'=' * 72}")

            for cat in func.categories.values():
                print(f"\n  --- {cat.name} ({cat.id}) ---")
                for ctrl in cat.controls:
                    print(f"\n  [{ctrl.id}] {ctrl.question}")
                    while True:
                        raw = input("    Answer [Yes/No/Partial/N-A]: ").strip()
                        if raw == "":
                            print("    (skipped)")
                            break
                        try:
                            notes = input("    Notes (optional): ").strip()
                            ctrl.set_answer(raw, notes)
                            break
                        except ValueError as exc:
                            print(f"    {exc}  Try again.")

        print("\n" + "=" * 72)
        print("  Assessment complete. Calculating results...")
        print("=" * 72)

    # ----- Scoring & maturity ----- #

    @property
    def overall_score(self):
        """Overall weighted compliance score across all functions."""
        all_applicable = []
        for func in self.functions.values():
            all_applicable.extend(func.applicable_controls)
        if not all_applicable:
            return None
        total_weight = sum(c.weight for c in all_applicable)
        if total_weight == 0:
            return None
        weighted_sum = sum(c.score * c.weight for c in all_applicable)
        return weighted_sum / total_weight

    @property
    def overall_score_percent(self):
        s = self.overall_score
        return round(s * 100, 1) if s is not None else None

    @property
    def maturity_tier(self):
        """Determine the implementation tier based on overall score."""
        score = self.overall_score
        if score is None:
            return ("N/A", "N/A", "Insufficient data to determine maturity tier.")
        for threshold, tier, label, desc in self.TIER_THRESHOLDS:
            if score >= threshold:
                return (tier, label, desc)
        return self.TIER_THRESHOLDS[-1][1:]

    @property
    def gaps(self):
        """Return controls that are non-compliant or partially compliant, sorted by weight."""
        gap_list = []
        for func in self.functions.values():
            for ctrl in func.all_controls:
                if ctrl.answer in ("No", "Partial"):
                    gap_list.append({
                        "control_id": ctrl.id,
                        "function": func.name,
                        "description": ctrl.description,
                        "question": ctrl.question,
                        "answer": ctrl.answer,
                        "notes": ctrl.notes,
                        "weight": ctrl.weight,
                        "priority": "High" if ctrl.weight >= 0.9 and ctrl.answer == "No"
                                    else "High" if ctrl.weight >= 1.0 and ctrl.answer == "Partial"
                                    else "Medium" if ctrl.weight >= 0.7
                                    else "Low",
                    })
        # Sort by priority then weight
        priority_order = {"High": 0, "Medium": 1, "Low": 2}
        gap_list.sort(key=lambda g: (priority_order.get(g["priority"], 9), -g["weight"]))
        return gap_list

    # ----- Output ----- #

    def to_dict(self):
        """Serialize the full assessment to a dictionary."""
        tier_name, tier_label, tier_desc = self.maturity_tier
        return {
            "assessment_metadata": {
                **self.metadata,
                "generated_at": datetime.datetime.now().isoformat(),
                "framework": "NIST Cybersecurity Framework (CSF) v1.1",
                "tool_version": "1.0.0",
            },
            "overall_score": self.overall_score,
            "overall_score_percent": self.overall_score_percent,
            "maturity_tier": {
                "tier": tier_name,
                "label": tier_label,
                "description": tier_desc,
            },
            "functions": [f.to_dict() for f in self.functions.values()],
            "gaps": self.gaps,
            "summary": {
                "total_controls": len(self._controls_by_id),
                "answered_controls": sum(1 for c in self._controls_by_id.values() if c.answer is not None),
                "applicable_controls": sum(1 for c in self._controls_by_id.values() if c.is_applicable),
                "compliant": sum(1 for c in self._controls_by_id.values() if c.answer == "Yes"),
                "partial": sum(1 for c in self._controls_by_id.values() if c.answer == "Partial"),
                "non_compliant": sum(1 for c in self._controls_by_id.values() if c.answer == "No"),
                "not_applicable": sum(1 for c in self._controls_by_id.values() if c.answer == "N/A"),
            },
        }

    def save_json(self, output_path):
        """Save assessment results to a JSON file."""
        results = self.to_dict()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"JSON results saved to: {output_path}")
        return output_path

    def generate_markdown_report(self):
        """Generate a Markdown compliance report string."""
        results = self.to_dict()
        meta = results["assessment_metadata"]
        tier = results["maturity_tier"]
        summary = results["summary"]

        lines = []
        lines.append("# NIST CSF Compliance Assessment Report")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Assessment Information")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Organization** | {meta.get('organization_name', 'N/A')} |")
        lines.append(f"| **Assessment Date** | {meta.get('assessment_date', 'N/A')} |")
        lines.append(f"| **Assessor** | {meta.get('assessor_name', 'N/A')} |")
        lines.append(f"| **Scope** | {meta.get('scope', 'N/A')} |")
        lines.append(f"| **Framework** | {meta.get('framework', 'NIST CSF v1.1')} |")
        lines.append(f"| **Report Generated** | {meta.get('generated_at', 'N/A')} |")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        pct = results["overall_score_percent"]
        lines.append(f"The organization achieved an overall compliance score of **{pct}%** "
                      f"against the NIST Cybersecurity Framework v1.1.")
        lines.append(f"This corresponds to **{tier['tier']} - {tier['label']}**.")
        lines.append("")
        lines.append(f"> {tier['description']}")
        lines.append("")
        lines.append(f"**Assessment Coverage:** {summary['answered_controls']} of "
                      f"{summary['total_controls']} controls assessed "
                      f"({summary['applicable_controls']} applicable).")
        lines.append("")
        lines.append(f"| Status | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Compliant (Yes) | {summary['compliant']} |")
        lines.append(f"| Partially Compliant | {summary['partial']} |")
        lines.append(f"| Non-Compliant (No) | {summary['non_compliant']} |")
        lines.append(f"| Not Applicable | {summary['not_applicable']} |")
        lines.append("")

        # Score Dashboard
        lines.append("## Compliance Score Dashboard")
        lines.append("")
        lines.append("```")
        lines.append(f"  Overall Score: {pct}%")
        lines.append("")
        bar_width = 40
        for func_data in results["functions"]:
            fp = func_data["score_percent"]
            if fp is not None:
                filled = int(bar_width * fp / 100)
                bar = "#" * filled + "-" * (bar_width - filled)
                label = f"  {func_data['name']:10s} ({func_data['id']})  [{bar}] {fp}%"
            else:
                label = f"  {func_data['name']:10s} ({func_data['id']})  [ No Data ]"
            lines.append(label)
        lines.append("```")
        lines.append("")

        # Maturity Tier
        lines.append("## Maturity Level Assessment")
        lines.append("")
        lines.append("| Tier | Name | Score Range | Status |")
        lines.append("|------|------|-------------|--------|")
        for threshold, t_name, t_label, _ in self.TIER_THRESHOLDS:
            marker = " << CURRENT" if t_name == tier["tier"] else ""
            pct_label = f"{int(threshold*100)}%+"
            lines.append(f"| {t_name} | {t_label} | {pct_label} | {marker} |")
        lines.append("")

        # Function-by-Function Breakdown
        lines.append("## Function-by-Function Breakdown")
        lines.append("")
        for func_data in results["functions"]:
            fp = func_data["score_percent"]
            lines.append(f"### {func_data['name']} ({func_data['id']}) -- {fp}%")
            lines.append("")
            lines.append(f"*{func_data['description']}*")
            lines.append("")
            lines.append("| Category | Score | Controls |")
            lines.append("|----------|-------|----------|")
            for cat_data in func_data["categories"]:
                cat_score = cat_data["score_percent"]
                cat_score_str = f"{cat_score}%" if cat_score is not None else "N/A"
                ctrl_summary_parts = []
                for ctrl in cat_data["controls"]:
                    status_icon = {"Yes": "PASS", "Partial": "PARTIAL", "No": "FAIL", "N/A": "N/A"}.get(
                        ctrl["answer"], "?")
                    ctrl_summary_parts.append(f"{ctrl['id']}: {status_icon}")
                ctrl_str = ", ".join(ctrl_summary_parts) if ctrl_summary_parts else "No controls"
                lines.append(f"| {cat_data['name']} ({cat_data['id']}) | {cat_score_str} | {ctrl_str} |")
            lines.append("")

        # Gap Analysis
        gaps = results["gaps"]
        lines.append("## Gap Analysis")
        lines.append("")
        if gaps:
            lines.append(f"**{len(gaps)} gaps identified.** The following controls are non-compliant or "
                          f"only partially compliant:")
            lines.append("")
            lines.append("| # | Control | Function | Status | Priority | Description |")
            lines.append("|---|---------|----------|--------|----------|-------------|")
            for i, gap in enumerate(gaps, 1):
                lines.append(f"| {i} | {gap['control_id']} | {gap['function']} | "
                              f"{gap['answer']} | {gap['priority']} | {gap['description']} |")
            lines.append("")

            # Detailed gap notes
            lines.append("### Gap Details and Assessor Notes")
            lines.append("")
            for gap in gaps:
                lines.append(f"**{gap['control_id']}** ({gap['function']} - {gap['answer']}) "
                              f"-- Priority: {gap['priority']}")
                lines.append(f"- *Control:* {gap['description']}")
                if gap["notes"]:
                    lines.append(f"- *Notes:* {gap['notes']}")
                lines.append("")
        else:
            lines.append("No gaps identified. All assessed controls are compliant.")
            lines.append("")

        # Remediation Recommendations
        lines.append("## Prioritized Remediation Recommendations")
        lines.append("")
        high_gaps = [g for g in gaps if g["priority"] == "High"]
        med_gaps = [g for g in gaps if g["priority"] == "Medium"]
        low_gaps = [g for g in gaps if g["priority"] == "Low"]

        if high_gaps:
            lines.append("### Immediate Priority (0-90 Days)")
            lines.append("")
            for g in high_gaps:
                action = "Implement" if g["answer"] == "No" else "Enhance"
                lines.append(f"- **{g['control_id']}**: {action} -- {g['description']}")
            lines.append("")
        if med_gaps:
            lines.append("### Short-Term Priority (90-180 Days)")
            lines.append("")
            for g in med_gaps:
                action = "Implement" if g["answer"] == "No" else "Enhance"
                lines.append(f"- **{g['control_id']}**: {action} -- {g['description']}")
            lines.append("")
        if low_gaps:
            lines.append("### Long-Term Priority (180-365 Days)")
            lines.append("")
            for g in low_gaps:
                action = "Implement" if g["answer"] == "No" else "Enhance"
                lines.append(f"- **{g['control_id']}**: {action} -- {g['description']}")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*Report generated by NIST CSF Compliance Checker v1.0.0*")
        lines.append("")
        return "\n".join(lines)

    def save_markdown_report(self, output_path):
        """Save the Markdown report to a file."""
        report = self.generate_markdown_report()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Markdown report saved to: {output_path}")
        return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def resolve_controls_path(explicit_path=None):
    """Resolve the path to the NIST CSF controls JSON template."""
    if explicit_path and os.path.isfile(explicit_path):
        return explicit_path

    # Try relative to this script's location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "..", "templates", "nist-csf-controls.json"),
        os.path.join(os.getcwd(), "templates", "nist-csf-controls.json"),
        os.path.join(script_dir, "nist-csf-controls.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return os.path.abspath(path)

    return None


def main():
    parser = argparse.ArgumentParser(
        description="NIST Cybersecurity Framework (CSF) v1.1 Compliance Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive assessment
  %(prog)s --interactive

  # File-based assessment
  %(prog)s --input assessment-answers.json --output results.json

  # Generate Markdown report alongside JSON
  %(prog)s --input answers.json --output results.json --report report.md

  # Specify a custom controls template
  %(prog)s --input answers.json --controls custom-controls.json
        """,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run interactive assessment (prompts for each control)",
    )
    mode_group.add_argument(
        "--input",
        metavar="FILE",
        help="Path to JSON file containing assessment answers",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="Path to save JSON results (default: results_<timestamp>.json)",
    )
    parser.add_argument(
        "-r", "--report",
        metavar="FILE",
        default=None,
        help="Path to save Markdown compliance report",
    )
    parser.add_argument(
        "--controls",
        metavar="FILE",
        default=None,
        help="Path to NIST CSF controls template JSON (auto-detected if omitted)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Output JSON results to stdout instead of saving to a file",
    )

    args = parser.parse_args()

    # Resolve controls template path
    controls_path = resolve_controls_path(args.controls)
    if controls_path is None:
        print("Error: Could not locate NIST CSF controls template.", file=sys.stderr)
        print("Provide the path with --controls or ensure templates/nist-csf-controls.json exists.",
              file=sys.stderr)
        sys.exit(1)

    # Build assessment
    assessment = Assessment()
    try:
        assessment.load_controls(controls_path)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Error loading controls: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(assessment._controls_by_id)} controls from {controls_path}")

    # Collect answers
    if args.interactive:
        try:
            assessment.run_interactive()
        except (KeyboardInterrupt, EOFError):
            print("\n\nAssessment interrupted.")
            sys.exit(1)
    else:
        try:
            assessment.load_answers_from_file(args.input)
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
            print(f"Error loading input file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Output results
    results = assessment.to_dict()

    if args.json_only:
        print(json.dumps(results, indent=2, default=str))
        return

    # Save JSON
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"nist_csf_results_{timestamp}.json"

    assessment.save_json(output_path)

    # Save Markdown report
    if args.report:
        assessment.save_markdown_report(args.report)

    # Print summary to console
    print()
    print("=" * 60)
    print("  NIST CSF COMPLIANCE ASSESSMENT - SUMMARY")
    print("=" * 60)
    print()
    pct = results["overall_score_percent"]
    tier = results["maturity_tier"]
    summary = results["summary"]
    print(f"  Overall Compliance Score:  {pct}%")
    print(f"  Maturity Tier:             {tier['tier']} - {tier['label']}")
    print()
    print(f"  Controls Assessed:  {summary['answered_controls']} / {summary['total_controls']}")
    print(f"    Compliant:        {summary['compliant']}")
    print(f"    Partial:          {summary['partial']}")
    print(f"    Non-Compliant:    {summary['non_compliant']}")
    print(f"    Not Applicable:   {summary['not_applicable']}")
    print()

    bar_width = 35
    print("  Function Scores:")
    for func_data in results["functions"]:
        fp = func_data["score_percent"]
        if fp is not None:
            filled = int(bar_width * fp / 100)
            bar = "#" * filled + "-" * (bar_width - filled)
            print(f"    {func_data['name']:10s}  [{bar}] {fp}%")
        else:
            print(f"    {func_data['name']:10s}  [ No Data ]")

    print()
    gap_count = len(results["gaps"])
    if gap_count:
        print(f"  Gaps Identified: {gap_count}")
        high_count = sum(1 for g in results["gaps"] if g["priority"] == "High")
        if high_count:
            print(f"    High Priority: {high_count}")
    else:
        print("  No gaps identified.")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
