"""
Report generator exporting human-readable and machine-parseable audit reports.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
from src.schemas import Decision


class VerificationReportGenerator:
    """Produces explainable audit and verification reports."""

    @staticmethod
    def generate_json_report(decisions: List[Decision]) -> str:
        """Exports decision audit list as formatted JSON."""
        return json.dumps([d.model_dump() for d in decisions], indent=2)

    @staticmethod
    def generate_markdown_summary(decision: Decision) -> str:
        """Formats a single verification decision as an operator-friendly markdown summary."""
        verdict_badge = {
            "ACCEPT": "[ ACCEPT: PASSED ]",
            "REJECT": "[ REJECT: THREAT DETECTED ]",
            "ESCALATE": "[ ESCALATE: MANUAL REVIEW REQUIRED ]",
        }.get(decision.verdict.value, decision.verdict.value)

        lines = [
            f"# Verification Event: {decision.decision_id}",
            f"**Verdict**: {verdict_badge}",
            f"**Timestamp**: {decision.timestamp:.4f}",
            f"**Target Message ID**: `{decision.message_id}`",
            f"**Target Signature ID**: `{decision.signature_id}`",
            f"**Policy Version**: `{decision.policy_version}`",
            f"**Event Hash (SHA-256)**: `{decision.event_hash}`",
            f"**Previous Event Hash**: `{decision.previous_event_hash}`",
            "",
            "## Primary Findings & Reasons",
        ]
        for reason in decision.reasons:
            lines.append(f"- {reason}")

        if decision.failed_checks:
            lines.append("\n## Failed Checks")
            for fc in decision.failed_checks:
                lines.append(f"- `[FAILED]` {fc}")

        if decision.statistics:
            lines.append("\n## Observed Quantum Statistics")
            for k, v in decision.statistics.items():
                if isinstance(v, float):
                    lines.append(f"- **{k}**: `{v:.5f}`")
                else:
                    lines.append(f"- **{k}**: `{v}`")

        return "\n".join(lines)
