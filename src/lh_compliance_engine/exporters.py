# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        src.lh_compliance_engine.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Exporters for regulatory compliance audit reports in table, JSON, and SARIF v2.1.0 formats.

Provides terminal presentation via Rich, machine-readable structured JSON,
and OASIS SARIF v2.1.0 output for CI/CD, governance pipelines, and compliance dashboards.
"""

from __future__ import annotations

import io
import json
from enum import StrEnum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_compliance_engine.models import (
    RULES_REGISTRY,
    ComplianceFinding,
    ComplianceReport,
    ComplianceStatus,
    FindingSeverity,
)

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"


class OutputFormat(StrEnum):
    """Supported output formats for compliance posture reports."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def _severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF rule level."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "error"
    if severity == FindingSeverity.MEDIUM:
        return "warning"
    return "note"


def _get_severity_badge(severity: FindingSeverity) -> Text:
    """Return styled Rich Text badge for finding severity."""
    if severity == FindingSeverity.CRITICAL:
        return Text("CRITICAL", style="bold white on red")
    if severity == FindingSeverity.HIGH:
        return Text("HIGH", style="bold red")
    if severity == FindingSeverity.MEDIUM:
        return Text("MEDIUM", style="bold yellow")
    if severity == FindingSeverity.LOW:
        return Text("LOW", style="bold cyan")
    return Text(severity.value, style="bold")


def _get_status_badge(status_str: str) -> Text:
    """Return styled Rich Text badge for compliance status."""
    if status_str == ComplianceStatus.COMPLIANT.value:
        return Text("COMPLIANT", style="bold green")
    if status_str == ComplianceStatus.NON_COMPLIANT.value:
        return Text("NON-COMPLIANT", style="bold red")
    return Text(status_str, style="dim")


def render_table_report(report: ComplianceReport, console: Console | None = None) -> str:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render complete ComplianceReport to terminal or capture to string."""
    report.compute_summary()
    string_io = io.StringIO()
    target_console = console or Console(file=string_io, color_system="auto", width=120)

    title = "lh-compliance-engine: Regulatory Compliance & Governance Posture Audit"
    subtitle = f"Generated at {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    target_console.print(
        Panel(
            Text(f"{title}\n{subtitle}", justify="center", style="bold cyan"),
            border_style="cyan",
        )
    )

    # 1. Executive Summary Table
    summary = report.summary
    summary_table = Table(title="Compliance Audit Executive Summary", border_style="blue")
    summary_table.add_column("Targets", justify="right")
    summary_table.add_column("Reports Ingested", justify="right")
    summary_table.add_column("Raw Findings", justify="right")
    summary_table.add_column("Control Violations", justify="right")
    summary_table.add_column("Critical", justify="right")
    summary_table.add_column("High", justify="right")
    summary_table.add_column("Medium", justify="right")
    summary_table.add_column("Low", justify="right")

    crit_style = "bold red" if summary.get("critical", 0) > 0 else "dim"
    high_style = "bold red" if summary.get("high", 0) > 0 else "dim"
    med_style = "bold yellow" if summary.get("medium", 0) > 0 else "dim"
    low_style = "bold cyan" if summary.get("low", 0) > 0 else "dim"

    summary_table.add_row(
        str(summary.get("total_targets", 0)),
        str(summary.get("reports_ingested", 0)),
        str(summary.get("raw_findings_ingested", 0)),
        str(summary.get("total_compliance_findings", 0)),
        f"[{crit_style}]{summary.get('critical', 0)}[/{crit_style}]",
        f"[{high_style}]{summary.get('high', 0)}[/{high_style}]",
        f"[{med_style}]{summary.get('medium', 0)}[/{med_style}]",
        f"[{low_style}]{summary.get('low', 0)}[/{low_style}]",
    )
    target_console.print(summary_table)

    # 2. Regulatory Framework Scorecard
    fw_table = Table(title="Regulatory Framework Compliance Scorecard", border_style="magenta")
    fw_table.add_column("Framework", style="bold white")
    fw_table.add_column("Total Controls", justify="right")
    fw_table.add_column("Passed", justify="right")
    fw_table.add_column("Failed", justify="right")
    fw_table.add_column("Pass Rate", justify="right")
    fw_table.add_column("Status", justify="center")
    fw_table.add_column("Failing Control IDs", style="dim")

    for fw_name, fw_data in sorted(report.framework_summaries.items()):
        pass_rate_val = fw_data.get("pass_rate_percentage", 100.0)
        rate_style = "bold green" if pass_rate_val == 100.0 else "bold red"
        failing_ctrls = ", ".join(fw_data.get("failing_control_ids", [])) or "-"

        fw_table.add_row(
            fw_name,
            str(fw_data.get("total_controls", 0)),
            str(fw_data.get("passed_controls", 0)),
            str(fw_data.get("failed_controls", 0)),
            f"[{rate_style}]{pass_rate_val:.1f}%[/{rate_style}]",
            _get_status_badge(fw_data.get("status", "COMPLIANT")),
            failing_ctrls,
        )
    target_console.print(fw_table)

    # 3. Findings Table
    all_findings: list[ComplianceFinding] = []
    for res in report.results:
        all_findings.extend(res.compliance_findings)

    if not all_findings:
        target_console.print(
            Panel(
                Text(
                    "✔ Clean Audit: 100% Compliance Pass Rate across SOC 2, ISO 27001, "
                    "CIS, GDPR, and PCI-DSS frameworks.",
                    justify="center",
                    style="bold green",
                ),
                border_style="green",
            )
        )
    else:
        findings_table = Table(
            title=f"Regulatory Control Violations ({len(all_findings)})",
            border_style="red"
            if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0
            else "yellow",
        )
        findings_table.add_column("Target", style="bold white")
        findings_table.add_column("Rule ID", style="bold magenta", no_wrap=True)
        findings_table.add_column("Framework", style="bold cyan")
        findings_table.add_column("Control ID", style="bold yellow", no_wrap=True)
        findings_table.add_column("Severity", justify="center", no_wrap=True)
        findings_table.add_column("Violation Details")

        for f in all_findings:
            target_label = Path(f.target).name if len(f.target) > 28 else f.target
            findings_table.add_row(
                target_label,
                f.rule_id,
                f.framework.value,
                f.control_id,
                _get_severity_badge(f.severity),
                f.message,
            )
        target_console.print(findings_table)

    for res in report.results:
        if res.error_message:
            target_console.print(
                Panel(
                    Text(
                        f"Compliance Scan Error on '{res.target}': {res.error_message}",
                        style="bold red",
                    ),
                    border_style="red",
                )
            )

    return string_io.getvalue()


def export_json(report: ComplianceReport, indent: int = 2) -> str:
    """Export ComplianceReport as structured JSON string."""
    return json.dumps(report.to_dict(), indent=indent)


def export_sarif(report: ComplianceReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export ComplianceReport as OASIS SARIF v2.1.0 document."""
    report.compute_summary()

    rules_meta: list[dict[str, Any]] = []
    for r_def in sorted(RULES_REGISTRY.values(), key=lambda r: r.rule_id):
        rules_meta.append(
            {
                "id": r_def.rule_id,
                "name": r_def.title.replace(" ", ""),
                "shortDescription": {"text": r_def.title},
                "fullDescription": {"text": r_def.description},
                "defaultConfiguration": {"level": _severity_to_sarif_level(r_def.severity)},
                "help": {
                    "text": f"Remediation: {r_def.remediation}",
                    "markdown": f"**Remediation**: {r_def.remediation}",
                },
                "properties": {
                    "severity": r_def.severity.value,
                    "controls": [f"{c.framework.value}: {c.control_id}" for c in r_def.controls],
                },
            }
        )

    sarif_results: list[dict[str, Any]] = []
    for res in report.results:
        for f in res.compliance_findings:
            line = f.line_number or 1
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "level": _severity_to_sarif_level(f.severity),
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.target,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": line,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "severity": f.severity.value,
                        "framework": f.framework.value,
                        "control_id": f.control_id,
                        "source_rule_id": f.source_rule_id,
                        "remediation": f.remediation,
                    },
                }
            )

    sarif_payload = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-compliance-engine",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-compliance-engine",
                        "rules": rules_meta,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_payload, indent=indent)
