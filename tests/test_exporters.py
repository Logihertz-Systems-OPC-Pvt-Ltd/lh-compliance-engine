# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for compliance report exporters (Table, JSON, SARIF v2.1.0).

Validates terminal presentation, structured JSON schema, and SARIF v2.1.0 specifications.
"""

from __future__ import annotations

import json

from lh_compliance_engine.exporters import (
    _get_severity_badge,
    _get_status_badge,
    _severity_to_sarif_level,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_compliance_engine.models import (
    ComplianceFinding,
    ComplianceFramework,
    ComplianceReport,
    ComplianceStatus,
    FindingSeverity,
    FrameworkAssessment,
    ScanTargetResult,
)


def _build_sample_compliance_report(has_findings: bool = True) -> ComplianceReport:
    """Helper creating a sample ComplianceReport for exporter tests."""
    findings = []
    if has_findings:
        findings = [
            ComplianceFinding(
                rule_id="LH-COMP-001",
                severity=FindingSeverity.CRITICAL,
                title="Identity & Access Governance Failure",
                message="Container executed as root user",
                target="Dockerfile",
                source_rule_id="LH-CONT-002",
                framework=ComplianceFramework.SOC2,
                control_id="CC6.1",
                remediation="Enforce non-root USER",
                line_number=1,
            ),
            ComplianceFinding(
                rule_id="LH-COMP-002",
                severity=FindingSeverity.CRITICAL,
                title="Cryptographic & Data Protection Non-Compliance",
                message="SSL disabled in postgresql.conf",
                target="postgresql.conf",
                source_rule_id="LH-DB-002",
                framework=ComplianceFramework.PCIDSS,
                control_id="Req 3",
                remediation="Enable SSL/TLS",
                line_number=12,
            ),
        ]

    assessments = {
        ComplianceFramework.SOC2.value: FrameworkAssessment(
            framework=ComplianceFramework.SOC2,
            total_controls=5,
            passed_controls=4 if has_findings else 5,
            failed_controls=1 if has_findings else 0,
            pass_rate_percentage=80.0 if has_findings else 100.0,
            status=ComplianceStatus.NON_COMPLIANT if has_findings else ComplianceStatus.COMPLIANT,
            failing_control_ids=["CC6.1"] if has_findings else [],
        ),
        ComplianceFramework.PCIDSS.value: FrameworkAssessment(
            framework=ComplianceFramework.PCIDSS,
            total_controls=5,
            passed_controls=4 if has_findings else 5,
            failed_controls=1 if has_findings else 0,
            pass_rate_percentage=80.0 if has_findings else 100.0,
            status=ComplianceStatus.NON_COMPLIANT if has_findings else ComplianceStatus.COMPLIANT,
            failing_control_ids=["Req 3"] if has_findings else [],
        ),
    }

    res = ScanTargetResult(
        target="/app",
        reports_ingested=1,
        raw_findings_count=2 if has_findings else 0,
        compliance_findings=findings,
        framework_assessments=assessments,
    )
    report = ComplianceReport(
        results=[res],
        parameters={"format": "table"},
    )
    report.compute_summary()
    return report


def test_render_table_report_with_findings() -> None:
    """Test table rendering when compliance violations are present."""
    report = _build_sample_compliance_report(has_findings=True)
    rendered = render_table_report(report)

    assert "lh-compliance-engine" in rendered
    assert "Compliance Audit Executive Summary" in rendered
    assert "Regulatory Framework Compliance Scorecard" in rendered
    assert "Regulatory Control Violations" in rendered
    assert "LH-COMP-001" in rendered
    assert "SOC 2 Type II" in rendered
    assert "CC6.1" in rendered


def test_render_table_report_clean() -> None:
    """Test table rendering for 100% compliant clean audit."""
    report = _build_sample_compliance_report(has_findings=False)
    rendered = render_table_report(report)

    assert "Clean Audit" in rendered
    assert "100% Compliance Pass Rate" in rendered


def test_export_json_schema() -> None:
    """Test JSON export schema conformity."""
    report = _build_sample_compliance_report(has_findings=True)
    json_str = export_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "compliance_posture_assessment"
    assert "summary" in data
    assert data["summary"]["total_compliance_findings"] == 2
    assert "framework_summaries" in data
    assert len(data["results"]) == 1
    assert len(data["results"][0]["compliance_findings"]) == 2


def test_export_sarif_schema() -> None:
    """Test SARIF v2.1.0 document structure conformity."""
    report = _build_sample_compliance_report(has_findings=True)
    sarif_str = export_sarif(report)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-compliance-engine"
    assert len(run["results"]) == 2
    assert run["results"][0]["ruleId"] == "LH-COMP-001"
    assert run["results"][0]["level"] == "error"


def test_severity_and_status_helpers() -> None:
    """Test severity and status badge formatting helpers."""
    assert _severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert _severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert _severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert _severity_to_sarif_level(FindingSeverity.LOW) == "note"

    crit_badge = _get_severity_badge(FindingSeverity.CRITICAL)
    assert "CRITICAL" in crit_badge.plain

    comp_badge = _get_status_badge(ComplianceStatus.COMPLIANT.value)
    assert "COMPLIANT" in comp_badge.plain

    non_comp_badge = _get_status_badge(ComplianceStatus.NON_COMPLIANT.value)
    assert "NON-COMPLIANT" in non_comp_badge.plain
