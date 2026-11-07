# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for the lh-compliance-engine command-line interface.

Validates CLI commands 'scan' and 'rules', parameter flags, output formats,
and exit status codes (0, 1, 2) using typer.testing.CliRunner.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_compliance_engine.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_rules_command() -> None:
    """Test 'rules' command lists all LH-COMP rules and mapped compliance controls."""
    result = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "LH-COMP-001" in result.stdout
    assert "LH-COMP-010" in result.stdout
    assert "SOC 2 Type II" in result.stdout
    assert "ISO/IEC 27001:2022" in result.stdout
    assert "Identity & Access Governance" in result.stdout


def test_cli_scan_clean_project(clean_project: Path) -> None:
    """Test scanning a clean environment returns exit code 0 and 100% compliant banner."""
    result = runner.invoke(app, ["scan", str(clean_project)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Clean Audit" in result.stdout


def test_cli_scan_vulnerable_project_fails(mixed_audit_project: Path) -> None:
    """Test scanning non-compliant audit files exits with 1 when findings meet fail-on threshold."""
    result = runner.invoke(
        app,
        ["scan", str(mixed_audit_project), "--fail-on", "HIGH"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    assert "LH-COMP-001" in result.stdout


def test_cli_scan_fail_on_threshold(sample_governance_manifest: Path) -> None:
    """Test fail-on threshold suppresses failure exit if findings are below threshold."""
    # sample_governance_manifest only triggers LH-COMP-010 (LOW severity)
    result = runner.invoke(
        app,
        ["scan", str(sample_governance_manifest), "--fail-on", "MEDIUM"],
        env=CLI_ENV,
    )
    assert result.exit_code == 0


def test_cli_scan_format_json(sample_sarif_file: Path) -> None:
    """Test JSON output formatting to stdout."""
    result = runner.invoke(
        app,
        ["scan", str(sample_sarif_file), "--format", "json"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["report_type"] == "compliance_posture_assessment"
    assert data["summary"]["critical"] >= 1


def test_cli_scan_format_sarif(sample_sarif_file: Path) -> None:
    """Test SARIF v2.1.0 output formatting to stdout."""
    result = runner.invoke(
        app,
        ["scan", str(sample_sarif_file), "--format", "sarif"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "lh-compliance-engine"


def test_cli_scan_output_file(clean_project: Path, tmp_path: Path) -> None:
    """Test writing compliance report directly to an output file."""
    out_file = tmp_path / "reports" / "compliance_report.json"
    result = runner.invoke(
        app,
        ["scan", str(clean_project), "--format", "json", "--output", str(out_file)],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["report_type"] == "compliance_posture_assessment"
    assert data["summary"]["total_compliance_findings"] == 0


def test_cli_scan_nonexistent_path() -> None:
    """Test scanning a nonexistent path exits with code 2."""
    result = runner.invoke(app, ["scan", "/nonexistent/report/path"], env=CLI_ENV)
    assert result.exit_code == 2
    assert "Error: Target path '/nonexistent/report/path' does not exist." in result.stdout


def test_cli_min_severity_filter(mixed_audit_project: Path) -> None:
    """Test min-severity filtering excludes lower severity violations."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(mixed_audit_project),
            "--format",
            "json",
            "--min-severity",
            "CRITICAL",
        ],
        env=CLI_ENV,
    )
    data = json.loads(result.stdout)
    for res in data["results"]:
        for f in res["compliance_findings"]:
            assert f["severity"] == "CRITICAL"
