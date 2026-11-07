# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        tests.test_report_ingestor
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report and governance manifest ingestors.

Validates ingestion of OASIS SARIF v2.1.0, Logihertz JSON reports, and governance YAML manifests.
"""

from __future__ import annotations

from pathlib import Path

from lh_compliance_engine.models import FindingSeverity
from lh_compliance_engine.report_ingestor import (
    _parse_severity,
    discover_and_ingest,
    ingest_file,
    ingest_governance_manifest,
    ingest_logihertz_json_file,
    ingest_sarif_file,
)


def test_parse_severity() -> None:
    """Test severity string normalization to FindingSeverity enum."""
    assert _parse_severity("CRITICAL") == FindingSeverity.CRITICAL
    assert _parse_severity("error") == FindingSeverity.HIGH
    assert _parse_severity("warning") == FindingSeverity.MEDIUM
    assert _parse_severity("note") == FindingSeverity.LOW
    assert _parse_severity("info") == FindingSeverity.LOW
    assert _parse_severity(None) == FindingSeverity.MEDIUM


def test_ingest_sarif_file(sample_sarif_file: Path) -> None:
    """Test parsing OASIS SARIF v2.1.0 document."""
    findings = ingest_sarif_file(sample_sarif_file)
    assert len(findings) == 2

    rule_ids = [f.rule_id for f in findings]
    assert "LH-CONT-002" in rule_ids
    assert "LH-CONT-003" in rule_ids

    root_finding = next(f for f in findings if f.rule_id == "LH-CONT-002")
    assert root_finding.severity == FindingSeverity.CRITICAL
    assert root_finding.target == "Dockerfile"
    assert root_finding.line_number == 1


def test_ingest_logihertz_json_file(sample_logihertz_json_file: Path) -> None:
    """Test parsing native Logihertz JSON scan reports."""
    findings = ingest_logihertz_json_file(sample_logihertz_json_file)
    assert len(findings) == 2

    ssl_f = next(f for f in findings if f.rule_id == "LH-DB-002")
    assert ssl_f.severity == FindingSeverity.CRITICAL
    assert "ssl = off" in ssl_f.message

    bind_f = next(f for f in findings if f.rule_id == "LH-DB-004")
    assert bind_f.severity == FindingSeverity.HIGH


def test_ingest_governance_manifest(sample_governance_manifest: Path) -> None:
    """Test parsing declarative governance YAML policy manifest."""
    findings = ingest_governance_manifest(sample_governance_manifest)
    assert len(findings) == 3

    rule_ids = [f.rule_id for f in findings]
    assert "LH-GOV-001" in rule_ids  # Unclassified datastore
    assert "LH-GOV-002" in rule_ids  # Expired waiver
    assert "LH-GOV-003" in rule_ids  # Missing trust zone


def test_ingest_file_auto_detection(
    sample_sarif_file: Path,
    sample_logihertz_json_file: Path,
    sample_governance_manifest: Path,
) -> None:
    """Test automatic format detection in ingest_file."""
    sarif_res = ingest_file(sample_sarif_file)
    assert len(sarif_res) == 2

    json_res = ingest_file(sample_logihertz_json_file)
    assert len(json_res) == 2

    yaml_res = ingest_file(sample_governance_manifest)
    assert len(yaml_res) == 3


def test_discover_and_ingest(mixed_audit_project: Path) -> None:
    """Test recursive report discovery across directory."""
    report_count, all_findings = discover_and_ingest(mixed_audit_project)
    assert report_count == 3
    assert len(all_findings) == 7


def test_ingest_corrupted_files(tmp_path: Path) -> None:
    """Test graceful handling of corrupt or empty report files."""
    bad_json = tmp_path / "corrupt.json"
    bad_json.write_text("{not-valid-json:", encoding="utf-8")

    assert ingest_sarif_file(bad_json) == []
    assert ingest_logihertz_json_file(bad_json) == []
    assert ingest_governance_manifest(bad_json) == []
    assert ingest_file(bad_json) == []
