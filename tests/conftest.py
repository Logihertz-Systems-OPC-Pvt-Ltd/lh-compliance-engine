# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared pytest fixtures for lh-compliance-engine test suite.

Provides mock SARIF reports, Logihertz JSON scan outputs, and governance policy manifests
for testing regulatory framework mappings (SOC 2, ISO 27001, CIS, GDPR, PCI-DSS).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def clean_project(tmp_path: Path) -> Path:
    """Create a project directory with zero failing security findings."""
    proj = tmp_path / "clean_env"
    proj.mkdir()

    clean_report = proj / "clean_audit.json"
    data = {
        "report_type": "security_audit",
        "results": [
            {
                "target": "/app",
                "findings": [],
            }
        ],
    }
    clean_report.write_text(json.dumps(data), encoding="utf-8")
    return proj


@pytest.fixture
def sample_sarif_file(tmp_path: Path) -> Path:
    """Create a sample OASIS SARIF v2.1.0 report with critical/high findings."""
    sarif_file = tmp_path / "scan_output.sarif"
    data = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-container-auditor",
                        "version": "0.1.0",
                        "rules": [
                            {
                                "id": "LH-CONT-002",
                                "name": "ContainerRunsAsRoot",
                                "shortDescription": {"text": "Container runs as root user"},
                            },
                            {
                                "id": "LH-CONT-003",
                                "name": "HardcodedSecretInDocker",
                                "shortDescription": {"text": "Hardcoded secret in ENV"},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "LH-CONT-002",
                        "level": "error",
                        "message": {"text": "Missing USER instruction in Dockerfile"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Dockerfile"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        "properties": {"severity": "CRITICAL"},
                    },
                    {
                        "ruleId": "LH-CONT-003",
                        "level": "error",
                        "message": {"text": "Hardcoded API key detected in ENV API_KEY=xyz"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Dockerfile"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                        "properties": {"severity": "CRITICAL"},
                    },
                ],
            }
        ],
    }
    sarif_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return sarif_file


@pytest.fixture
def sample_logihertz_json_file(tmp_path: Path) -> Path:
    """Create a sample Logihertz JSON audit output."""
    json_file = tmp_path / "lh_scan.json"
    data = {
        "report_type": "database_security_audit",
        "results": [
            {
                "target": "postgresql.conf",
                "findings": [
                    {
                        "rule_id": "LH-DB-002",
                        "severity": "CRITICAL",
                        "title": "SSL Disabled in Database Configuration",
                        "message": "Parameter 'ssl = off' allows unencrypted transport",
                        "target": "postgresql.conf",
                        "line_number": 12,
                    },
                    {
                        "rule_id": "LH-DB-004",
                        "severity": "HIGH",
                        "title": "Database Bound to Public Interface",
                        "message": "Parameter 'listen_addresses = *' exposes database to 0.0.0.0/0",
                        "target": "postgresql.conf",
                        "line_number": 15,
                    },
                ],
            }
        ],
    }
    json_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return json_file


@pytest.fixture
def sample_governance_manifest(tmp_path: Path) -> Path:
    """Create a declarative governance YAML policy manifest."""
    gov_file = tmp_path / "governance_policy.yaml"
    gov_file.write_text(
        """version: "1.0"
organization: "Logihertz Systems"

datastores:
  - name: "customer_transactions_db"
    engine: "postgresql"
    # Missing classification/confidentiality (triggers LH-GOV-001 -> LH-COMP-010)

waivers:
  - id: "W-2023-001"
    rule: "LH-SSL-001"
    status: "expired"
    expires_at: "2023-01-01T00:00:00Z"
    reason: "Legacy service migration grace period"

services:
  - name: "payment_webhook"
    runtime: "container"
    # Missing trust_zone (triggers LH-GOV-003 -> LH-COMP-010)
""",
        encoding="utf-8",
    )
    return gov_file


@pytest.fixture
def mixed_audit_project(
    tmp_path: Path,
    sample_sarif_file: Path,
    sample_logihertz_json_file: Path,
    sample_governance_manifest: Path,
) -> Path:
    """Create a comprehensive project directory containing SARIF, JSON, and YAML manifests."""
    proj = tmp_path / "mixed_audit"
    proj.mkdir()

    # Copy files into directory
    (proj / "container_scan.sarif").write_text(
        sample_sarif_file.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (proj / "db_scan.json").write_text(
        sample_logihertz_json_file.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (proj / "policy.yaml").write_text(
        sample_governance_manifest.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return proj
