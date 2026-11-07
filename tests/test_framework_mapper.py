# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        tests.test_framework_mapper
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for regulatory framework mapping engine.

Validates mapping of security findings to SOC 2, ISO 27001, CIS, GDPR, and PCI-DSS,
along with control pass rate calculations and status determinations.
"""

from __future__ import annotations

from pathlib import Path

from lh_compliance_engine.framework_mapper import (
    analyze_compliance,
    map_finding_to_compliance_rule,
)
from lh_compliance_engine.models import (
    RULES_REGISTRY,
    ComplianceFramework,
    ComplianceStatus,
    FindingSeverity,
    IngestedFinding,
)


def test_clean_compliance_baseline(clean_project: Path) -> None:
    """Validate that a clean scan results in 100% compliance across all frameworks."""
    result = analyze_compliance(clean_project)
    assert result.error_message is None
    assert result.reports_ingested == 1
    assert result.raw_findings_count == 0
    assert len(result.compliance_findings) == 0

    for fw in ComplianceFramework:
        asm = result.framework_assessments[fw.value]
        assert asm.status == ComplianceStatus.COMPLIANT
        assert asm.pass_rate_percentage == 100.0
        assert asm.failed_controls == 0
        assert len(asm.failing_control_ids) == 0


def test_mapping_lh_ssl_to_comp_002() -> None:
    """Validate that SSL/TLS findings map to LH-COMP-002 and regulatory controls."""
    raw = IngestedFinding(
        rule_id="LH-SSL-001",
        severity=FindingSeverity.CRITICAL,
        title="Expired SSL Certificate",
        message="Certificate expired 5 days ago",
        target="example.com",
        source_file="ssl.json",
    )
    rule_def = map_finding_to_compliance_rule(raw)
    assert rule_def is not None
    assert rule_def.rule_id == "LH-COMP-002"

    ctrl_ids = {c.control_id for c in rule_def.controls}
    assert "CC6.7" in ctrl_ids  # SOC 2
    assert "A.8.24" in ctrl_ids  # ISO 27001
    assert "Art. 32" in ctrl_ids  # GDPR
    assert "Req 3" in ctrl_ids  # PCI-DSS


def test_mapping_lh_cont_and_db_rules() -> None:
    """Validate container and database finding mappings."""
    # Root user -> LH-COMP-001
    f_root = IngestedFinding(
        rule_id="LH-CONT-002",
        severity=FindingSeverity.CRITICAL,
        title="Root Container",
        message="Runs as root",
        target="Dockerfile",
        source_file="Dockerfile",
    )
    rule_001 = map_finding_to_compliance_rule(f_root)
    assert rule_001 is not None and rule_001.rule_id == "LH-COMP-001"

    # Privileged container -> LH-COMP-005
    f_priv = IngestedFinding(
        rule_id="LH-CONT-006",
        severity=FindingSeverity.HIGH,
        title="Privileged Container",
        message="privileged: true",
        target="docker-compose.yml",
        source_file="docker-compose.yml",
    )
    rule_005 = map_finding_to_compliance_rule(f_priv)
    assert rule_005 is not None and rule_005.rule_id == "LH-COMP-005"

    # Database 0.0.0.0 bind -> LH-COMP-004
    f_net = IngestedFinding(
        rule_id="LH-DB-004",
        severity=FindingSeverity.HIGH,
        title="Public DB Bind",
        message="bind_address 0.0.0.0",
        target="my.cnf",
        source_file="my.cnf",
    )
    rule_004 = map_finding_to_compliance_rule(f_net)
    assert rule_004 is not None and rule_004.rule_id == "LH-COMP-004"


def test_mapping_supply_chain_and_audit_logging() -> None:
    """Validate dependency reachability and audit trail mappings."""
    # Vulnerable dependency -> LH-COMP-006
    f_dep = IngestedFinding(
        rule_id="LH-DEP-002",
        severity=FindingSeverity.CRITICAL,
        title="Vulnerable Reachable Dependency",
        message="requests 2.28 is reachable",
        target="requirements.txt",
        source_file="requirements.txt",
    )
    rule_006 = map_finding_to_compliance_rule(f_dep)
    assert rule_006 is not None and rule_006.rule_id == "LH-COMP-006"

    # Disabled CloudTrail -> LH-COMP-007
    f_trail = IngestedFinding(
        rule_id="LH-CLOUD-007",
        severity=FindingSeverity.MEDIUM,
        title="CloudTrail Disabled",
        message="Logging disabled in us-east-1",
        target="main.tf",
        source_file="main.tf",
    )
    rule_007 = map_finding_to_compliance_rule(f_trail)
    assert rule_007 is not None and rule_007.rule_id == "LH-COMP-007"


def test_mapping_api_and_resilience() -> None:
    """Validate API security and operational resilience mappings."""
    # BOLA / IDOR -> LH-COMP-008
    f_bola = IngestedFinding(
        rule_id="LH-API-003",
        severity=FindingSeverity.HIGH,
        title="BOLA Vulnerability",
        message="Missing user ownership check",
        target="/api/v1/users/{id}",
        source_file="openapi.yaml",
    )
    rule_008 = map_finding_to_compliance_rule(f_bola)
    assert rule_008 is not None and rule_008.rule_id == "LH-COMP-008"

    # Missing HEALTHCHECK -> LH-COMP-009
    f_health = IngestedFinding(
        rule_id="LH-CONT-009",
        severity=FindingSeverity.MEDIUM,
        title="Missing HEALTHCHECK",
        message="Container lacks healthcheck probe",
        target="Dockerfile",
        source_file="Dockerfile",
    )
    rule_009 = map_finding_to_compliance_rule(f_health)
    assert rule_009 is not None and rule_009.rule_id == "LH-COMP-009"


def test_mapping_governance_rules() -> None:
    """Validate governance policy and asset classification mappings."""
    f_gov = IngestedFinding(
        rule_id="LH-GOV-001",
        severity=FindingSeverity.LOW,
        title="Unclassified Datastore",
        message="Missing confidentiality classification",
        target="policy.yaml",
        source_file="policy.yaml",
    )
    rule_010 = map_finding_to_compliance_rule(f_gov)
    assert rule_010 is not None and rule_010.rule_id == "LH-COMP-010"


def test_keyword_fallback_mapping() -> None:
    """Test heuristic keyword mapping for unstructured findings."""
    f_kw = IngestedFinding(
        rule_id="GENERIC-SEC-01",
        severity=FindingSeverity.HIGH,
        title="Hardcoded API Secret in config",
        message="Found AWS_SECRET_ACCESS_KEY exposed in settings.py",
        target="settings.py",
        source_file="settings.py",
    )
    rule = map_finding_to_compliance_rule(f_kw)
    assert rule is not None and rule.rule_id == "LH-COMP-003"


def test_mixed_audit_analysis(mixed_audit_project: Path) -> None:
    """Validate full analysis on mixed audit directory containing SARIF, JSON, and YAML."""
    result = analyze_compliance(mixed_audit_project)
    assert result.error_message is None
    assert result.reports_ingested == 3
    assert result.raw_findings_count == 7
    assert len(result.compliance_findings) > 10

    # Verify framework scorecard calculations
    soc2_asm = result.framework_assessments[ComplianceFramework.SOC2.value]
    assert soc2_asm.status == ComplianceStatus.NON_COMPLIANT
    assert soc2_asm.failed_controls > 0
    assert soc2_asm.pass_rate_percentage < 100.0
    assert "CC6.1" in soc2_asm.failing_control_ids

    pci_asm = result.framework_assessments[ComplianceFramework.PCIDSS.value]
    assert pci_asm.status == ComplianceStatus.NON_COMPLIANT
    assert "Req 3" in pci_asm.failing_control_ids


def test_all_ten_rules_defined_in_registry() -> None:
    """Verify all 10 LH-COMP rules exist in RULES_REGISTRY with valid controls."""
    assert len(RULES_REGISTRY) == 10
    for idx in range(1, 11):
        rule_id = f"LH-COMP-{idx:03d}"
        assert rule_id in RULES_REGISTRY
        r_def = RULES_REGISTRY[rule_id]
        assert len(r_def.controls) > 0


def test_prefix_and_cve_mappings() -> None:
    """Test prefix matching for kernel, dependency, governance, and CVEs."""
    f_kern = IngestedFinding(
        rule_id="LH-KERN-999",
        severity=FindingSeverity.HIGH,
        title="Custom Kernel Rule",
        message="sysctl check",
        target="sysctl.conf",
        source_file="sysctl.conf",
    )
    assert map_finding_to_compliance_rule(f_kern).rule_id == "LH-COMP-005"

    f_dep = IngestedFinding(
        rule_id="LH-DEP-999",
        severity=FindingSeverity.HIGH,
        title="Custom Dep Rule",
        message="dependency check",
        target="requirements.txt",
        source_file="requirements.txt",
    )
    assert map_finding_to_compliance_rule(f_dep).rule_id == "LH-COMP-006"

    f_gov = IngestedFinding(
        rule_id="LH-GOV-999",
        severity=FindingSeverity.LOW,
        title="Custom Gov Rule",
        message="governance check",
        target="gov.yaml",
        source_file="gov.yaml",
    )
    assert map_finding_to_compliance_rule(f_gov).rule_id == "LH-COMP-010"

    f_cve = IngestedFinding(
        rule_id="CVE-2023-12345",
        severity=FindingSeverity.HIGH,
        title="Common Vulnerability",
        message="Remote exploit",
        target="lib.so",
        source_file="lib.so",
    )
    assert map_finding_to_compliance_rule(f_cve).rule_id == "LH-COMP-006"


def test_nonexistent_target_path() -> None:
    """Test analyze_compliance with nonexistent target."""
    result = analyze_compliance("/nonexistent/path/for/audit")
    assert result.error_message is not None
    assert "does not exist" in result.error_message
