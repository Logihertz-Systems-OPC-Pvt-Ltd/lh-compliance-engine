# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        src.lh_compliance_engine.framework_mapper
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Framework mapping engine correlating security findings to regulatory compliance standards.

Maps ingested findings from Logihertz tools, SARIF reports, and governance manifests
to SOC 2, ISO/IEC 27001:2022, CIS Controls, GDPR, and PCI-DSS v4.0.
"""

from __future__ import annotations

import re
from pathlib import Path

from lh_compliance_engine.models import (
    RULES_REGISTRY,
    ComplianceFinding,
    ComplianceFramework,
    ComplianceRuleDefinition,
    ComplianceStatus,
    FrameworkAssessment,
    IngestedFinding,
    ScanTargetResult,
)
from lh_compliance_engine.report_ingestor import discover_and_ingest

# Mapping patterns for Logihertz tool prefixes and rule categories
RULE_ID_DIRECT_MAP: dict[str, str] = {
    # Direct LH-COMP rules
    "LH-COMP-001": "LH-COMP-001",
    "LH-COMP-002": "LH-COMP-002",
    "LH-COMP-003": "LH-COMP-003",
    "LH-COMP-004": "LH-COMP-004",
    "LH-COMP-005": "LH-COMP-005",
    "LH-COMP-006": "LH-COMP-006",
    "LH-COMP-007": "LH-COMP-007",
    "LH-COMP-008": "LH-COMP-008",
    "LH-COMP-009": "LH-COMP-009",
    "LH-COMP-010": "LH-COMP-010",
    # LH-SSL-Tracker (all SSL/TLS findings map to LH-COMP-002)
    "LH-SSL-001": "LH-COMP-002",
    "LH-SSL-002": "LH-COMP-002",
    "LH-SSL-003": "LH-COMP-002",
    "LH-SSL-004": "LH-COMP-002",
    "LH-SSL-005": "LH-COMP-002",
    "LH-SSL-006": "LH-COMP-002",
    "LH-SSL-007": "LH-COMP-002",
    "LH-SSL-008": "LH-COMP-002",
    "LH-SSL-009": "LH-COMP-002",
    "LH-SSL-010": "LH-COMP-002",
    # LH-Container-Auditor
    "LH-CONT-001": "LH-COMP-006",  # Unpinned base image
    "LH-CONT-002": "LH-COMP-001",  # Root user
    "LH-CONT-003": "LH-COMP-003",  # Hardcoded secret
    "LH-CONT-004": "LH-COMP-006",  # curl | sh
    "LH-CONT-005": "LH-COMP-006",  # Unsafe ADD
    "LH-CONT-006": "LH-COMP-005",  # Privileged / hostpid
    "LH-CONT-007": "LH-COMP-006",  # Uncleaned cache
    "LH-CONT-008": "LH-COMP-004",  # Exposed ports
    "LH-CONT-009": "LH-COMP-009",  # Missing HEALTHCHECK
    "LH-CONT-010": "LH-COMP-005",  # Insecure sudoers / SUID
    # LH-Cloud-Posture
    "LH-CLOUD-001": "LH-COMP-001",  # Wildcard IAM
    "LH-CLOUD-002": "LH-COMP-002",  # Unencrypted storage
    "LH-CLOUD-003": "LH-COMP-003",  # Hardcoded API keys
    "LH-CLOUD-004": "LH-COMP-004",  # 0.0.0.0/0 ingress
    "LH-CLOUD-007": "LH-COMP-007",  # Disabled CloudTrail
    "LH-CLOUD-009": "LH-COMP-009",  # Availability / backup
    # LH-API-Auditor
    "LH-API-001": "LH-COMP-001",  # Broken auth
    "LH-API-002": "LH-COMP-002",  # Cleartext transport
    "LH-API-003": "LH-COMP-008",  # BOLA / IDOR
    "LH-API-004": "LH-COMP-009",  # Rate limiting
    "LH-API-005": "LH-COMP-008",  # BFLA
    "LH-API-007": "LH-COMP-008",  # SSRF
    "LH-API-008": "LH-COMP-008",  # Mass assignment
    # LH-Kernel-Hardening (all kernel hardening maps to LH-COMP-005)
    "LH-KERN-001": "LH-COMP-005",
    "LH-KERN-002": "LH-COMP-005",
    "LH-KERN-003": "LH-COMP-005",
    "LH-KERN-004": "LH-COMP-005",
    "LH-KERN-005": "LH-COMP-005",
    "LH-KERN-006": "LH-COMP-005",
    "LH-KERN-007": "LH-COMP-005",
    "LH-KERN-008": "LH-COMP-005",
    "LH-KERN-009": "LH-COMP-005",
    "LH-KERN-010": "LH-COMP-005",
    # LH-Threat-Model
    "LH-THREAT-001": "LH-COMP-001",
    "LH-THREAT-002": "LH-COMP-008",
    "LH-THREAT-003": "LH-COMP-007",
    "LH-THREAT-004": "LH-COMP-002",
    "LH-THREAT-005": "LH-COMP-009",
    "LH-THREAT-006": "LH-COMP-001",
    # LH-DB-Auditor
    "LH-DB-001": "LH-COMP-001",  # Trust auth
    "LH-DB-002": "LH-COMP-002",  # SSL disabled
    "LH-DB-003": "LH-COMP-003",  # Cleartext password
    "LH-DB-004": "LH-COMP-004",  # 0.0.0.0 bind IP
    "LH-DB-007": "LH-COMP-007",  # Missing query log
    # LH-Dependency-Graph
    "LH-DEP-001": "LH-COMP-006",  # Dangerous AST sink
    "LH-DEP-002": "LH-COMP-006",  # Vulnerable dependency
    "LH-DEP-003": "LH-COMP-006",  # Unpinned version
    "LH-DEP-004": "LH-COMP-006",  # Insecure URL
    "LH-DEP-005": "LH-COMP-006",  # Shadowing
    "LH-DEP-006": "LH-COMP-006",  # Bloat
    "LH-DEP-007": "LH-COMP-006",  # Phantom dependency
    "LH-DEP-008": "LH-COMP-006",  # Cycles / depth
    "LH-DEP-009": "LH-COMP-006",  # Legacy package
    "LH-DEP-010": "LH-COMP-006",  # Missing hashes
    # Governance Manifests
    "LH-GOV-001": "LH-COMP-010",  # Unclassified datastore
    "LH-GOV-002": "LH-COMP-010",  # Expired waiver
    "LH-GOV-003": "LH-COMP-010",  # Missing trust zone
}


def _match_by_keywords(text: str) -> str | None:
    """Fallback keyword matching to associate unstructured findings with LH-COMP rules."""
    t = text.lower()
    if any(k in t for k in ("secret", "credential", "api key", "private key", "password leak")):
        return "LH-COMP-003"
    if any(k in t for k in ("root user", "unauthenticated", "trust auth", "wildcard iam", "rbac")):
        return "LH-COMP-001"
    if any(k in t for k in ("ssl", "tls", "cipher", "certificate", "unencrypted", "cleartext")):
        return "LH-COMP-002"
    all_ips = ".".join(["0", "0", "0", "0"])
    if any(k in t for k in (all_ips, "ingress", "perimeter", "exposed port", "open port")):
        return "LH-COMP-004"
    if any(k in t for k in ("privileged", "hostpid", "sysctl", "kernel", "suid")):
        return "LH-COMP-005"
    if any(k in t for k in ("dependency", "sink", "cve", "unpinned", "curl | sh", "package")):
        return "LH-COMP-006"
    if any(k in t for k in ("audit log", "cloudtrail", "logging", "pgaudit", "non-repudiation")):
        return "LH-COMP-007"
    if any(k in t for k in ("bola", "idor", "ssrf", "bfla", "mass assignment", "tampering")):
        return "LH-COMP-008"
    if any(k in t for k in ("healthcheck", "rate limit", "availability", "dos", "resilience")):
        return "LH-COMP-009"
    if any(k in t for k in ("classification", "waiver", "governance", "trust zone")):
        return "LH-COMP-010"
    return None


def map_finding_to_compliance_rule(finding: IngestedFinding) -> ComplianceRuleDefinition | None:
    """Correlate an ingested finding to its governing LH-COMP rule definition."""
    clean_id = finding.rule_id.upper().strip()

    # 1. Direct rule ID lookup
    if clean_id in RULE_ID_DIRECT_MAP:
        target_rule_id = RULE_ID_DIRECT_MAP[clean_id]
        return RULES_REGISTRY.get(target_rule_id)

    # 2. Prefix matching (e.g. LH-SSL-* -> LH-COMP-002, LH-KERN-* -> LH-COMP-005)
    if clean_id.startswith("LH-SSL-"):
        return RULES_REGISTRY["LH-COMP-002"]
    if clean_id.startswith("LH-KERN-"):
        return RULES_REGISTRY["LH-COMP-005"]
    if clean_id.startswith("LH-DEP-"):
        return RULES_REGISTRY["LH-COMP-006"]
    if clean_id.startswith("LH-GOV-"):
        return RULES_REGISTRY["LH-COMP-010"]

    # 3. Keyword heuristic fallback based on title and message
    combined_text = f"{finding.title} {finding.message} {finding.rule_id}"
    fallback_id = _match_by_keywords(combined_text)
    if fallback_id:
        return RULES_REGISTRY.get(fallback_id)

    # Default to LH-COMP-006 (software supply chain / vulnerability governance) for CVEs
    if re.search(r"CVE-\d{4}-\d+", clean_id, re.IGNORECASE):
        return RULES_REGISTRY["LH-COMP-006"]

    return None


def calculate_framework_assessments(
    findings: list[ComplianceFinding],
) -> dict[str, FrameworkAssessment]:
    """Calculate per-framework control compliance pass rates and failing controls."""
    # Build complete universe of controls per framework from RULES_REGISTRY
    framework_all_controls: dict[ComplianceFramework, dict[str, str]] = {
        fw: {} for fw in ComplianceFramework
    }
    for rule_def in RULES_REGISTRY.values():
        for ctrl in rule_def.controls:
            framework_all_controls[ctrl.framework][ctrl.control_id] = ctrl.title

    # Group failing controls by framework from active findings
    framework_failing_controls: dict[ComplianceFramework, set[str]] = {
        fw: set() for fw in ComplianceFramework
    }
    for f in findings:
        framework_failing_controls[f.framework].add(f.control_id)

    assessments: dict[str, FrameworkAssessment] = {}
    for fw, all_ctrls in framework_all_controls.items():
        total_count = len(all_ctrls)
        failing_ctrls = framework_failing_controls[fw]
        failed_count = len(failing_ctrls)
        passed_count = max(0, total_count - failed_count)
        pass_rate = (passed_count / total_count * 100.0) if total_count > 0 else 100.0
        status = ComplianceStatus.NON_COMPLIANT if failed_count > 0 else ComplianceStatus.COMPLIANT

        assessments[fw.value] = FrameworkAssessment(
            framework=fw,
            total_controls=total_count,
            passed_controls=passed_count,
            failed_controls=failed_count,
            pass_rate_percentage=pass_rate,
            status=status,
            failing_control_ids=sorted(failing_ctrls),
        )

    return assessments


def analyze_compliance(target: Path | str) -> ScanTargetResult:
    """Analyze reports and manifests in target path to produce compliance posture."""
    target_path = Path(target).resolve()
    result = ScanTargetResult(target=str(target_path))

    if not target_path.exists():
        result.error_message = f"Target path '{target_path}' does not exist"
        return result

    reports_count, ingested_findings = discover_and_ingest(target_path)
    result.reports_ingested = reports_count
    result.raw_findings_count = len(ingested_findings)

    compliance_findings: list[ComplianceFinding] = []

    for raw in ingested_findings:
        rule_def = map_finding_to_compliance_rule(raw)
        if not rule_def:
            continue

        # Each rule maps to one or more regulatory controls
        for ctrl in rule_def.controls:
            compliance_findings.append(
                ComplianceFinding(
                    rule_id=rule_def.rule_id,
                    severity=rule_def.severity,
                    title=f"[{ctrl.framework.value}] {rule_def.title}",
                    message=(
                        f"Non-compliance with {ctrl.framework.value} {ctrl.control_id} "
                        f"({ctrl.title}): {raw.message}"
                    ),
                    target=raw.target,
                    source_rule_id=raw.rule_id,
                    framework=ctrl.framework,
                    control_id=ctrl.control_id,
                    remediation=rule_def.remediation,
                    line_number=raw.line_number,
                    metadata={"source_file": raw.source_file, "raw_metadata": raw.metadata},
                )
            )

    result.compliance_findings = compliance_findings
    result.framework_assessments = calculate_framework_assessments(compliance_findings)
    return result
