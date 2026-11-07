# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        src.lh_compliance_engine.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and regulatory framework mappings for lh-compliance-engine.

Provides structured types for compliance frameworks (SOC 2, ISO 27001, CIS,
GDPR, PCI-DSS), ingested findings from SARIF and Logihertz JSON reports,
declarative governance policies, and consolidated compliance audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ComplianceFramework(StrEnum):
    """Supported regulatory and security compliance frameworks."""

    SOC2 = "SOC 2 Type II"
    ISO27001 = "ISO/IEC 27001:2022"
    CIS = "CIS Benchmarks / Controls"
    GDPR = "GDPR"
    PCIDSS = "PCI-DSS v4.0"


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for security and compliance findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class ComplianceStatus(StrEnum):
    """Compliance assessment status for controls or frameworks."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class FrameworkControl:
    """Specific regulatory control requirement within a compliance framework."""

    framework: ComplianceFramework
    control_id: str
    title: str
    description: str


@dataclass
class ComplianceRuleDefinition:
    """Formal definition and framework mappings for an LH-COMP rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    description: str
    remediation: str
    controls: list[FrameworkControl] = field(default_factory=list)


@dataclass
class IngestedFinding:
    """Normalized finding ingested from SARIF, Logihertz JSON, or governance YAML."""

    rule_id: str
    severity: FindingSeverity
    title: str
    message: str
    target: str
    source_file: str
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceFinding:
    """Specific regulatory compliance violation mapped to a framework control."""

    rule_id: str
    severity: FindingSeverity
    title: str
    message: str
    target: str
    source_rule_id: str
    framework: ComplianceFramework
    control_id: str
    remediation: str
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert compliance finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "target": self.target,
            "source_rule_id": self.source_rule_id,
            "framework": self.framework.value,
            "control_id": self.control_id,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclass
class FrameworkAssessment:
    """Compliance assessment metrics and pass rates for a single framework."""

    framework: ComplianceFramework
    total_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    pass_rate_percentage: float = 100.0
    status: ComplianceStatus = ComplianceStatus.COMPLIANT
    failing_control_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert assessment to dictionary."""
        return {
            "framework": self.framework.value,
            "total_controls": self.total_controls,
            "passed_controls": self.passed_controls,
            "failed_controls": self.failed_controls,
            "pass_rate_percentage": round(self.pass_rate_percentage, 1),
            "status": self.status.value,
            "failing_control_ids": self.failing_control_ids,
        }


@dataclass
class ScanTargetResult:
    """Audit results for an ingested target file or directory."""

    target: str
    reports_ingested: int = 0
    raw_findings_count: int = 0
    compliance_findings: list[ComplianceFinding] = field(default_factory=list)
    framework_assessments: dict[str, FrameworkAssessment] = field(default_factory=dict)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "target": self.target,
            "reports_ingested": self.reports_ingested,
            "raw_findings_count": self.raw_findings_count,
            "error_message": self.error_message,
            "framework_assessments": {
                k: v.to_dict() for k, v in self.framework_assessments.items()
            },
            "compliance_findings": [f.to_dict() for f in self.compliance_findings],
        }


@dataclass
class ComplianceReport:
    """Consolidated compliance posture audit report."""

    report_type: str = "compliance_posture_assessment"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    framework_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Compute aggregated findings counts and framework metrics."""
        counts = {
            "total_targets": len(self.results),
            "reports_ingested": sum(r.reports_ingested for r in self.results),
            "raw_findings_ingested": sum(r.raw_findings_count for r in self.results),
            "total_compliance_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for res in self.results:
            for f in res.compliance_findings:
                counts["total_compliance_findings"] += 1
                if f.severity == FindingSeverity.CRITICAL:
                    counts["critical"] += 1
                elif f.severity == FindingSeverity.HIGH:
                    counts["high"] += 1
                elif f.severity == FindingSeverity.MEDIUM:
                    counts["medium"] += 1
                elif f.severity == FindingSeverity.LOW:
                    counts["low"] += 1

        self.summary = counts

        # Aggregate framework assessments across all results
        f_summaries: dict[str, dict[str, Any]] = {}
        for fw in ComplianceFramework:
            all_failing_controls: set[str] = set()
            total_ctrls = 0
            for res in self.results:
                asm = res.framework_assessments.get(fw.value)
                if asm:
                    total_ctrls = max(total_ctrls, asm.total_controls)
                    all_failing_controls.update(asm.failing_control_ids)

            failed_ctrls = len(all_failing_controls)
            passed_ctrls = max(0, total_ctrls - failed_ctrls)
            pass_rate = (passed_ctrls / total_ctrls * 100.0) if total_ctrls > 0 else 100.0
            status = (
                ComplianceStatus.NON_COMPLIANT if failed_ctrls > 0 else ComplianceStatus.COMPLIANT
            )

            f_summaries[fw.value] = {
                "framework": fw.value,
                "total_controls": total_ctrls,
                "passed_controls": passed_ctrls,
                "failed_controls": failed_ctrls,
                "pass_rate_percentage": round(pass_rate, 1),
                "status": status.value,
                "failing_control_ids": sorted(all_failing_controls),
            }

        self.framework_summaries = f_summaries

    def has_failures(self, threshold: FindingSeverity | None) -> bool:
        """Check if any compliance finding meets or exceeds the failure threshold."""
        if threshold is None:
            return False
        for res in self.results:
            for f in res.compliance_findings:
                if f.severity.meets_threshold(threshold):
                    return True
        return False

    def filter_min_severity(self, min_sev: FindingSeverity) -> None:
        """Filter out findings below the specified minimum severity."""
        for res in self.results:
            res.compliance_findings = [
                f for f in res.compliance_findings if f.severity.meets_threshold(min_sev)
            ]
        self.compute_summary()

    def to_dict(self) -> dict[str, Any]:
        """Convert complete compliance report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "framework_summaries": self.framework_summaries,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, ComplianceRuleDefinition] = {
    "LH-COMP-001": ComplianceRuleDefinition(
        rule_id="LH-COMP-001",
        title="Identity & Access Governance Failure",
        severity=FindingSeverity.CRITICAL,
        description=(
            "Identifies unauthenticated endpoints, root container/process execution, insecure "
            "database trust authentication, or wildcard IAM/RBAC permissions."
        ),
        remediation=(
            "Enforce least privilege, eliminate root execution, disable unauthenticated endpoints, "
            "and restrict IAM/RBAC wildcard policies."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC6.1",
                title="Logical Access Security",
                description="Logical access security measures restrict unauthorized user access.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.5.15",
                title="Access Control",
                description="Rules to control physical and logical access to information.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.2",
                title="Privileged Access Rights",
                description="Allocation and use of privileged access rights shall be restricted.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.CIS,
                control_id="Control 5",
                title="Account Management",
                description="Use processes to manage credentials and privileges.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.CIS,
                control_id="Control 6",
                title="Access Control Management",
                description="Use processes and tools to grant and revoke credentials.",
            ),
        ],
    ),
    "LH-COMP-002": ComplianceRuleDefinition(
        rule_id="LH-COMP-002",
        title="Cryptographic & Data Protection Non-Compliance",
        severity=FindingSeverity.CRITICAL,
        description=(
            "Identifies unencrypted data stores, cleartext HTTP/database transport, weak cipher "
            "suites, or expired/soon-to-expire SSL/TLS certificates."
        ),
        remediation=(
            "Enforce AES-256 encryption at rest, mandatory TLS 1.2+ in transit, and automate "
            "certificate renewal."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC6.7",
                title="Transmission Data Protection",
                description="Protects data transmitted over public networks via encryption.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.24",
                title="Use of Cryptography",
                description="Rules for effective use of cryptography shall be defined.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.GDPR,
                control_id="Art. 32",
                title="Security of Processing",
                description="Implement appropriate measures including encryption of personal data.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.PCIDSS,
                control_id="Req 3",
                title="Protect Stored Account Data",
                description="Protect stored cardholder data with robust cryptography.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.PCIDSS,
                control_id="Req 4",
                title="Protect Cardholder Data in Transit",
                description="Encrypt cardholder data across open public networks.",
            ),
        ],
    ),
    "LH-COMP-003": ComplianceRuleDefinition(
        rule_id="LH-COMP-003",
        title="Secret Hygiene & Credential Exposure Violation",
        severity=FindingSeverity.CRITICAL,
        description=(
            "Detects hardcoded secrets, plaintext database passwords, API tokens, or embedded "
            "private keys across source code, container manifests, and config files."
        ),
        remediation=(
            "Remove hardcoded secrets, rotate compromised credentials, and use a dedicated "
            "secret manager (Vault, AWS Secrets Manager, GCP Secret Manager)."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC6.1",
                title="Credential Protection",
                description="Protects logical access credentials from unauthorized disclosure.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.5.17",
                title="Authentication Information",
                description="Allocation and management of authentication information.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.CIS,
                control_id="Control 3",
                title="Data Protection",
                description="Develop processes and controls to prevent secret and data leakage.",
            ),
        ],
    ),
    "LH-COMP-004": ComplianceRuleDefinition(
        rule_id="LH-COMP-004",
        title="Network Perimeter & Segmentation Control Drift",
        severity=FindingSeverity.HIGH,
        description=(
            "Identifies unrestricted 0.0.0.0/0 ingress rules, public database/Redis/MongoDB "
            "listeners, or exposed administrative management ports."
        ),
        remediation=(
            "Restrict open ingress, bind databases to private interfaces/VPCs, and enforce "
            "bastion hosts or VPNs for administration."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC6.6",
                title="Boundary Protection",
                description="Logical boundaries protect internal systems from external networks.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.20",
                title="Network Security",
                description="Networks and network services shall be secured and managed.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.22",
                title="Segregation of Networks",
                description="Information services, users, and systems shall be segregated.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.PCIDSS,
                control_id="Req 1",
                title="Network Security Controls",
                description="Install and maintain network security controls to protect CDE.",
            ),
        ],
    ),
    "LH-COMP-005": ComplianceRuleDefinition(
        rule_id="LH-COMP-005",
        title="Workload, Host & Kernel Baseline Hardening Gap",
        severity=FindingSeverity.HIGH,
        description=(
            "Identifies privileged container execution, shared host namespaces (PID/IPC/net), "
            "unhardened kernel sysctl parameters, or vulnerable SUID/SGID binaries."
        ),
        remediation=(
            "Execute workloads non-root without privileged flags, drop unnecessary capabilities, "
            "and enforce kernel security sysctl settings."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.CIS,
                control_id="CIS Benchmarks",
                title="System Hardening Baselines",
                description="Maintain secure system and container configuration baselines.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.9",
                title="Configuration Management",
                description="Configurations including security settings of hardware and software.",
            ),
        ],
    ),
    "LH-COMP-006": ComplianceRuleDefinition(
        rule_id="LH-COMP-006",
        title="Software Supply Chain & Vulnerability Governance Deficit",
        severity=FindingSeverity.HIGH,
        description=(
            "Identifies reachable vulnerable dependencies, unpinned package versions, dangerous "
            "deserialization/subprocess AST sinks, or unverified curl-to-shell installations."
        ),
        remediation=(
            "Patch vulnerable dependencies, pin exact versions with integrity hashes, and avoid "
            "unsafe deserialization sinks."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC7.1",
                title="Vulnerability Management",
                description="Monitors and remediates vulnerabilities across lifecycle.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.8",
                title="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities shall be obtained.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.28",
                title="Secure Coding",
                description="Secure coding principles shall be applied to software development.",
            ),
        ],
    ),
    "LH-COMP-007": ComplianceRuleDefinition(
        rule_id="LH-COMP-007",
        title="Audit Logging & Non-Repudiation Control Deficiency",
        severity=FindingSeverity.MEDIUM,
        description=(
            "Identifies disabled audit trails (e.g. CloudTrail, database query/DDL logs), missing "
            "security event forwarding, or insufficient log retention configurations."
        ),
        remediation=(
            "Enable comprehensive audit logging for administrative actions and modifications, "
            "and retain logs securely for at least 365 days."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC7.2",
                title="Security Event Monitoring",
                description="Monitors infrastructure and components to detect security anomalies.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.15",
                title="Logging",
                description="Logs that record activities, exceptions, faults shall be produced.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.PCIDSS,
                control_id="Req 10",
                title="Log and Monitor All Access",
                description="Log and monitor all access to system components and cardholder data.",
            ),
        ],
    ),
    "LH-COMP-008": ComplianceRuleDefinition(
        rule_id="LH-COMP-008",
        title="Application & API Input/Authorization Security Gap",
        severity=FindingSeverity.HIGH,
        description=(
            "Identifies Broken Object Level Authorization (BOLA/IDOR), Server-Side Request "
            "Forgery (SSRF), mass assignment, or missing input parameter validation."
        ),
        remediation=(
            "Validate object ownership on every request, enforce strict URL allowlists for SSRF "
            "prevention, and use schema-enforced DTOs."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="CC6.8",
                title="Application Security Controls",
                description="Protects applications against tampering and unauthorized access.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.26",
                title="Application Security Requirements",
                description="Information security requirements shall be identified and addressed.",
            ),
        ],
    ),
    "LH-COMP-009": ComplianceRuleDefinition(
        rule_id="LH-COMP-009",
        title="Operational Resilience & Availability Control Gap",
        severity=FindingSeverity.MEDIUM,
        description=(
            "Identifies missing container health checks, unconfigured resource limits (OOM risk), "
            "or absence of API rate limiting and DoS protections."
        ),
        remediation=(
            "Configure liveness/readiness health probes, define container resource limits, "
            "and enforce rate limiting and WAF rules."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.SOC2,
                control_id="A1.2",
                title="Environmental & Operational Availability",
                description="Designs and tests controls to meet availability commitments.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.8.6",
                title="Capacity Management",
                description="The use of resources shall be monitored to meet requirements.",
            ),
        ],
    ),
    "LH-COMP-010": ComplianceRuleDefinition(
        rule_id="LH-COMP-010",
        title="Governance Policy, Asset Classification & Waiver Expiry Violation",
        severity=FindingSeverity.LOW,
        description=(
            "Identifies unclassified data stores, missing organizational trust zones, or expired "
            "and unapproved security waivers in declarative governance policies."
        ),
        remediation=(
            "Classify all storage assets by data sensitivity tier, assign explicit trust zones, "
            "and review and re-authorize or revoke expired waivers."
        ),
        controls=[
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.5.9",
                title="Inventory of Information and Other Associated Assets",
                description="An inventory of information and assets shall be developed.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.ISO27001,
                control_id="A.5.12",
                title="Classification of Information",
                description="Information shall be classified in accordance with requirements.",
            ),
            FrameworkControl(
                framework=ComplianceFramework.GDPR,
                control_id="Art. 30",
                title="Records of Processing Activities",
                description="Maintain detailed records of processing activities and data tiers.",
            ),
        ],
    ),
}
