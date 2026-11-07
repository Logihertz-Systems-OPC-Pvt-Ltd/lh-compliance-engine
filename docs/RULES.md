# Security Rules Reference: lh-compliance-engine

An enterprise regulatory compliance & security framework engine developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-compliance-engine`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-COMP-001` | `CRITICAL` | Access Governance | Identity & Access Governance Failure |
| `LH-COMP-002` | `CRITICAL` | Cryptography | Cryptographic & Data Protection Non-Compliance |
| `LH-COMP-003` | `CRITICAL` | Credential Hygiene | Secret Hygiene & Credential Exposure Violation |
| `LH-COMP-004` | `HIGH` | Network Protection | Network Perimeter & Segmentation Control Drift |
| `LH-COMP-005` | `HIGH` | System Hardening | Workload, Container & System Hardening Deficit |
| `LH-COMP-006` | `HIGH` | Audit & Accountability | Audit Logging & Telemetry Non-Compliance |
| `LH-COMP-007` | `HIGH` | Vulnerability Management | Software Supply Chain & Vulnerability Governance Failure |
| `LH-COMP-008` | `MEDIUM` | Business Continuity | Operational Resilience & High Availability Deficit |
| `LH-COMP-009` | `HIGH` | Data Privacy | Data Privacy & Sensitive PII Exposure Violation |
| `LH-COMP-010` | `LOW` | Asset Management | Governance Metadata & Asset Inventory Incompleteness |

---

## Granular Rule Specifications

### `LH-COMP-001`: Identity & Access Governance Failure

- **Severity**: `CRITICAL`
- **Category**: `Access Governance`
- **Description**: Root execution, missing MFA, or wildcard IAM policies violating regulatory access controls.
- **Remediation**: Enforce principle of least privilege, disable root accounts, and mandate MFA on all access.

---

### `LH-COMP-002`: Cryptographic & Data Protection Non-Compliance

- **Severity**: `CRITICAL`
- **Category**: `Cryptography`
- **Description**: Unencrypted data at rest or weak ciphers violating cryptographic mandate controls.
- **Remediation**: Enforce AES-256 or ChaCha20 encryption at rest and TLS 1.3 in transit across all systems.

---

### `LH-COMP-003`: Secret Hygiene & Credential Exposure Violation

- **Severity**: `CRITICAL`
- **Category**: `Credential Hygiene`
- **Description**: Hardcoded credentials, API keys, or private tokens violating credential storage rules.
- **Remediation**: Migrate all credentials to managed secret stores with automated rotation policies.

---

### `LH-COMP-004`: Network Perimeter & Segmentation Control Drift

- **Severity**: `HIGH`
- **Category**: `Network Protection`
- **Description**: Unrestricted 0.0.0.0/0 ingress and open management ports violating boundary defense rules.
- **Remediation**: Implement micro-segmentation and restrict perimeter ingress behind zero-trust firewalls.

---

### `LH-COMP-005`: Workload, Container & System Hardening Deficit

- **Severity**: `HIGH`
- **Category**: `System Hardening`
- **Description**: Privileged containers and insecure sysctl configs failing baseline hardening standards.
- **Remediation**: Apply CIS benchmark hardened profiles and enforce non-root container execution.

---

### `LH-COMP-006`: Audit Logging & Telemetry Non-Compliance

- **Severity**: `HIGH`
- **Category**: `Audit & Accountability`
- **Description**: Disabled audit trails, missing access logging, or short retention violating audit controls.
- **Remediation**: Enable immutable audit logging with 365-day retention and centralized SIEM ingestion.

---

### `LH-COMP-007`: Software Supply Chain & Vulnerability Governance Failure

- **Severity**: `HIGH`
- **Category**: `Vulnerability Management`
- **Description**: Critical CVEs and unpinned dependencies failing regular vulnerability management SLAs.
- **Remediation**: Establish automated lockfile scanning and enforce 14-day patching SLA for critical findings.

---

### `LH-COMP-008`: Operational Resilience & High Availability Deficit

- **Severity**: `MEDIUM`
- **Category**: `Business Continuity`
- **Description**: Missing healthchecks and resource limits violating disaster recovery and availability rules.
- **Remediation**: Configure automated container liveness/readiness probes and multi-zone deployment topology.

---

### `LH-COMP-009`: Data Privacy & Sensitive PII Exposure Violation

- **Severity**: `HIGH`
- **Category**: `Data Privacy`
- **Description**: Unmasked PII, insecure cookie flags, or cleartext transfer violating HIPAA/GDPR privacy rules.
- **Remediation**: Mask PII in logs, enforce Secure/HttpOnly cookie attributes, and sanitize test data.

---

### `LH-COMP-010`: Governance Metadata & Asset Inventory Incompleteness

- **Severity**: `LOW`
- **Category**: `Asset Management`
- **Description**: Untagged cloud assets and missing ownership metadata violating asset tracking controls.
- **Remediation**: Enforce mandatory resource tagging (Owner, Environment, DataClassification) via IaC policies.

---
