# lh-compliance-engine

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-compliance-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-compliance-engine/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise multi-framework governance & compliance developed by **Logihertz Systems (OPC) Private Limited**.

Evaluates technical security controls, audit evidence manifests, and posture reports against SOC 2 Type II, ISO/IEC 27001, CIS Benchmarks, GDPR, and PCI-DSS v4.0 control catalogs with automated gap scoring.

---

## Key Features

- **Cross-Framework Mapping Matrix**: Maps 75+ granular technical controls across SOC 2, ISO 27001, NIST CSF, PCI DSS, and HIPAA.
- **Compliance Posture Scoring**: Computes objective compliance readiness scores (0-100%) and gap assessments per framework.
- **Audit-Ready Evidence Generation**: Generates structured compliance manifests detailing passing controls, failing controls, and remediation paths.
- **Automated Risk Attribution**: Groups violations by regulatory domains (Access Control, Cryptography, Incident Response, Network Protection).
- **Multi-Format Reporting**: Outputs colored terminal summary scorecards via `rich`, JSON compliance reports, and SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-COMP-001` | `CRITICAL` | Identity & Access Governance Failure — maps root execution, missing MFA, or wildcard IAM policies to regulatory access controls |
| `LH-COMP-002` | `CRITICAL` | Cryptographic & Data Protection Non-Compliance — maps unencrypted data at rest or weak ciphers to encryption requirements |
| `LH-COMP-003` | `CRITICAL` | Secret Hygiene & Credential Exposure Violation — maps hardcoded credentials and token leakage to credential hygiene controls |
| `LH-COMP-004` | `HIGH` | Network Perimeter & Segmentation Control Drift — maps unrestricted 0.0.0.0/0 ingress and open management ports to firewall controls |
| `LH-COMP-005` | `HIGH` | Workload, Container & System Hardening Deficit — maps privileged containers and insecure sysctl configs to secure baseline standards |
| `LH-COMP-006` | `HIGH` | Audit Logging & Telemetry Non-Compliance — maps disabled audit trails, missing access logging, or short retention to accountability controls |
| `LH-COMP-007` | `HIGH` | Software Supply Chain & Vulnerability Governance Failure — maps critical CVEs and unpinned dependencies to vulnerability management controls |
| `LH-COMP-008` | `MEDIUM` | Operational Resilience & High Availability Deficit — maps missing healthchecks and resource limits to availability and disaster recovery requirements |
| `LH-COMP-009` | `HIGH` | Data Privacy & Sensitive PII Exposure Violation — maps unmasked PII, cookie flags, or cleartext transfer to privacy mandates (HIPAA/GDPR) |
| `LH-COMP-010` | `LOW` | Governance Metadata & Asset Inventory Incompleteness — maps untagged resources and missing ownership tags to asset management controls |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-compliance-engine.git
cd lh-compliance-engine

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-compliance` (also accessible via `lh-compliance`, `lh-compliance-engine`).

```bash
# Audit a SARIF finding report against all supported frameworks
lh-compliance scan findings.sarif

# Evaluate compliance specifically for SOC 2 Type II
lh-compliance scan findings.json --framework soc2

# Export structured compliance audit report to JSON
lh-compliance scan findings.sarif --format json --output compliance-report.json

# List all mapped compliance control rules
lh-compliance rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
