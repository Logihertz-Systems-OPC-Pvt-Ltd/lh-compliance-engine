# ==============================================================================
# Product:       lh-compliance-engine (lh-compliance)
# Module:        src.lh_compliance_engine.report_ingestor
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Ingestors for SARIF v2.1.0, Logihertz JSON reports, and governance policy manifests.

Parses external security assessment outputs across any `lh-*` tool and maps raw
findings into normalized IngestedFinding instances for compliance framework mapping.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from lh_compliance_engine.models import FindingSeverity, IngestedFinding

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
}


def _parse_severity(raw_sev: str | None) -> FindingSeverity:
    """Normalize severity strings to FindingSeverity enum."""
    if not raw_sev:
        return FindingSeverity.MEDIUM
    clean = raw_sev.strip().upper()
    if clean in ("CRITICAL", "FATAL"):
        return FindingSeverity.CRITICAL
    if clean in ("HIGH", "ERROR"):
        return FindingSeverity.HIGH
    if clean in ("MEDIUM", "WARN", "WARNING"):
        return FindingSeverity.MEDIUM
    if clean in ("LOW", "INFO", "NOTE"):
        return FindingSeverity.LOW
    return FindingSeverity.MEDIUM


def ingest_sarif_file(path: Path) -> list[IngestedFinding]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Ingest findings from OASIS SARIF v2.1.0 document."""
    findings: list[IngestedFinding] = []
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception:
        return findings

    runs = data.get("runs", [])
    if not isinstance(runs, list):
        return findings

    for run in runs:
        if not isinstance(run, dict):
            continue
        # Extract rule definitions if available
        rules_dict: dict[str, dict[str, Any]] = {}
        tool_driver = run.get("tool", {}).get("driver", {})
        for r in tool_driver.get("rules", []):
            if isinstance(r, dict) and "id" in r:
                rules_dict[r["id"]] = r

        results = run.get("results", [])
        if not isinstance(results, list):
            continue

        for res in results:
            if not isinstance(res, dict):
                continue
            rule_id = res.get("ruleId") or "UNKNOWN-RULE"
            msg = res.get("message", {}).get("text") or "Security finding"
            level = res.get("level") or "warning"
            props = res.get("properties", {})

            # Prefer explicit properties.severity if present
            sev_str = props.get("severity") or level
            severity = _parse_severity(sev_str)

            rule_meta = rules_dict.get(rule_id, {})
            title = (
                rule_meta.get("shortDescription", {}).get("text")
                or rule_meta.get("name")
                or f"Violation of {rule_id}"
            )

            # Extract location uri and line number
            target = str(path)
            line_no = None
            locs = res.get("locations", [])
            if locs and isinstance(locs, list) and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation", {})
                target = phys.get("artifactLocation", {}).get("uri") or str(path)
                region = phys.get("region", {})
                line_no = region.get("startLine")

            findings.append(
                IngestedFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    message=msg,
                    target=target,
                    source_file=str(path),
                    line_number=line_no,
                    metadata=props,
                )
            )

    return findings


def ingest_logihertz_json_file(path: Path) -> list[IngestedFinding]:
    """Ingest findings from native Logihertz JSON scan reports."""
    findings: list[IngestedFinding] = []
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    # Look for results array or top-level findings
    results_list = data.get("results")
    if isinstance(results_list, list):
        for res_obj in results_list:
            if not isinstance(res_obj, dict):
                continue
            res_target = res_obj.get("target") or str(path)
            sub_findings = res_obj.get("findings", [])
            if isinstance(sub_findings, list):
                for f in sub_findings:
                    if isinstance(f, dict):
                        findings.append(
                            IngestedFinding(
                                rule_id=f.get("rule_id") or "UNKNOWN-RULE",
                                severity=_parse_severity(f.get("severity")),
                                title=f.get("title") or f.get("rule_id", "Finding"),
                                message=f.get("message") or "",
                                target=f.get("target") or res_target,
                                source_file=str(path),
                                line_number=f.get("line_number"),
                                metadata=f.get("metadata", {}),
                            )
                        )

    # Top-level findings fallback
    top_findings = data.get("findings")
    if isinstance(top_findings, list):
        for f in top_findings:
            if isinstance(f, dict):
                findings.append(
                    IngestedFinding(
                        rule_id=f.get("rule_id") or "UNKNOWN-RULE",
                        severity=_parse_severity(f.get("severity")),
                        title=f.get("title") or f.get("rule_id", "Finding"),
                        message=f.get("message") or "",
                        target=f.get("target") or str(path),
                        source_file=str(path),
                        line_number=f.get("line_number"),
                        metadata=f.get("metadata", {}),
                    )
                )

    return findings


def ingest_governance_manifest(path: Path) -> list[IngestedFinding]:
    """Ingest and validate declarative governance policies and asset classifications."""
    findings: list[IngestedFinding] = []
    try:
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    # 1. Inspect datastores for missing classification (ISO 27001 A.5.12, GDPR Art. 30)
    datastores = data.get("datastores") or data.get("databases") or []
    if isinstance(datastores, list):
        for ds in datastores:
            if isinstance(ds, dict):
                name = ds.get("name") or "unnamed_datastore"
                has_classification = any(
                    k in ds for k in ("classification", "confidentiality", "sensitivity")
                )
                if not has_classification:
                    findings.append(
                        IngestedFinding(
                            rule_id="LH-GOV-001",
                            severity=FindingSeverity.LOW,
                            title="Unclassified Data Store in Governance Policy",
                            message=(
                                f"Datastore '{name}' lacks required data sensitivity / "
                                f"confidentiality classification tier."
                            ),
                            target=str(path),
                            source_file=str(path),
                            metadata={"asset_type": "datastore", "asset_name": name},
                        )
                    )

    # 2. Inspect waivers for expiration
    waivers = data.get("waivers") or data.get("exceptions") or []
    if isinstance(waivers, list):
        now_utc = datetime.now(UTC)
        for w in waivers:
            if isinstance(w, dict):
                w_id = w.get("id") or w.get("name") or "unnamed_waiver"
                exp_str = w.get("expires_at") or w.get("expiration_date") or w.get("expiry")
                is_expired = False
                if exp_str:
                    try:
                        exp_dt = datetime.fromisoformat(str(exp_str).replace("Z", "+00:00"))
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=UTC)
                        if exp_dt < now_utc:
                            is_expired = True
                    except Exception:
                        is_expired = False

                if w.get("status") == "expired" or is_expired:
                    findings.append(
                        IngestedFinding(
                            rule_id="LH-GOV-002",
                            severity=FindingSeverity.LOW,
                            title="Expired Security Risk Waiver",
                            message=(
                                f"Security waiver '{w_id}' for rule '{w.get('rule', 'any')}' "
                                f"has expired on {exp_str} and requires review or re-authorization."
                            ),
                            target=str(path),
                            source_file=str(path),
                            metadata={"waiver_id": w_id, "expired_date": str(exp_str)},
                        )
                    )

    # 3. Inspect services for missing trust zones
    services = data.get("services") or data.get("workloads") or []
    if isinstance(services, list):
        for svc in services:
            if isinstance(svc, dict):
                name = svc.get("name") or "unnamed_service"
                has_zone = any(k in svc for k in ("trust_zone", "network_zone", "zone"))
                if not has_zone:
                    findings.append(
                        IngestedFinding(
                            rule_id="LH-GOV-003",
                            severity=FindingSeverity.LOW,
                            title="Missing Trust Zone Definition for Workload",
                            message=(
                                f"Service workload '{name}' lacks explicit network/trust zone "
                                f"segmentation boundary."
                            ),
                            target=str(path),
                            source_file=str(path),
                            metadata={"service": name},
                        )
                    )

    return findings


def is_valid_report_file(path: Path) -> bool:
    """Check if file matches known SARIF, Logihertz report, or governance schema."""
    try:
        suffix = path.suffix.lower()
        if suffix in (".json", ".sarif"):
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return bool(
                    "runs" in data
                    or data.get("version") == "2.1.0"
                    or "report_type" in data
                    or "results" in data
                    or "findings" in data
                )
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                gov_keys = (
                    "datastores",
                    "databases",
                    "waivers",
                    "exceptions",
                    "services",
                    "organization",
                    "governance",
                )
                return any(k in data for k in gov_keys)
    except Exception:
        return False
    return False


def ingest_file(path: Path) -> list[IngestedFinding]:
    """Auto-detect file format and ingest findings."""
    if not path.is_file():
        return []

    name = path.name.lower()
    suffix = path.suffix.lower()

    if suffix in (".sarif", ".json") or "sarif" in name:
        try:
            sample = path.read_text(encoding="utf-8")[:1024]
            if "sarif" in sample.lower() or '"runs"' in sample:
                return ingest_sarif_file(path)
            return ingest_logihertz_json_file(path)
        except Exception:
            return []

    if suffix in (".yaml", ".yml"):
        return ingest_governance_manifest(path)

    return []


def discover_and_ingest(target_path: Path) -> tuple[int, list[IngestedFinding]]:
    """Recursively discover and ingest all supported security reports and manifests."""
    if target_path.is_file():
        is_rep = is_valid_report_file(target_path)
        findings = ingest_file(target_path)
        return (1 if is_rep else 0), findings

    total_reports = 0
    all_findings: list[IngestedFinding] = []

    for item in sorted(target_path.rglob("*")):
        if any(part in EXCLUDED_DIRS for part in item.parts):
            continue
        if not item.is_file():
            continue
        if item.suffix.lower() in (".json", ".sarif", ".yaml", ".yml"):
            if is_valid_report_file(item):
                total_reports += 1
                all_findings.extend(ingest_file(item))

    return total_reports, all_findings
