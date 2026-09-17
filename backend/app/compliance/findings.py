"""Derives Findings from FAIL compliance results.

A Finding is the user-facing unit of "something is wrong" -- one per failed
control per scan. Risk and attack-graph analysis both consume this list.
"""
from __future__ import annotations

from app.compliance.models import ComplianceStatus
from app.utils.ids import new_finding_id, utcnow_iso


def derive_findings(compliance_result: dict, *, device_id: str, scan_id: str) -> list[dict]:
    findings = []
    for control in compliance_result["controls"]:
        if control["status"] != ComplianceStatus.FAIL.value:
            continue
        findings.append(
            {
                "finding_id": new_finding_id(),
                "scan_id": scan_id,
                "device_id": device_id,
                "control_id": control["control_id"],
                "title": control["title"],
                "description": control["description"],
                "category": control["category"],
                "severity": control["severity"],
                "status": control["status"],
                "evidence": control["evidence"],
                "notes": control["notes"],
                "framework_mappings": control["framework_mappings"],
                "created_at": utcnow_iso(),
            }
        )
    return findings
