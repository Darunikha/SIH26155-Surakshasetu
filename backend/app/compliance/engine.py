"""Deterministic compliance engine (spec section 17).

Pipeline: Framework -> Control -> Requirement -> IR Evidence -> Rule
Evaluation -> Result. Purely a function of the Security IR -- no AI
involvement, ever (spec: "The AI must never override deterministic
compliance results").
"""
from __future__ import annotations

from app.compliance.controls import CONTROLS
from app.compliance.frameworks import FRAMEWORKS
from app.compliance.models import ComplianceStatus
from app.normalization.ir_schema import SecurityIR


def run_compliance(ir: SecurityIR) -> dict:
    control_results = []
    for control in CONTROLS:
        evaluation = control.evaluate(ir)
        control_results.append(
            {
                "control_id": control.control_id,
                "title": control.title,
                "description": control.description,
                "category": control.category,
                "severity": control.severity.value,
                "framework_mappings": [
                    {"framework": m.framework, "control_id": m.control_id} for m in control.framework_mappings
                ],
                "status": evaluation.status.value,
                "evidence": evaluation.evidence,
                "notes": evaluation.notes,
            }
        )

    framework_coverage = {}
    for key, info in FRAMEWORKS.items():
        implemented_ids = {
            c["control_id"]
            for c in control_results
            if any(m["framework"] == key for m in c["framework_mappings"])
        }
        implemented_count = len(implemented_ids)
        coverage_pct = (
            round((implemented_count / info.total_controls) * 100, 2)
            if info.total_controls
            else None
        )
        framework_coverage[key] = {
            "framework": info.display_name,
            "implemented_controls": implemented_count,
            "total_controls": info.total_controls,
            "coverage_percent": coverage_pct,
            "note": info.note,
        }

    status_counts = {status.value: 0 for status in ComplianceStatus}
    severity_of_failures: dict[str, int] = {}
    for c in control_results:
        status_counts[c["status"]] += 1
        if c["status"] == ComplianceStatus.FAIL.value:
            severity_of_failures[c["severity"]] = severity_of_failures.get(c["severity"], 0) + 1

    total_applicable = sum(
        status_counts[s]
        for s in (ComplianceStatus.PASS.value, ComplianceStatus.FAIL.value)
    )
    compliance_score = (
        round((status_counts[ComplianceStatus.PASS.value] / total_applicable) * 100, 2)
        if total_applicable
        else None
    )

    return {
        "controls": control_results,
        "framework_coverage": framework_coverage,
        "status_counts": status_counts,
        "failures_by_severity": severity_of_failures,
        "compliance_score": compliance_score,  # None if no applicable (PASS/FAIL) controls could be evaluated
    }
