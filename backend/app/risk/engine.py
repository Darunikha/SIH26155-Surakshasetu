"""Dynamic risk engine (spec sections 20-21).

Risk = weighted combination of Exposure, Asset Criticality, Vulnerability
density, and Control-failure rate -- each normalized to 0-100, then combined
by documented fixed weights and clipped to 0-100. Nothing here is
hard-coded to a specific final score: every subscore is derived from the
actual IR/findings/asset-context for this scan.

Recalculating with a different asset context (spec section 21) simply
re-runs this function with the new context -- historical risk_scores
documents are never mutated in place.
"""
from __future__ import annotations

from app.normalization.ir_schema import SecurityIR

CALCULATION_VERSION = "1.0"

# Fixed, documented weights (sum to 1.0). Changing these requires bumping
# CALCULATION_VERSION so historical scores remain interpretable.
WEIGHTS = {
    "exposure": 0.30,
    "asset_criticality": 0.20,
    "vulnerability": 0.30,
    "control_failure": 0.20,
}

_CRITICALITY_SCORE = {"low": 25, "high": 75, "critical": 100, "medium": 50}
_SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3}

RISK_BANDS = (
    (0, 30, "LOW"),
    (31, 60, "MEDIUM"),
    (61, 80, "HIGH"),
    (81, 100, "CRITICAL"),
)


def _risk_level(score: float) -> str:
    for lo, hi, label in RISK_BANDS:
        if lo <= score <= hi:
            return label
    return "CRITICAL"


def _exposure_score(ir: SecurityIR, asset_context: dict) -> float:
    internet_exposed = ir.internet_exposed or bool(asset_context.get("internet_exposure"))
    base = 85.0 if internet_exposed else 15.0
    if internet_exposed and (ir.management.telnet_enabled or ir.management.http_management):
        base = min(100.0, base + 15.0)
    return base


def _asset_criticality_score(asset_context: dict) -> float:
    criticality = str(asset_context.get("criticality", "medium")).lower()
    return float(_CRITICALITY_SCORE.get(criticality, 50))


def _vulnerability_score(findings: list[dict]) -> float:
    total = sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    return float(min(100, total))


def _control_failure_score(compliance_result: dict) -> float:
    counts = compliance_result["status_counts"]
    applicable = counts["PASS"] + counts["FAIL"]
    if applicable == 0:
        return 50.0  # neutral: not enough applicable evidence either way
    return round((counts["FAIL"] / applicable) * 100, 2)


def calculate_risk(ir: SecurityIR, compliance_result: dict, findings: list[dict], asset_context: dict) -> dict:
    exposure = _exposure_score(ir, asset_context)
    criticality = _asset_criticality_score(asset_context)
    vulnerability = _vulnerability_score(findings)
    control_failure = _control_failure_score(compliance_result)

    raw_score = (
        exposure * WEIGHTS["exposure"]
        + criticality * WEIGHTS["asset_criticality"]
        + vulnerability * WEIGHTS["vulnerability"]
        + control_failure * WEIGHTS["control_failure"]
    )
    risk_score = round(max(0.0, min(100.0, raw_score)), 2)

    return {
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "risk_factors": {
            "exposure": {"score": exposure, "weight": WEIGHTS["exposure"]},
            "asset_criticality": {"score": criticality, "weight": WEIGHTS["asset_criticality"]},
            "vulnerability": {"score": vulnerability, "weight": WEIGHTS["vulnerability"]},
            "control_failure": {"score": control_failure, "weight": WEIGHTS["control_failure"]},
        },
        "calculation_version": CALCULATION_VERSION,
    }
