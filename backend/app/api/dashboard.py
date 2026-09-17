"""Dashboard aggregate endpoint (spec section 43). Every number here is a
real aggregation over MongoDB -- nothing is hard-coded."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_request_id
from app.auth.access import accessible_project_filter, require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.schemas.common import ok


async def _scope_query(db, user: CurrentUser, project_id: str | None) -> dict:
    if project_id:
        await require_project_access(db, user, project_id)
        return {"project_id": project_id}
    return await accessible_project_filter(db, user)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
async def dashboard_summary(
    project_id: str | None = None,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    scoped_query = await _scope_query(db, user, project_id)
    device_query = scoped_query
    config_query = scoped_query

    total_devices = await db[Collections.DEVICES].count_documents(device_query)
    total_configurations = await db[Collections.CONFIGURATIONS].count_documents(config_query)

    scan_query = scoped_query
    total_scans = await db[Collections.SCANS].count_documents(scan_query)
    completed_scans = await db[Collections.SCANS].find({**scan_query, "status": "COMPLETED"}, {"_id": 0}).to_list(length=5000)

    compliance_scores = [s["compliance_score"] for s in completed_scans if s.get("compliance_score") is not None]
    risk_scores = [s["risk_score"] for s in completed_scans if s.get("risk_score") is not None]
    avg_compliance = round(sum(compliance_scores) / len(compliance_scores), 2) if compliance_scores else None
    avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else None

    scan_ids = [s["scan_id"] for s in completed_scans]
    findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_potential_paths = 0
    if scan_ids:
        async for f in db[Collections.FINDINGS].find({"scan_id": {"$in": scan_ids}}, {"_id": 0, "severity": 1}):
            if f["severity"] in findings_by_severity:
                findings_by_severity[f["severity"]] += 1
        async for g in db[Collections.ATTACK_GRAPHS].find({"scan_id": {"$in": scan_ids}}, {"_id": 0, "potential_attack_paths": 1}):
            total_potential_paths += len(g.get("potential_attack_paths", []))

    # REMEDIATION_PLANS and BLOCKCHAIN_TRANSACTIONS have no project_id of their
    # own (they key off device_id/finding_id), so scope them by the accessible
    # device set -- otherwise every user's dashboard would aggregate over
    # every other user's remediation/blockchain activity too (admins still see
    # everything, since device_query is unrestricted for them).
    accessible_device_ids = await db[Collections.DEVICES].distinct("device_id", device_query)
    device_scope = {"device_id": {"$in": accessible_device_ids}} if scoped_query else {}

    remediation_total = await db[Collections.REMEDIATION_PLANS].count_documents(device_scope)
    remediation_done = await db[Collections.REMEDIATION_PLANS].count_documents(
        {**device_scope, "status": {"$in": ["APPROVED", "SIMULATED"]}}
    )
    remediation_progress = round((remediation_done / remediation_total) * 100, 2) if remediation_total else None

    audit_events = await db[Collections.BLOCKCHAIN_TRANSACTIONS].count_documents({**device_scope, "event_type": "AUDIT_COMPLETED"})
    confirmed_events = await db[Collections.BLOCKCHAIN_TRANSACTIONS].count_documents(
        {**device_scope, "event_type": "AUDIT_COMPLETED", "status": "CONFIRMED"}
    )
    blockchain_verification_rate = round((confirmed_events / audit_events) * 100, 2) if audit_events else None

    # Compliance-by-framework aggregate (average coverage across completed scans' compliance results).
    framework_totals: dict[str, list[float]] = {}
    if scan_ids:
        async for c in db[Collections.COMPLIANCE_RESULTS].find({"scan_id": {"$in": scan_ids}}, {"_id": 0, "framework_coverage": 1}):
            for key, info in (c.get("framework_coverage") or {}).items():
                if info.get("coverage_percent") is not None:
                    framework_totals.setdefault(key, []).append(info["coverage_percent"])
    compliance_by_framework = {
        k: round(sum(v) / len(v), 2) for k, v in framework_totals.items()
    }

    return ok(
        {
            "total_devices": total_devices,
            "total_configurations": total_configurations,
            "total_audits": total_scans,
            "average_compliance_percent": avg_compliance,
            "average_risk_score": avg_risk,
            "findings_by_severity": findings_by_severity,
            "potential_attack_paths": total_potential_paths,
            "remediation_progress_percent": remediation_progress,
            "blockchain_verification_rate_percent": blockchain_verification_rate,
            "compliance_by_framework": compliance_by_framework,
        },
        request_id,
    )


@router.get("/risk-trend")
async def risk_trend(
    project_id: str | None = None,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    query = {"status": "COMPLETED", **await _scope_query(db, user, project_id)}
    scans = (
        await db[Collections.SCANS]
        .find(query, {"_id": 0, "scan_id": 1, "created_at": 1, "risk_score": 1, "compliance_score": 1, "device_id": 1})
        .sort("created_at", 1)
        .to_list(length=500)
    )
    return ok(scans, request_id)
