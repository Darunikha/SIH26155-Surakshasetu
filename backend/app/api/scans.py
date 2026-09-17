from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel

from app.ai.exceptions import AIUnavailableError
from app.ai.service import AIService
from app.api.deps import get_request_id
from app.auth.access import accessible_project_filter, require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.schemas.common import AppError, ErrorCode, ok
from app.services.scan_service import create_scan, run_scan_pipeline

router = APIRouter(prefix="/api/scans", tags=["scans"])


class CreateScanRequest(BaseModel):
    device_id: str


async def _require_scan_access(db, user: CurrentUser, scan_id: str) -> dict:
    """Loads the scan and enforces project ownership, or raises NOT_FOUND/FORBIDDEN.
    Every per-scan endpoint below must call this before returning scan-derived
    data -- a scan has no owner of its own, only its parent project does."""
    scan = await db[Collections.SCANS].find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan:
        raise AppError(ErrorCode.NOT_FOUND, "Scan not found", 404)
    await require_project_access(db, user, scan["project_id"])
    return scan


@router.post("")
async def start_scan(
    body: CreateScanRequest,
    background_tasks: BackgroundTasks,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    device = await db[Collections.DEVICES].find_one({"device_id": body.device_id}, {"_id": 0, "project_id": 1})
    if device:
        await require_project_access(db, user, device["project_id"])
    try:
        scan = await create_scan(db, device_id=body.device_id, triggered_by=user.user_id)
    except ValueError as exc:
        raise AppError(ErrorCode.VALIDATION_ERROR, str(exc), 400) from exc

    background_tasks.add_task(run_scan_pipeline, db, scan["scan_id"])
    return ok(scan, request_id)


@router.get("")
async def list_scans(
    device_id: str | None = None,
    project_id: str | None = None,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    query: dict = {}
    if device_id:
        query["device_id"] = device_id
    if project_id:
        await require_project_access(db, user, project_id)
        query["project_id"] = project_id
    else:
        query.update(await accessible_project_filter(db, user))
    scans = await db[Collections.SCANS].find(query, {"_id": 0}).sort("created_at", -1).to_list(length=500)
    return ok(scans, request_id)


@router.get("/{scan_id}")
async def get_scan(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    scan = await _require_scan_access(db, user, scan_id)
    return ok(scan, request_id)


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    await _require_scan_access(db, user, scan_id)
    scan = await db[Collections.SCANS].find_one({"scan_id": scan_id}, {"_id": 0, "status": 1, "scan_id": 1, "error_message": 1, "updated_at": 1})
    return ok(scan, request_id)


@router.get("/{scan_id}/compliance")
async def get_scan_compliance(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    await _require_scan_access(db, user, scan_id)
    result = await db[Collections.COMPLIANCE_RESULTS].find_one({"scan_id": scan_id}, {"_id": 0})
    if not result:
        raise AppError(ErrorCode.NOT_FOUND, "Compliance results not found for this scan", 404)
    return ok(result, request_id)


@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    await _require_scan_access(db, user, scan_id)
    findings = await db[Collections.FINDINGS].find({"scan_id": scan_id}, {"_id": 0}).to_list(length=1000)
    return ok(findings, request_id)


@router.get("/{scan_id}/risk")
async def get_scan_risk(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    await _require_scan_access(db, user, scan_id)
    risk = await db[Collections.RISK_SCORES].find_one({"scan_id": scan_id}, {"_id": 0}, sort=[("timestamp", -1)])
    if not risk:
        raise AppError(ErrorCode.NOT_FOUND, "Risk score not found for this scan", 404)
    return ok(risk, request_id)


@router.post("/{scan_id}/risk/ai-summary")
async def get_risk_ai_summary(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    await _require_scan_access(db, user, scan_id)
    risk = await db[Collections.RISK_SCORES].find_one({"scan_id": scan_id}, {"_id": 0}, sort=[("timestamp", -1)])
    if not risk:
        raise AppError(ErrorCode.NOT_FOUND, "Risk score not found for this scan", 404)

    findings = (
        await db[Collections.FINDINGS]
        .find({"scan_id": scan_id}, {"_id": 0, "title": 1, "description": 1, "severity": 1})
        .to_list(length=1000)
    )
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top_findings = sorted(findings, key=lambda f: severity_rank.get(f.get("severity"), 4))[:8]

    ai = AIService()
    try:
        result = await ai.summarize_risk(
            risk_score=risk["risk_score"], risk_level=risk["risk_level"], risk_factors=risk["risk_factors"], top_findings=top_findings
        )
    except AIUnavailableError as exc:
        raise AppError(ErrorCode.AI_UNAVAILABLE, str(exc), 503) from exc
    return ok(result, request_id)


@router.get("/{scan_id}/attack-paths")
async def get_scan_attack_paths(scan_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    await _require_scan_access(db, user, scan_id)
    graph_doc = await db[Collections.ATTACK_GRAPHS].find_one({"scan_id": scan_id}, {"_id": 0})
    if not graph_doc:
        raise AppError(ErrorCode.NOT_FOUND, "Attack graph not found for this scan", 404)
    return ok(graph_doc, request_id)
