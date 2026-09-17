from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.ai.exceptions import AIUnavailableError
from app.ai.service import AIService
from app.api.deps import get_request_id
from app.auth.access import require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.optimizer.aco import compare_strategies
from app.schemas.common import AppError, ErrorCode, ok
from app.utils.ids import new_optimizer_run_id, utcnow_iso

router = APIRouter(prefix="/api/optimizer", tags=["optimizer"])


class RunOptimizerRequest(BaseModel):
    scan_id: str
    budget: int | None = None


@router.post("/run")
async def run_optimizer(
    body: RunOptimizerRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    scan = await db[Collections.SCANS].find_one({"scan_id": body.scan_id})
    if not scan:
        raise AppError(ErrorCode.NOT_FOUND, "Scan not found", 404)
    await require_project_access(db, user, scan["project_id"])

    findings = await db[Collections.FINDINGS].find({"scan_id": body.scan_id}, {"_id": 0}).to_list(length=1000)
    graph_doc = await db[Collections.ATTACK_GRAPHS].find_one({"scan_id": body.scan_id})
    potential_paths = graph_doc.get("potential_attack_paths", []) if graph_doc else []

    if not findings:
        raise AppError(ErrorCode.VALIDATION_ERROR, "No findings to optimize for this scan", 400)

    comparison = compare_strategies(findings, potential_paths, budget=body.budget)
    optimizer_run_id = new_optimizer_run_id()
    doc = {
        "optimizer_run_id": optimizer_run_id,
        "scan_id": body.scan_id,
        "device_id": scan["device_id"],
        **comparison,
        "created_at": utcnow_iso(),
    }
    await db[Collections.OPTIMIZER_RUNS].insert_one(doc)
    doc.pop("_id", None)
    return ok(doc, request_id)


@router.get("/{optimizer_run_id}")
async def get_optimizer_run(
    optimizer_run_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    doc = await db[Collections.OPTIMIZER_RUNS].find_one({"optimizer_run_id": optimizer_run_id}, {"_id": 0})
    if not doc:
        raise AppError(ErrorCode.NOT_FOUND, "Optimizer run not found", 404)
    scan = await db[Collections.SCANS].find_one({"scan_id": doc["scan_id"]}, {"_id": 0, "project_id": 1})
    if scan:
        await require_project_access(db, user, scan["project_id"])
    return ok(doc, request_id)


@router.post("/{optimizer_run_id}/ai-summary")
async def get_optimizer_ai_summary(
    optimizer_run_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    doc = await db[Collections.OPTIMIZER_RUNS].find_one({"optimizer_run_id": optimizer_run_id}, {"_id": 0})
    if not doc:
        raise AppError(ErrorCode.NOT_FOUND, "Optimizer run not found", 404)
    scan = await db[Collections.SCANS].find_one({"scan_id": doc["scan_id"]}, {"_id": 0, "project_id": 1})
    if scan:
        await require_project_access(db, user, scan["project_id"])

    findings = await db[Collections.FINDINGS].find({"scan_id": doc["scan_id"]}, {"_id": 0}).to_list(length=1000)
    findings_by_id = {f["finding_id"]: f for f in findings}

    ai = AIService()
    try:
        result = await ai.summarize_optimizer(strategies=doc["strategies"], findings_by_id=findings_by_id)
    except AIUnavailableError as exc:
        raise AppError(ErrorCode.AI_UNAVAILABLE, str(exc), 503) from exc
    return ok(result, request_id)
