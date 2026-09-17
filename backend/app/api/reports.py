from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from app.api.deps import get_request_id
from app.auth.access import require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.reporting.pdf_generator import generate_audit_report
from app.schemas.common import AppError, ErrorCode, ok
from app.security.hashing import calculate_report_hash
from app.utils.ids import new_report_id, utcnow_iso

router = APIRouter(prefix="/api/reports", tags=["reports"])


class GenerateReportRequest(BaseModel):
    scan_id: str


@router.post("/generate")
async def generate_report(
    body: GenerateReportRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    scan = await db[Collections.SCANS].find_one({"scan_id": body.scan_id}, {"_id": 0})
    if not scan:
        raise AppError(ErrorCode.NOT_FOUND, "Scan not found", 404)
    await require_project_access(db, user, scan["project_id"])
    if scan.get("status") != "COMPLETED":
        raise AppError(ErrorCode.VALIDATION_ERROR, f"Scan is not completed (status={scan.get('status')})", 400)

    device = await db[Collections.DEVICES].find_one({"device_id": scan["device_id"]}, {"_id": 0})
    compliance = await db[Collections.COMPLIANCE_RESULTS].find_one({"scan_id": body.scan_id}, {"_id": 0})
    risk = await db[Collections.RISK_SCORES].find_one({"scan_id": body.scan_id}, {"_id": 0}, sort=[("timestamp", -1)])
    attack_graph = await db[Collections.ATTACK_GRAPHS].find_one({"scan_id": body.scan_id}, {"_id": 0}) or {}
    optimizer = None
    if scan.get("optimizer_run_id"):
        optimizer = await db[Collections.OPTIMIZER_RUNS].find_one({"optimizer_run_id": scan["optimizer_run_id"]}, {"_id": 0})

    blockchain_tx = await db[Collections.BLOCKCHAIN_TRANSACTIONS].find_one(
        {"audit_id": body.scan_id, "event_type": "AUDIT_COMPLETED"}, {"_id": 0}
    )
    blockchain_info = blockchain_tx or {"status": "PENDING", "transaction_id": None}

    if not compliance or not risk:
        raise AppError(ErrorCode.VALIDATION_ERROR, "Scan is missing compliance or risk evidence", 400)

    report_id = new_report_id()
    pdf_bytes = generate_audit_report(
        scan=scan, device=device or {}, compliance=compliance, risk=risk,
        attack_graph=attack_graph, optimizer=optimizer, blockchain=blockchain_info,
        report_id=report_id,
    )
    report_hash = calculate_report_hash(pdf_bytes)

    from app.config import get_settings

    settings = get_settings()
    reports_dir = settings.upload_storage_path.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    storage_path = reports_dir / f"{report_id}.pdf"
    storage_path.write_bytes(pdf_bytes)

    report_doc = {
        "report_id": report_id,
        "scan_id": body.scan_id,
        "device_id": scan["device_id"],
        "report_hash": report_hash,
        "storage_path": str(storage_path),
        "generated_by": user.user_id,
        "generated_at": utcnow_iso(),
        "size_bytes": len(pdf_bytes),
    }
    await db[Collections.REPORTS].insert_one(dict(report_doc))

    try:
        from app.blockchain.service import record_event

        await record_event(
            db, audit_id=body.scan_id, device_id=scan["device_id"], actor_id=user.user_id,
            event_type="REPORT_GENERATED", report_hash=report_hash,
        )
    except Exception:
        pass  # report generation must succeed even if blockchain recording is delayed

    return ok(report_doc, request_id)


async def _require_report_access(db, user: CurrentUser, doc: dict) -> None:
    """A report has no owner of its own -- it inherits access from the
    device (via project) it was generated for."""
    device = await db[Collections.DEVICES].find_one({"device_id": doc["device_id"]}, {"_id": 0, "project_id": 1})
    if device:
        await require_project_access(db, user, device["project_id"])


@router.get("/{report_id}")
async def get_report(report_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    doc = await db[Collections.REPORTS].find_one({"report_id": report_id}, {"_id": 0, "storage_path": 0})
    if not doc:
        raise AppError(ErrorCode.NOT_FOUND, "Report not found", 404)
    await _require_report_access(db, user, doc)
    return ok(doc, request_id)


@router.get("/{report_id}/download")
async def download_report(report_id: str, user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    doc = await db[Collections.REPORTS].find_one({"report_id": report_id})
    if not doc:
        raise AppError(ErrorCode.NOT_FOUND, "Report not found", 404)
    await _require_report_access(db, user, doc)
    from pathlib import Path

    pdf_bytes = Path(doc["storage_path"]).read_bytes()
    return Response(content=pdf_bytes, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{report_id}.pdf"'
    })
