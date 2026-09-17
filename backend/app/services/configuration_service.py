"""Upload processing pipeline: validate -> hash -> duplicate-check -> store
-> detect vendor -> parse -> normalize -> persist (spec sections 9-16).

This is the synchronous, fast part of the pipeline. The heavier analysis
(compliance/risk/attack-graph/ACO/AI/blockchain) runs separately as a scan
(see services/scan_service.py) so large batches of uploads don't block on
minutes-long analysis.
"""
from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import Collections
from app.ingestion.duplicate import find_duplicate_version
from app.ingestion.storage import store_upload
from app.ingestion.validation import validate_upload
from app.models.configuration import ProcessingStatus
from app.schemas.common import AppError, ErrorCode
from app.security.hashing import calculate_configuration_hash, calculate_ir_hash
from app.security.secret_redaction import detect_secrets
from app.utils.ids import new_configuration_id, utcnow_iso
from app.vendors.registry import (
    AUTHORITATIVE_CONFIDENCE_THRESHOLD,
    detect_vendor,
    parse_configuration,
)


async def _next_version(db: AsyncIOMotorDatabase, configuration_id: str) -> int:
    latest = await db[Collections.CONFIGURATION_VERSIONS].find_one(
        {"configuration_id": configuration_id}, sort=[("version", -1)]
    )
    return (latest["version"] + 1) if latest else 1


async def _get_or_create_configuration(
    db: AsyncIOMotorDatabase, device_id: str, project_id: str
) -> str:
    existing = await db[Collections.CONFIGURATIONS].find_one({"device_id": device_id})
    if existing:
        return existing["configuration_id"]

    configuration_id = new_configuration_id()
    await db[Collections.CONFIGURATIONS].insert_one(
        {
            "configuration_id": configuration_id,
            "device_id": device_id,
            "project_id": project_id,
            "latest_version": 0,
            "created_at": utcnow_iso(),
        }
    )
    return configuration_id


async def _record_unmapped_commands(
    db: AsyncIOMotorDatabase, *, device_id: str, vendor: str, configuration_id: str, version: int, ir: dict
) -> None:
    unmapped = ir.get("unmapped_commands") or []
    for cmd in unmapped:
        raw_line = cmd["raw_line"]
        existing = await db[Collections.UNKNOWN_PATTERNS].find_one(
            {"vendor": vendor, "raw_line": raw_line}
        )
        if existing:
            await db[Collections.UNKNOWN_PATTERNS].update_one(
                {"_id": existing["_id"]},
                {"$inc": {"occurrence_count": 1}, "$set": {"last_seen_at": utcnow_iso()}},
            )
        else:
            await db[Collections.UNKNOWN_PATTERNS].insert_one(
                {
                    "vendor": vendor,
                    "raw_line": raw_line,
                    "line_number": cmd.get("line_number"),
                    "device_id": device_id,
                    "configuration_id": configuration_id,
                    "version": version,
                    "status": "pending_review",
                    "ai_suggestion": None,
                    "occurrence_count": 1,
                    "first_seen_at": utcnow_iso(),
                    "last_seen_at": utcnow_iso(),
                }
            )


async def process_upload(
    db: AsyncIOMotorDatabase,
    *,
    project_id: str,
    device_id: str,
    filename: str,
    content: bytes,
    uploaded_by: str,
    vendor_hint: str | None = None,
) -> dict:
    validated = validate_upload(filename, content)
    configuration_hash = calculate_configuration_hash(content)

    duplicate = await find_duplicate_version(db, device_id, configuration_hash)
    if duplicate:
        raise AppError(
            ErrorCode.DUPLICATE_UPLOAD,
            f"Identical configuration already exists as version {duplicate['version']} "
            f"(uploaded {duplicate['uploaded_at']})",
            409,
        )

    storage_id = store_upload(content, validated.extension)
    secret_findings = detect_secrets(validated.text)

    configuration_id = await _get_or_create_configuration(db, device_id, project_id)
    version = await _next_version(db, configuration_id)

    detection = detect_vendor(validated.text, metadata_hint=vendor_hint)

    doc: dict = {
        "configuration_id": configuration_id,
        "device_id": device_id,
        "project_id": project_id,
        "version": version,
        "original_filename": validated.original_filename,
        "storage_id": storage_id,
        "vendor": detection.vendor,
        "platform": detection.platform,
        "vendor_confidence": detection.confidence,
        "vendor_detection_method": detection.method,
        "software_version": None,
        "file_size": validated.size_bytes,
        "encoding": validated.encoding,
        "uploaded_by": uploaded_by,
        "uploaded_at": utcnow_iso(),
        "configuration_hash": configuration_hash,
        "ir_hash": None,
        "secret_findings": secret_findings,
        "status": ProcessingStatus.DETECTING_VENDOR.value,
        "error_message": None,
        "security_ir": None,
    }

    needs_confirmation = detection.confidence < AUTHORITATIVE_CONFIDENCE_THRESHOLD and not vendor_hint

    if needs_confirmation:
        doc["status"] = ProcessingStatus.NEEDS_VENDOR_CONFIRMATION.value
    elif not detection.implemented:
        doc["status"] = ProcessingStatus.FAILED.value
        doc["error_message"] = (
            f"A parser for vendor '{detection.vendor}' is architected but not yet implemented. "
            "Hash and vendor-signature detection succeeded; automated normalization did not run."
        )
    else:
        try:
            ir = parse_configuration(detection.vendor, validated.text)
        except Exception as exc:  # parser bug or malformed config -- never fabricate an IR
            doc["status"] = ProcessingStatus.FAILED.value
            doc["error_message"] = f"Parser failure: {exc}"
        else:
            ir_dict = ir.model_dump(mode="json")
            doc["security_ir"] = ir_dict
            doc["ir_hash"] = calculate_ir_hash(ir_dict)
            doc["software_version"] = ir.device.version
            doc["status"] = ProcessingStatus.COMPLETED.value
            await _record_unmapped_commands(
                db,
                device_id=device_id,
                vendor=detection.vendor,
                configuration_id=configuration_id,
                version=version,
                ir=ir_dict,
            )

    await db[Collections.CONFIGURATION_VERSIONS].insert_one(doc)
    await db[Collections.CONFIGURATIONS].update_one(
        {"configuration_id": configuration_id}, {"$set": {"latest_version": version}}
    )

    doc.pop("_id", None)
    return doc
