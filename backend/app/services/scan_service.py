"""Orchestrates a scan: compliance -> risk -> attack graph -> ACO
(spec sections 17-23). Runs as a background task so bulk uploads don't
block on analysis (spec section 53).

Blockchain provenance recording (spec section 27+) hooks in at the end via
`app.blockchain.service`, which itself degrades to a PENDING queue if
Fabric is unreachable -- a scan always completes in Mongo regardless of
blockchain availability (spec section 34).
"""
from __future__ import annotations

import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.attack_graph.builder import build_attack_graph, serialize_graph
from app.attack_graph.paths import find_potential_attack_paths
from app.compliance.engine import run_compliance
from app.compliance.findings import derive_findings
from app.db import Collections
from app.models.scan import ScanStatus
from app.normalization.ir_schema import SecurityIR
from app.optimizer.aco import compare_strategies
from app.risk.engine import calculate_risk
from app.security.hashing import (
    calculate_attack_graph_hash,
    calculate_compliance_hash,
    calculate_risk_hash,
)
from app.utils.ids import new_optimizer_run_id, new_scan_id, utcnow_iso

logger = logging.getLogger("sih26155.scan")


async def _set_status(db: AsyncIOMotorDatabase, scan_id: str, status: ScanStatus, **extra) -> None:
    await db[Collections.SCANS].update_one(
        {"scan_id": scan_id}, {"$set": {"status": status.value, "updated_at": utcnow_iso(), **extra}}
    )


async def create_scan(db: AsyncIOMotorDatabase, *, device_id: str, triggered_by: str) -> dict:
    device = await db[Collections.DEVICES].find_one({"device_id": device_id})
    if not device:
        raise ValueError("Device not found")

    configuration = await db[Collections.CONFIGURATIONS].find_one({"device_id": device_id})
    if not configuration:
        raise ValueError("No configuration uploaded for this device")

    version_doc = await db[Collections.CONFIGURATION_VERSIONS].find_one(
        {"configuration_id": configuration["configuration_id"], "status": "COMPLETED"},
        sort=[("version", -1)],
    )
    if not version_doc:
        raise ValueError("No successfully normalized configuration version available for this device")

    scan_id = new_scan_id()
    doc = {
        "scan_id": scan_id,
        "device_id": device_id,
        "project_id": device["project_id"],
        "configuration_id": configuration["configuration_id"],
        "configuration_version": version_doc["version"],
        "configuration_hash": version_doc["configuration_hash"],
        "ir_hash": version_doc["ir_hash"],
        "status": ScanStatus.PENDING.value,
        "triggered_by": triggered_by,
        "created_at": utcnow_iso(),
        "updated_at": utcnow_iso(),
        "error_message": None,
    }
    await db[Collections.SCANS].insert_one(doc)
    doc.pop("_id", None)
    return doc


async def run_scan_pipeline(db: AsyncIOMotorDatabase, scan_id: str) -> None:
    scan = await db[Collections.SCANS].find_one({"scan_id": scan_id})
    if not scan:
        logger.error("Scan %s not found for pipeline execution", scan_id)
        return

    try:
        device = await db[Collections.DEVICES].find_one({"device_id": scan["device_id"]})
        version_doc = await db[Collections.CONFIGURATION_VERSIONS].find_one(
            {"configuration_id": scan["configuration_id"], "version": scan["configuration_version"]}
        )
        ir = SecurityIR(**version_doc["security_ir"])
        asset_context = device.get("asset_context", {})

        await _set_status(db, scan_id, ScanStatus.COMPLIANCE_ANALYSIS)
        compliance_result = run_compliance(ir)
        compliance_hash = calculate_compliance_hash(compliance_result)
        await db[Collections.COMPLIANCE_RESULTS].insert_one(
            {"scan_id": scan_id, "device_id": scan["device_id"], **compliance_result, "compliance_hash": compliance_hash, "created_at": utcnow_iso()}
        )

        findings = derive_findings(compliance_result, device_id=scan["device_id"], scan_id=scan_id)
        if findings:
            await db[Collections.FINDINGS].insert_many([dict(f) for f in findings])

        await _set_status(db, scan_id, ScanStatus.RISK_ANALYSIS)
        risk = calculate_risk(ir, compliance_result, findings, asset_context)
        risk_hash = calculate_risk_hash(risk)
        await db[Collections.RISK_SCORES].insert_one(
            {"scan_id": scan_id, "device_id": scan["device_id"], **risk, "risk_hash": risk_hash, "timestamp": utcnow_iso()}
        )

        await _set_status(db, scan_id, ScanStatus.BUILDING_ATTACK_GRAPH)
        graph = build_attack_graph(ir, device_id=scan["device_id"], device_name=device["name"], asset_context=asset_context)
        serialized_graph = serialize_graph(graph)
        potential_paths = find_potential_attack_paths(graph, findings)
        attack_graph_hash = calculate_attack_graph_hash(serialized_graph)
        await db[Collections.ATTACK_GRAPHS].insert_one(
            {
                "scan_id": scan_id,
                "device_id": scan["device_id"],
                "graph": serialized_graph,
                "potential_attack_paths": potential_paths,
                "attack_graph_hash": attack_graph_hash,
                "created_at": utcnow_iso(),
            }
        )

        await _set_status(db, scan_id, ScanStatus.OPTIMIZING)
        if findings:
            comparison = compare_strategies(findings, potential_paths)
            optimizer_run_id = new_optimizer_run_id()
            await db[Collections.OPTIMIZER_RUNS].insert_one(
                {
                    "optimizer_run_id": optimizer_run_id,
                    "scan_id": scan_id,
                    "device_id": scan["device_id"],
                    **comparison,
                    "created_at": utcnow_iso(),
                }
            )
        else:
            optimizer_run_id = None

        await _set_status(db, scan_id, ScanStatus.RECORDING_BLOCKCHAIN)
        try:
            from app.blockchain.service import record_audit_completed

            blockchain_status = await record_audit_completed(
                db,
                audit_id=scan_id,
                device_id=scan["device_id"],
                actor_id=scan["triggered_by"],
                configuration_hash=scan["configuration_hash"],
                compliance_hash=compliance_hash,
                risk_hash=risk_hash,
            )
        except Exception:
            logger.exception("Blockchain recording failed for scan %s; continuing (Mongo evidence is authoritative)", scan_id)
            blockchain_status = {"status": "PENDING", "reason": "blockchain service error"}

        await _set_status(
            db,
            scan_id,
            ScanStatus.COMPLETED,
            compliance_score=compliance_result["compliance_score"],
            risk_score=risk["risk_score"],
            optimizer_run_id=optimizer_run_id,
            blockchain_status=blockchain_status.get("status"),
        )
    except Exception as exc:
        logger.exception("Scan pipeline failed for %s", scan_id)
        await _set_status(db, scan_id, ScanStatus.FAILED, error_message=str(exc))
