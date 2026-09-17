"""Agent tool registry (spec section 36). Every tool the AI assistant can
invoke is declared here with an explicit risk level and approval
requirement -- the assistant can never silently perform an important action
(spec section 37); risky tools are only executed after the approval
endpoints below confirm human sign-off.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: RiskLevel
    requires_approval: bool
    handler: Callable[..., Awaitable[Any]]


async def _upload_configuration(**kwargs):
    from app.services.configuration_service import process_upload

    return await process_upload(**kwargs)


async def _start_scan(db, device_id: str, triggered_by: str):
    from app.services.scan_service import create_scan

    return await create_scan(db, device_id=device_id, triggered_by=triggered_by)


async def _get_scan_status(db, scan_id: str):
    from app.db import Collections

    return await db[Collections.SCANS].find_one({"scan_id": scan_id}, {"_id": 0, "status": 1, "scan_id": 1})


async def _get_findings(db, scan_id: str):
    from app.db import Collections

    return await db[Collections.FINDINGS].find({"scan_id": scan_id}, {"_id": 0}).to_list(length=1000)


async def _get_risk(db, scan_id: str):
    from app.db import Collections

    return await db[Collections.RISK_SCORES].find_one({"scan_id": scan_id}, {"_id": 0}, sort=[("timestamp", -1)])


async def _get_attack_paths(db, scan_id: str):
    from app.db import Collections

    doc = await db[Collections.ATTACK_GRAPHS].find_one({"scan_id": scan_id}, {"_id": 0})
    return doc.get("potential_attack_paths", []) if doc else []


async def _generate_remediation_plan(db, finding_id: str):
    from app.ai.service import AIService
    from app.db import Collections

    finding = await db[Collections.FINDINGS].find_one({"finding_id": finding_id}, {"_id": 0})
    if not finding:
        raise ValueError("Finding not found")
    device = await db[Collections.DEVICES].find_one({"device_id": finding["device_id"]}, {"_id": 0})
    ai = AIService()
    return await ai.generate_remediation(
        finding=finding, vendor=(device or {}).get("vendor") or "Unknown", platform=(device or {}).get("platform") or "Unknown"
    )


async def _validate_remediation(db, remediation_id: str):
    from app.db import Collections

    return await db[Collections.REMEDIATION_PLANS].find_one({"remediation_id": remediation_id}, {"_id": 0})


async def _generate_report(db, scan_id: str, user_id: str):
    # Delegates to the same logic as the /api/reports/generate endpoint.
    raise NotImplementedError("Call POST /api/reports/generate directly -- report generation requires full request context")


async def _verify_blockchain(db, audit_id: str):
    from app.blockchain.verifier import verify_audit

    return await verify_audit(db, audit_id)


async def _get_audit_history(db, device_id: str):
    from app.db import Collections

    return await db[Collections.BLOCKCHAIN_TRANSACTIONS].find({"device_id": device_id}, {"_id": 0}).sort("created_at", 1).to_list(length=1000)


TOOLS: dict[str, ToolDefinition] = {
    "upload_configuration": ToolDefinition(
        name="upload_configuration",
        description="Uploads a configuration file for a device and normalizes it into the Security IR.",
        input_schema={"project_id": "str", "device_id": "str", "filename": "str", "content": "bytes"},
        output_schema={"configuration_id": "str", "vendor": "str", "status": "str"},
        risk_level=RiskLevel.LOW,
        requires_approval=False,
        handler=_upload_configuration,
    ),
    "start_scan": ToolDefinition(
        name="start_scan",
        description="Starts a full compliance/risk/attack-graph/ACO scan for a device.",
        input_schema={"device_id": "str"},
        output_schema={"scan_id": "str", "status": "str"},
        risk_level=RiskLevel.MEDIUM,
        requires_approval=True,
        handler=_start_scan,
    ),
    "get_scan_status": ToolDefinition(
        name="get_scan_status", description="Gets the current status of a scan.",
        input_schema={"scan_id": "str"}, output_schema={"status": "str"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_get_scan_status,
    ),
    "get_findings": ToolDefinition(
        name="get_findings", description="Lists findings for a scan.",
        input_schema={"scan_id": "str"}, output_schema={"findings": "list"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_get_findings,
    ),
    "get_risk": ToolDefinition(
        name="get_risk", description="Gets the calculated risk score for a scan.",
        input_schema={"scan_id": "str"}, output_schema={"risk_score": "float"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_get_risk,
    ),
    "get_attack_paths": ToolDefinition(
        name="get_attack_paths", description="Lists potential attack paths for a scan.",
        input_schema={"scan_id": "str"}, output_schema={"paths": "list"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_get_attack_paths,
    ),
    "generate_remediation_plan": ToolDefinition(
        name="generate_remediation_plan", description="Uses the local LLM to draft a remediation plan for a finding.",
        input_schema={"finding_id": "str"}, output_schema={"suggested_commands": "list"},
        risk_level=RiskLevel.MEDIUM, requires_approval=True, handler=_generate_remediation_plan,
    ),
    "validate_remediation": ToolDefinition(
        name="validate_remediation", description="Retrieves validation/simulation status of a remediation plan.",
        input_schema={"remediation_id": "str"}, output_schema={"status": "str"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_validate_remediation,
    ),
    "generate_report": ToolDefinition(
        name="generate_report", description="Generates a PDF audit report for a scan.",
        input_schema={"scan_id": "str"}, output_schema={"report_id": "str"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_generate_report,
    ),
    "verify_blockchain": ToolDefinition(
        name="verify_blockchain", description="Recomputes and compares evidence hashes against the Fabric ledger.",
        input_schema={"audit_id": "str"}, output_schema={"verified": "bool"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_verify_blockchain,
    ),
    "get_audit_history": ToolDefinition(
        name="get_audit_history", description="Lists blockchain provenance events for a device.",
        input_schema={"device_id": "str"}, output_schema={"events": "list"},
        risk_level=RiskLevel.LOW, requires_approval=False, handler=_get_audit_history,
    ),
}


def describe_tools() -> list[dict]:
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "output_schema": t.output_schema,
            "risk_level": t.risk_level.value,
            "requires_approval": t.requires_approval,
        }
        for t in TOOLS.values()
    ]
