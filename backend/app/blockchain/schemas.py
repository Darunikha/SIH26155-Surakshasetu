"""Data shapes exchanged with the chaincode (spec section 29-30).

Kept intentionally minimal: only hashes and provenance metadata ever cross
this boundary -- never raw configurations, secrets, or full documents
(spec section 7).
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

EventType = Literal[
    "CONFIGURATION_RECEIVED",
    "CONFIGURATION_VERSION_CREATED",
    "COMPLIANCE_COMPLETED",
    "RISK_CALCULATED",
    "REMEDIATION_APPROVED",
    "TRAINING_MAPPING_APPROVED",
    "REPORT_GENERATED",
    "AUDIT_COMPLETED",
]


class AuditRecord(BaseModel):
    event_id: str
    audit_id: str
    device_id: str
    actor_id: str
    event_type: EventType
    configuration_hash: str | None = None
    compliance_hash: str | None = None
    risk_hash: str | None = None
    attack_graph_hash: str | None = None
    remediation_hash: str | None = None
    report_hash: str | None = None
    version: int = 1
    schema_version: str = "1.0"
    timestamp: str


class BlockchainTransactionResult(BaseModel):
    status: Literal["CONFIRMED", "PENDING", "FAILED"]
    transaction_id: str | None = None
    block_number: int | None = None
    reason: str | None = None
