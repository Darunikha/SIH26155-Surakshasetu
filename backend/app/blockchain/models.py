from __future__ import annotations

from pydantic import BaseModel


class BlockchainTransactionDocument(BaseModel):
    event_id: str
    audit_id: str
    device_id: str
    actor_id: str
    event_type: str
    status: str  # CONFIRMED | PENDING | FAILED
    transaction_id: str | None
    block_number: int | None
    configuration_hash: str | None
    compliance_hash: str | None
    risk_hash: str | None
    attack_graph_hash: str | None
    remediation_hash: str | None
    report_hash: str | None
    reason: str | None
    created_at: str
    updated_at: str
    retry_count: int = 0
