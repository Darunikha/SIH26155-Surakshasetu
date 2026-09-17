from __future__ import annotations

from enum import Enum


class ScanStatus(str, Enum):
    """Async scan pipeline status (spec section 53)."""

    PENDING = "PENDING"
    COMPLIANCE_ANALYSIS = "COMPLIANCE_ANALYSIS"
    RISK_ANALYSIS = "RISK_ANALYSIS"
    BUILDING_ATTACK_GRAPH = "BUILDING_ATTACK_GRAPH"
    OPTIMIZING = "OPTIMIZING"
    RECORDING_BLOCKCHAIN = "RECORDING_BLOCKCHAIN"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
