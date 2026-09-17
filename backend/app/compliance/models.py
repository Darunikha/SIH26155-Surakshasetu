from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from app.normalization.ir_schema import SecurityIR


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class FrameworkMapping:
    framework: str  # "CIS" | "NIST_800_53" | "DISA_STIG" | "ISO_27001"
    control_id: str


@dataclass(frozen=True)
class ControlDefinition:
    control_id: str
    title: str
    description: str
    category: str
    severity: Severity
    framework_mappings: tuple[FrameworkMapping, ...]
    # Pure function: IR -> (status, evidence dict). Never mutates the IR.
    evaluate: Callable[[SecurityIR], "ControlEvaluation"]


@dataclass
class ControlEvaluation:
    status: ComplianceStatus
    evidence: dict = field(default_factory=dict)
    notes: str = ""
