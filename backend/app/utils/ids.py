"""Human-readable, collision-resistant id generation for domain entities.

Uses a short random suffix (not a raw incrementing counter, to avoid
leaking record volume) combined with a readable prefix so ids are easy to
spot in logs/UI (e.g. AUD-7F3A2C9B1D).
"""
from __future__ import annotations

import secrets
import time


def _suffix(n_bytes: int = 5) -> str:
    return secrets.token_hex(n_bytes).upper()


def new_id(prefix: str) -> str:
    return f"{prefix}-{_suffix()}"


def new_audit_id() -> str:
    return new_id("AUD")


def new_device_id() -> str:
    return new_id("DEVICE")


def new_configuration_id() -> str:
    return new_id("CFG")


def new_scan_id() -> str:
    return new_id("SCAN")


def new_finding_id() -> str:
    return new_id("FIND")


def new_project_id() -> str:
    return new_id("PROJ")


def new_user_id() -> str:
    return new_id("USER")


def new_event_id() -> str:
    return new_id("EVT")


def new_request_id() -> str:
    return new_id("REQ")


def new_report_id() -> str:
    return new_id("RPT")


def new_remediation_id() -> str:
    return new_id("REM")


def new_training_mapping_id() -> str:
    return new_id("MAP")


def new_optimizer_run_id() -> str:
    return new_id("OPT")


def utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
