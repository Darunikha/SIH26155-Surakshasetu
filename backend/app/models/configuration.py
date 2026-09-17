from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class ProcessingStatus(str, Enum):
    """Async processing state machine surfaced to the frontend (spec
    section 53)."""

    UPLOADING = "UPLOADING"
    VALIDATING = "VALIDATING"
    HASHING = "HASHING"
    DETECTING_VENDOR = "DETECTING_VENDOR"
    PARSING = "PARSING"
    NORMALIZING = "NORMALIZING"
    NEEDS_VENDOR_CONFIRMATION = "NEEDS_VENDOR_CONFIRMATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ConfigurationDocument(BaseModel):
    configuration_id: str
    device_id: str
    project_id: str
    latest_version: int
    created_at: str


class ConfigurationVersionDocument(BaseModel):
    configuration_id: str
    device_id: str
    project_id: str
    version: int
    original_filename: str
    storage_id: str
    vendor: str | None
    platform: str | None
    vendor_confidence: float | None
    vendor_detection_method: str | None
    software_version: str | None
    file_size: int
    encoding: str
    uploaded_by: str
    uploaded_at: str
    configuration_hash: str
    ir_hash: str | None = None
    secret_findings: list[str] = []
    status: ProcessingStatus
    error_message: str | None = None
    security_ir: dict[str, Any] | None = None
