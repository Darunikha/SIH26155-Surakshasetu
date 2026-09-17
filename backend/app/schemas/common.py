"""Shared API response envelope (spec section 55) and error codes."""
from __future__ import annotations

from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ErrorCode(str, Enum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    ENCODING_FAILURE = "ENCODING_FAILURE"
    DUPLICATE_UPLOAD = "DUPLICATE_UPLOAD"
    VENDOR_DETECTION_FAILED = "VENDOR_DETECTION_FAILED"
    PARSER_FAILURE = "PARSER_FAILURE"
    NORMALIZATION_FAILURE = "NORMALIZATION_FAILURE"
    COMPLIANCE_FAILURE = "COMPLIANCE_FAILURE"
    AI_UNAVAILABLE = "AI_UNAVAILABLE"
    RAG_UNAVAILABLE = "RAG_UNAVAILABLE"
    OPTIMIZER_FAILURE = "OPTIMIZER_FAILURE"
    REPORT_FAILURE = "REPORT_FAILURE"
    DATABASE_FAILURE = "DATABASE_FAILURE"
    BLOCKCHAIN_UNAVAILABLE = "BLOCKCHAIN_UNAVAILABLE"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    NOT_FOUND = "NOT_FOUND"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    CONFLICT = "CONFLICT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ApiError(BaseModel):
    code: ErrorCode
    message: str


class ApiResponse(BaseModel, Generic[T]):
    success: bool
    data: T | None = None
    error: ApiError | None = None
    request_id: str


def ok(data: Any, request_id: str) -> dict:
    return {"success": True, "data": data, "error": None, "request_id": request_id}


def fail(code: ErrorCode, message: str, request_id: str) -> dict:
    return {
        "success": False,
        "data": None,
        "error": {"code": code.value, "message": message},
        "request_id": request_id,
    }


class AppError(Exception):
    """Raised by services; translated to the ApiResponse envelope by the
    global exception handler in main.py. Carries an HTTP status so callers
    don't need to know transport details."""

    def __init__(self, code: ErrorCode, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
