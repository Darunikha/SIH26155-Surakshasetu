"""SHA-256 hashing service.

Every hash committed to MongoDB or Hyperledger Fabric passes through this
module so hashing is deterministic and reproducible: the same logical
evidence always produces the same digest, and volatile bookkeeping fields
(timestamps, database ids, request ids) never leak into the hash.

Pipeline (spec section 8):
    Evidence -> canonicalize -> UTF-8 bytes -> SHA-256 -> hex digest
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

# Fields that are bookkeeping/nondeterministic and must never affect a hash.
# Individual callers may extend this set for entity-specific volatile fields.
DEFAULT_VOLATILE_FIELDS: frozenset[str] = frozenset(
    {
        "_id",
        "id",
        "created_at",
        "updated_at",
        "uploaded_at",
        "timestamp",
        "generated_at",
        "recorded_at",
        "request_id",
        "transaction_id",
        "block_number",
    }
)


def _strip_volatile(value: Any, volatile_fields: frozenset[str]) -> Any:
    """Recursively remove volatile keys from dicts/lists so hashing is stable."""
    if isinstance(value, dict):
        return {
            k: _strip_volatile(v, volatile_fields)
            for k, v in value.items()
            if k not in volatile_fields
        }
    if isinstance(value, list):
        return [_strip_volatile(v, volatile_fields) for v in value]
    return value


def canonicalize_json(
    data: dict | list,
    extra_volatile_fields: frozenset[str] | set[str] | None = None,
) -> bytes:
    """Produce a deterministic canonical byte-serialization of structured data.

    Steps: strip volatile fields -> sort keys recursively -> compact,
    separator-stable JSON encoding -> UTF-8 bytes with NFC normalization
    applied to strings so equivalent unicode representations hash the same.
    """
    volatile = DEFAULT_VOLATILE_FIELDS | frozenset(extra_volatile_fields or ())
    cleaned = _strip_volatile(data, volatile)

    def _default(o: Any) -> Any:
        # Deterministic fallback for non-JSON-native types (e.g. datetime).
        return unicodedata.normalize("NFC", str(o))

    canonical_str = json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_default,
    )
    return unicodedata.normalize("NFC", canonical_str).encode("utf-8")


def canonicalize_configuration(raw: bytes | str) -> bytes:
    """Canonicalize raw uploaded configuration text before hashing.

    Steps: decode to text (best-effort UTF-8, falling back to latin-1 so no
    byte sequence can crash hashing) -> normalize line endings -> strip
    trailing whitespace per line -> strip trailing blank lines -> NFC
    normalize -> UTF-8 encode. This makes the hash independent of the
    uploading OS's line-ending convention or trailing-whitespace noise while
    leaving all meaningful configuration content untouched.
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
    else:
        text = raw

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    normalized = "\n".join(lines)
    return unicodedata.normalize("NFC", normalized).encode("utf-8")


def calculate_sha256(data: bytes) -> str:
    """Calculate the SHA-256 hex digest of already-canonicalized bytes."""
    return hashlib.sha256(data).hexdigest()


# --- Entity-specific wrappers -------------------------------------------------


def calculate_configuration_hash(raw_config: bytes | str) -> str:
    return calculate_sha256(canonicalize_configuration(raw_config))


def calculate_ir_hash(ir: dict) -> str:
    return calculate_sha256(canonicalize_json(ir))


def calculate_compliance_hash(compliance_results: dict | list) -> str:
    return calculate_sha256(canonicalize_json(compliance_results))


def calculate_risk_hash(risk: dict) -> str:
    return calculate_sha256(canonicalize_json(risk))


def calculate_attack_graph_hash(graph_data: dict) -> str:
    return calculate_sha256(canonicalize_json(graph_data))


def calculate_remediation_hash(remediation_plan: dict) -> str:
    return calculate_sha256(canonicalize_json(remediation_plan))


def calculate_report_hash(report_bytes: bytes) -> str:
    """PDF reports are hashed directly as binary -- no JSON canonicalization
    applies to a rendered document."""
    return calculate_sha256(report_bytes)


def calculate_audit_hash(audit_summary: dict) -> str:
    return calculate_sha256(canonicalize_json(audit_summary))
