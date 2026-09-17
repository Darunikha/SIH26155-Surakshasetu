"""Secure file validation for uploaded configurations (spec sections 9-10).

Uploaded files are never executed and never trusted by original filename.
Validation covers: extension allow-list, size cap, encoding detection,
path-traversal in the supplied filename, and a content-signature check that
rejects binaries/executables masquerading as text configs.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

import chardet

from app.config import get_settings
from app.schemas.common import AppError, ErrorCode

ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".cfg", ".conf", ".txt", ".xml", ".json", ".yaml", ".yml"})

# Byte signatures of executable/binary formats that must never be accepted
# as a "text" configuration upload, even if the extension was spoofed.
_DISALLOWED_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"MZ",  # Windows PE executable
    b"\x7fELF",  # Linux ELF executable
    b"\xca\xfe\xba\xbe",  # Mach-O / Java class (fat binary)
    b"PK\x03\x04",  # zip/office/jar container
    b"%PDF-",  # PDF
    b"\x89PNG",  # PNG
    b"\xff\xd8\xff",  # JPEG
    b"GIF8",  # GIF
)

_PATH_TRAVERSAL_RE = re.compile(r"\.\.[\\/]|^[\\/]|^[A-Za-z]:")


@dataclass
class ValidatedUpload:
    original_filename: str
    extension: str
    size_bytes: int
    encoding: str
    text: str


def _check_extension(filename: str) -> str:
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise AppError(
            ErrorCode.UNSUPPORTED_FILE_TYPE,
            f"Unsupported file extension '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )
    return ext


def _check_filename_safety(filename: str) -> None:
    if not filename or _PATH_TRAVERSAL_RE.search(filename):
        raise AppError(ErrorCode.VALIDATION_ERROR, "Filename contains unsafe path characters")


def _check_size(content: bytes) -> None:
    max_bytes = get_settings().max_upload_size_mb * 1024 * 1024
    if len(content) == 0:
        raise AppError(ErrorCode.VALIDATION_ERROR, "Uploaded file is empty")
    if len(content) > max_bytes:
        raise AppError(
            ErrorCode.FILE_TOO_LARGE,
            f"File exceeds the {get_settings().max_upload_size_mb}MB limit",
        )


def _check_not_binary(content: bytes) -> None:
    head = content[:16]
    for sig in _DISALLOWED_MAGIC_PREFIXES:
        if head.startswith(sig):
            raise AppError(
                ErrorCode.UNSUPPORTED_FILE_TYPE,
                "File content signature indicates a binary/executable format, not a text configuration",
            )
    # A text configuration should not contain NUL bytes.
    if b"\x00" in content[:4096]:
        raise AppError(ErrorCode.UNSUPPORTED_FILE_TYPE, "File appears to be binary (contains NUL bytes)")


def decode_text(content: bytes) -> tuple[str, str]:
    """Public wrapper around encoding detection, for callers that already
    have validated bytes and just need to re-decode them (e.g. re-parsing
    after a human vendor confirmation)."""
    return _detect_encoding(content)


def _detect_encoding(content: bytes) -> tuple[str, str]:
    detected = chardet.detect(content)
    encoding = (detected.get("encoding") or "utf-8").lower()
    try:
        text = content.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        try:
            text = content.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError as exc:
            raise AppError(ErrorCode.ENCODING_FAILURE, "Unable to decode file with a supported text encoding") from exc
    return encoding, text


def validate_upload(filename: str, content: bytes) -> ValidatedUpload:
    _check_filename_safety(filename)
    ext = _check_extension(filename)
    _check_size(content)
    _check_not_binary(content)
    encoding, text = _detect_encoding(content)

    return ValidatedUpload(
        original_filename=filename,
        extension=ext,
        size_bytes=len(content),
        encoding=encoding,
        text=text,
    )
