from app.security.hashing import (
    calculate_compliance_hash,
    calculate_configuration_hash,
    calculate_sha256,
    canonicalize_configuration,
    canonicalize_json,
)


def test_sha256_is_deterministic():
    assert calculate_sha256(b"hello") == calculate_sha256(b"hello")
    assert calculate_sha256(b"hello") != calculate_sha256(b"world")


def test_canonicalize_json_ignores_key_order():
    a = canonicalize_json({"b": 1, "a": 2})
    b = canonicalize_json({"a": 2, "b": 1})
    assert a == b


def test_canonicalize_json_strips_volatile_fields():
    a = canonicalize_json({"value": 1, "timestamp": "2026-01-01T00:00:00Z", "_id": "abc"})
    b = canonicalize_json({"value": 1, "timestamp": "2099-12-31T00:00:00Z", "_id": "xyz"})
    assert a == b


def test_canonicalize_json_detects_real_changes():
    a = canonicalize_json({"value": 1})
    b = canonicalize_json({"value": 2})
    assert a != b


def test_canonicalize_configuration_normalizes_line_endings_and_trailing_whitespace():
    text_crlf = "hostname foo\r\ninterface Gi0/0  \r\n ip address 1.2.3.4\r\n\r\n"
    text_lf = "hostname foo\ninterface Gi0/0\n ip address 1.2.3.4"
    assert canonicalize_configuration(text_crlf) == canonicalize_configuration(text_lf)


def test_calculate_configuration_hash_is_stable_across_whitespace_noise():
    h1 = calculate_configuration_hash("line one\nline two\n")
    h2 = calculate_configuration_hash("line one\r\nline two\r\n\r\n")
    assert h1 == h2


def test_calculate_configuration_hash_detects_content_change():
    h1 = calculate_configuration_hash("telnet enabled")
    h2 = calculate_configuration_hash("telnet disabled")
    assert h1 != h2


def test_calculate_compliance_hash_ignores_default_volatile_fields():
    # Only the DEFAULT_VOLATILE_FIELDS set (created_at, timestamp, _id, ...) is
    # stripped automatically; caller-specific identifying fields like scan_id
    # are NOT stripped by default -- callers filter those out themselves
    # (see app/blockchain/verifier.py) before hashing, so two different
    # scan_ids intentionally produce different hashes here.
    a = calculate_compliance_hash({"compliance_score": 50, "created_at": "t1"})
    b = calculate_compliance_hash({"compliance_score": 50, "created_at": "t2"})
    assert a == b


def test_calculate_compliance_hash_detects_tampering():
    a = calculate_compliance_hash({"compliance_score": 50})
    b = calculate_compliance_hash({"compliance_score": 99.99})
    assert a != b
