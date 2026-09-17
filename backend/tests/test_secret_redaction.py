from app.security.secret_redaction import detect_secrets, redact_secrets


def test_redacts_cisco_password():
    result = redact_secrets("enable password cisco123")
    assert "cisco123" not in result.redacted_text
    assert "[REDACTED]" in result.redacted_text


def test_redacts_snmp_community():
    result = redact_secrets("snmp-server community public RO")
    assert "public" not in result.redacted_text


def test_redacts_fortinet_password():
    result = redact_secrets('set password "SuperSecret!"')
    assert "SuperSecret" not in result.redacted_text


def test_redacts_private_key_block():
    text = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG\n-----END PRIVATE KEY-----"
    result = redact_secrets(text)
    assert "MIIBVQIBADANBgkqhkiG" not in result.redacted_text
    assert "-----BEGIN PRIVATE KEY-----" in result.redacted_text


def test_does_not_flag_ordinary_config_lines():
    findings = detect_secrets("interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0")
    assert findings == []


def test_detect_secrets_returns_categories_not_values():
    findings = detect_secrets("enable password topsecret")
    assert "cisco_password" in findings
    assert "topsecret" not in str(findings)
