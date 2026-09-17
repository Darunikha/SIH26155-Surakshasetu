"""Detects and redacts secrets in uploaded network configurations.

Applied before ANY configuration text reaches the AI service, RAG context,
logs, or the adaptive-learning "unknown pattern" pipeline. Raw secret values
never leave this module -- only the redacted text and (for audit purposes) a
count/category of what was found.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretPattern:
    name: str
    # Regex with a single capturing group around the secret value to redact.
    pattern: re.Pattern[str]


def _p(name: str, regex: str) -> SecretPattern:
    return SecretPattern(name, re.compile(regex, re.IGNORECASE | re.MULTILINE))


# Patterns cover the vendor syntaxes most likely to appear in the initial
# vendor set (Cisco/Fortinet/PaloAlto) plus generic secret-shaped tokens.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    _p("cisco_password", r"^(\s*(?:enable\s+)?(?:secret|password)\s+(?:\d\s+)?)(\S+)"),
    _p("cisco_username_password", r"^(\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+(?:\d\s+)?)(\S+)"),
    _p("fortinet_password", r"^(\s*set\s+password\s+)(\S+)"),
    _p("fortinet_psksecret", r"^(\s*set\s+psksecret\s+)(\S+)"),
    _p("paloalto_phash", r"^(\s*phash\s+)(\S+)"),
    _p("generic_password_kv", r"(?i)\b(password\s*[:=]\s*)([^\s,;]+)"),
    _p("generic_secret_kv", r"(?i)\b(secret\s*[:=]\s*)([^\s,;]+)"),
    _p("api_key", r"(?i)\b((?:api[_-]?key|apikey)\s*[:=]\s*)([^\s,;]+)"),
    _p("bearer_token", r"(?i)\b(bearer\s+)([A-Za-z0-9\-._~+/]+=*)"),
    _p("generic_token_kv", r"(?i)\b(token\s*[:=]\s*)([^\s,;]+)"),
    _p("private_key_block", r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)([\s\S]+?)(-----END [A-Z ]*PRIVATE KEY-----)"),
    _p("snmp_community", r"^(\s*snmp-server\s+community\s+)(\S+)"),
    _p("snmp_community_set", r"^(\s*set\s+(?:snmp-)?community\s+)(\S+)"),
    _p("aws_access_key", r"\b(AKIA)([0-9A-Z]{16})\b"),
)


@dataclass
class RedactionResult:
    redacted_text: str
    findings: list[str] = field(default_factory=list)  # category names, not values
    total_redactions: int = 0


def redact_secrets(text: str) -> RedactionResult:
    """Return a copy of `text` with all detected secret values replaced by
    REDACTED. Never returns or logs the original secret value."""
    redacted = text
    findings: list[str] = []
    total = 0

    for spec in SECRET_PATTERNS:
        if spec.name == "private_key_block":
            def _sub_pk(m: re.Match[str]) -> str:
                nonlocal total
                total += 1
                findings.append(spec.name)
                return f"{m.group(1)}\n{REDACTED}\n{m.group(3)}"

            redacted, n = spec.pattern.subn(_sub_pk, redacted)
            continue

        def _sub(m: re.Match[str], _spec: SecretPattern = spec) -> str:
            nonlocal total
            total += 1
            findings.append(_spec.name)
            groups = m.groups()
            # Replace only the last captured group (the secret value itself).
            prefix = "".join(groups[:-1])
            return f"{prefix}{REDACTED}"

        redacted = spec.pattern.sub(_sub, redacted)

    return RedactionResult(redacted_text=redacted, findings=findings, total_redactions=total)


def detect_secrets(text: str) -> list[str]:
    """Return the list of secret categories detected, without redacting."""
    return redact_secrets(text).findings
