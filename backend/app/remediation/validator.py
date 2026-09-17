"""Lightweight syntax validation for AI-suggested remediation commands
(spec section 25). This checks that a suggested line is plausibly a real
configuration command for the stated vendor -- not a full grammar-level
parse -- and rejects anything that looks like injection or is empty.
"""
from __future__ import annotations

import re

_DANGEROUS_PATTERNS = (
    re.compile(r"[;&|`$]"),  # shell metacharacters -- never expected in a config line
    re.compile(r"\brm\s+-rf\b", re.I),
    re.compile(r"\bformat\b", re.I),
    re.compile(r"\bshutdown\b\s*$", re.I),  # bare device shutdown is never an auto-suggested fix
)

_VENDOR_COMMAND_PREFIXES = {
    "Cisco": ("no ", "ip ", "line ", "interface ", "username ", "enable ", "security ", "logging ", "ntp ", "snmp-server ", "access-list ", "aaa "),
    "Fortinet": ("set ", "config ", "edit ", "unset ", "next", "end"),
    "PaloAlto": ("set ", "delete "),
}


def validate_commands(vendor: str, commands: list[str]) -> list[dict]:
    prefixes = _VENDOR_COMMAND_PREFIXES.get(vendor, ())
    results = []
    for cmd in commands:
        stripped = cmd.strip()
        if not stripped:
            results.append({"command": cmd, "valid": False, "reason": "Empty command"})
            continue

        if any(p.search(stripped) for p in _DANGEROUS_PATTERNS):
            results.append({"command": cmd, "valid": False, "reason": "Contains disallowed pattern"})
            continue

        if prefixes and not stripped.lower().startswith(prefixes):
            results.append(
                {
                    "command": cmd,
                    "valid": False,
                    "reason": f"Does not match a known {vendor} command prefix -- review manually before applying",
                }
            )
            continue

        results.append({"command": cmd, "valid": True, "reason": None})
    return results
