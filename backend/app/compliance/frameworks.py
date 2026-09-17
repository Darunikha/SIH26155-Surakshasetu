"""Framework registry: publicly documented catalog sizes, used ONLY to
compute an honest "implemented / total" coverage percentage (spec section
19: "Never falsely claim complete framework coverage").

These totals are widely-cited approximations of each framework's published
catalog size, not a certification claim -- see docs/compliance.md for
sourcing notes and caveats. DISA STIG has no single universal control count
(it is published per platform/product), so it is intentionally left as
"not enumerated" rather than inventing a number.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkInfo:
    key: str
    display_name: str
    total_controls: int | None  # None = not enumerable at a single-number level
    note: str


FRAMEWORKS: dict[str, FrameworkInfo] = {
    "CIS": FrameworkInfo(
        key="CIS",
        display_name="CIS Controls v8",
        total_controls=153,
        note="153 Safeguards across 18 CIS Controls v8 (IG1+IG2+IG3).",
    ),
    "NIST_800_53": FrameworkInfo(
        key="NIST_800_53",
        display_name="NIST SP 800-53 Rev. 5",
        total_controls=322,
        note="Approximate count of base controls (excluding control enhancements) across 20 control families.",
    ),
    "DISA_STIG": FrameworkInfo(
        key="DISA_STIG",
        display_name="DISA STIG",
        total_controls=None,
        note="STIG requirement counts are published per platform/product (e.g. Cisco IOS Router STIG), "
        "not as one universal number. Architecture is present; a platform-specific checklist is not yet implemented.",
    ),
    "ISO_27001": FrameworkInfo(
        key="ISO_27001",
        display_name="ISO/IEC 27001:2022 Annex A",
        total_controls=93,
        note="93 Annex A controls (ISO/IEC 27001:2022). Architecture is present; control checks are not yet implemented.",
    ),
}

# Frameworks with zero implemented controls today -- kept explicit so the
# engine never silently claims otherwise.
ARCHITECTURE_ONLY_FRAMEWORKS: frozenset[str] = frozenset({"DISA_STIG", "ISO_27001"})
