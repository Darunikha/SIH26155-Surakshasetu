"""Builds per-finding remediation profiles consumed by the optimizer.

Cost and disruption are estimated, deterministic "operational units" (1-10
scale) keyed by control category -- documented approximations, not measured
real-world engineering time. Risk reduction reuses the same severity
weighting the risk engine uses for vulnerability scoring, so "remediating
this finding" and "this finding's contribution to risk" stay consistent.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Estimated operational cost (engineering effort) per control category, 1-10.
COST_BY_CATEGORY = {
    "authentication": 5,
    "access_control": 6,
    "management_plane": 3,
    "logging": 2,
    "hardening": 2,
}

# Estimated disruption risk (likelihood/impact of a service interruption
# while remediating) per control category, 1-10.
DISRUPTION_BY_CATEGORY = {
    "authentication": 4,
    "access_control": 7,
    "management_plane": 5,
    "logging": 1,
    "hardening": 2,
}

# Which control's remediation removes which attack-graph "service" exposure.
CONTROL_TO_SERVICE = {
    "telnet_disabled": "telnet",
    "http_management_disabled": "http",
    "ssh_version_2": "ssh-v1",
    "snmp_secure": "snmp",
}

# Concrete, documented remediation-ordering dependency: the aggregate
# "management plane exposed to the internet" finding is rooted in telnet/http
# being enabled, so those should be addressed at the same time or first.
DEPENDENCIES = {
    "management_plane_not_internet_exposed": ("telnet_disabled", "http_management_disabled"),
}


@dataclass
class FindingProfile:
    finding_id: str
    control_id: str
    severity: str
    category: str
    risk_reduction: float
    cost: float
    disruption: float
    depends_on: tuple[str, ...] = field(default_factory=tuple)


def build_profiles(findings: list[dict]) -> list[FindingProfile]:
    control_to_finding_id = {f["control_id"]: f["finding_id"] for f in findings}
    profiles = []
    for f in findings:
        depends_on = tuple(
            control_to_finding_id[dep]
            for dep in DEPENDENCIES.get(f["control_id"], ())
            if dep in control_to_finding_id
        )
        profiles.append(
            FindingProfile(
                finding_id=f["finding_id"],
                control_id=f["control_id"],
                severity=f["severity"],
                category=f["category"],
                risk_reduction=float(SEVERITY_WEIGHT.get(f["severity"], 1)),
                cost=float(COST_BY_CATEGORY.get(f["category"], 3)),
                disruption=float(DISRUPTION_BY_CATEGORY.get(f["category"], 3)),
                depends_on=depends_on,
            )
        )
    return profiles
