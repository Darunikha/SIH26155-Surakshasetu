"""RBAC roles (spec section 50)."""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"


# Which roles may perform the "important actions" spec section 37 requires
# human approval for (starting an audit, approving remediation, confirming
# adaptive-learning mappings, blockchain-sensitive provenance actions).
APPROVAL_ROLES: frozenset[Role] = frozenset({Role.ADMIN, Role.SECURITY_ANALYST, Role.AUDITOR})

ALL_ROLES: tuple[Role, ...] = tuple(Role)
