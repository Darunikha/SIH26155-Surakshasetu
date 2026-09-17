from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    LAB = "lab"


class AssetContext(BaseModel):
    """User-supplied business context that feeds the risk engine (spec
    section 21). Risk recalculates whenever this changes."""

    criticality: Criticality = Criticality.MEDIUM
    business_role: str = ""
    data_sensitivity: str = "internal"  # public | internal | confidential | restricted
    internet_exposure: bool = False
    environment: Environment = Environment.PRODUCTION
    owner: str = ""
    department: str = ""


class DeviceDocument(BaseModel):
    device_id: str
    project_id: str
    name: str
    vendor: str | None = None
    platform: str | None = None
    asset_context: AssetContext = AssetContext()
    created_at: str
    updated_at: str
