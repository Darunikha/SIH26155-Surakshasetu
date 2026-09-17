"""Vendor-neutral Security Intermediate Representation (spec section 14).

Every vendor parser produces exactly this shape. The compliance engine, risk
engine, and attack-graph builder read only this IR -- never vendor syntax
directly (spec section 15: semantic normalization). The schema is
deliberately extensible: `interfaces`/`zones`/`services` feed the attack
graph, and `unmapped_commands` feeds adaptive learning (spec section 16).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DeviceInfo(BaseModel):
    vendor: str = "Unknown"
    model: str = "Unknown"
    os: str = "Unknown"
    version: str = "Unknown"
    hostname: str | None = None
    serial_number: str | None = None


class PasswordPolicy(BaseModel):
    minimum_length: int | None = None
    complexity_required: bool | None = None
    max_age_days: int | None = None


class ManagementPlane(BaseModel):
    ssh_enabled: bool | None = None
    ssh_version: int | None = None
    telnet_enabled: bool | None = None
    http_management: bool | None = None
    https_management: bool | None = None
    session_timeout_seconds: int | None = None


class Authentication(BaseModel):
    mfa: bool | None = None
    aaa_enabled: bool | None = None
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    default_credentials_detected: bool | None = None
    privileged_access_restricted: bool | None = None


class Logging(BaseModel):
    enabled: bool | None = None
    remote_syslog: bool | None = None
    syslog_servers: list[str] = Field(default_factory=list)
    audit_logging: bool | None = None


class NtpConfig(BaseModel):
    enabled: bool | None = None
    servers: list[str] = Field(default_factory=list)


class SnmpConfig(BaseModel):
    enabled: bool | None = None
    version: str | None = None  # "1", "2c", "3"
    community_strings_present: bool | None = None


class Interface(BaseModel):
    name: str
    zone: str | None = None
    ip_address: str | None = None
    internet_facing: bool = False
    enabled: bool = True


class Zone(BaseModel):
    name: str
    trust_level: str = "unknown"  # "trusted" | "untrusted" | "dmz" | "unknown"


class Service(BaseModel):
    name: str
    port: int | None = None
    protocol: str | None = None
    exposed_zone: str | None = None


class AclRule(BaseModel):
    name: str | None = None
    action: str  # "permit" | "deny"
    source: str = "any"
    destination: str = "any"
    service: str = "any"
    is_unrestricted: bool = False  # any/any/permit pattern


class AccessControl(BaseModel):
    rules: list[AclRule] = Field(default_factory=list)


class Network(BaseModel):
    interfaces: list[Interface] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    routes: list[dict[str, Any]] = Field(default_factory=list)


class UnmappedCommand(BaseModel):
    raw_line: str
    line_number: int | None = None
    context: str | None = None


class SecurityIR(BaseModel):
    """The vendor-neutral Security Intermediate Representation."""

    device: DeviceInfo = Field(default_factory=DeviceInfo)
    management: ManagementPlane = Field(default_factory=ManagementPlane)
    authentication: Authentication = Field(default_factory=Authentication)
    logging: Logging = Field(default_factory=Logging)
    ntp: NtpConfig = Field(default_factory=NtpConfig)
    snmp: SnmpConfig = Field(default_factory=SnmpConfig)
    network: Network = Field(default_factory=Network)
    access_control: AccessControl = Field(default_factory=AccessControl)
    insecure_services: list[str] = Field(default_factory=list)
    unused_services: list[str] = Field(default_factory=list)
    internet_exposed: bool = False
    unmapped_commands: list[UnmappedCommand] = Field(default_factory=list)
