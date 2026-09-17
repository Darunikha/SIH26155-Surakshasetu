"""The implemented control set (spec section 18).

Each control is a small, self-contained `ControlDefinition` with a pure
`evaluate(ir) -> ControlEvaluation` function. Adding a new control means
adding one more entry to `CONTROLS` -- nothing else in the engine changes.

Framework mappings are illustrative/best-effort cross-references to CIS
Controls v8 and NIST SP 800-53 Rev 5, documented further in
docs/compliance.md. They are not a claim of official certification.
"""
from __future__ import annotations

from app.compliance.models import (
    ComplianceStatus,
    ControlDefinition,
    ControlEvaluation,
    FrameworkMapping,
    Severity,
)
from app.normalization.ir_schema import SecurityIR

CS = ComplianceStatus


def _cis(control_id: str) -> FrameworkMapping:
    return FrameworkMapping("CIS", control_id)


def _nist(control_id: str) -> FrameworkMapping:
    return FrameworkMapping("NIST_800_53", control_id)


# --- Individual evaluators ---------------------------------------------------


def _eval_telnet_disabled(ir: SecurityIR) -> ControlEvaluation:
    v = ir.management.telnet_enabled
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"telnet_enabled": None}, "Telnet state not determinable from configuration")
    if v:
        return ControlEvaluation(CS.FAIL, {"telnet_enabled": True}, "Telnet is enabled for administrative access")
    return ControlEvaluation(CS.PASS, {"telnet_enabled": False})


def _eval_http_management_disabled(ir: SecurityIR) -> ControlEvaluation:
    v = ir.management.http_management
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"http_management": None})
    if v:
        return ControlEvaluation(CS.FAIL, {"http_management": True}, "Unencrypted HTTP management interface is enabled")
    return ControlEvaluation(CS.PASS, {"http_management": False})


def _eval_ssh_version(ir: SecurityIR) -> ControlEvaluation:
    v = ir.management.ssh_version
    if not ir.management.ssh_enabled:
        return ControlEvaluation(CS.NOT_APPLICABLE, {"ssh_enabled": False}, "SSH is not enabled on this device")
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"ssh_version": None})
    if v < 2:
        return ControlEvaluation(CS.FAIL, {"ssh_version": v}, "SSH protocol version 1 is cryptographically weak")
    return ControlEvaluation(CS.PASS, {"ssh_version": v})


def _eval_management_encryption(ir: SecurityIR) -> ControlEvaluation:
    https = ir.management.https_management
    if https is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"https_management": None})
    if not https:
        return ControlEvaluation(CS.FAIL, {"https_management": False}, "Encrypted management (HTTPS) is not enabled")
    return ControlEvaluation(CS.PASS, {"https_management": True})


def _eval_password_policy(ir: SecurityIR) -> ControlEvaluation:
    min_len = ir.authentication.password_policy.minimum_length
    if min_len is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"minimum_length": None})
    if min_len < 8:
        return ControlEvaluation(CS.FAIL, {"minimum_length": min_len}, "Password minimum length below CIS baseline (8)")
    return ControlEvaluation(CS.PASS, {"minimum_length": min_len})


def _eval_privileged_access_restricted(ir: SecurityIR) -> ControlEvaluation:
    v = ir.authentication.privileged_access_restricted
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"privileged_access_restricted": None})
    if not v:
        return ControlEvaluation(CS.FAIL, {"privileged_access_restricted": False}, "Privileged/enable access is not adequately restricted")
    return ControlEvaluation(CS.PASS, {"privileged_access_restricted": True})


def _eval_mfa(ir: SecurityIR) -> ControlEvaluation:
    v = ir.authentication.mfa
    if v is None:
        return ControlEvaluation(CS.NOT_APPLICABLE, {"mfa": None}, "MFA is not representable from this vendor's configuration syntax")
    if not v:
        return ControlEvaluation(CS.FAIL, {"mfa": False})
    return ControlEvaluation(CS.PASS, {"mfa": True})


def _eval_default_credentials(ir: SecurityIR) -> ControlEvaluation:
    v = ir.authentication.default_credentials_detected
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if v:
        return ControlEvaluation(CS.FAIL, {"default_credentials_detected": True}, "Default or well-known credential pattern detected")
    return ControlEvaluation(CS.PASS, {"default_credentials_detected": False})


def _eval_logging_enabled(ir: SecurityIR) -> ControlEvaluation:
    v = ir.logging.enabled
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if not v:
        return ControlEvaluation(CS.FAIL, {"logging_enabled": False})
    return ControlEvaluation(CS.PASS, {"logging_enabled": True})


def _eval_remote_syslog(ir: SecurityIR) -> ControlEvaluation:
    v = ir.logging.remote_syslog
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if not v:
        return ControlEvaluation(CS.FAIL, {"remote_syslog": False, "syslog_servers": ir.logging.syslog_servers})
    return ControlEvaluation(CS.PASS, {"remote_syslog": True, "syslog_servers": ir.logging.syslog_servers})


def _eval_audit_logging(ir: SecurityIR) -> ControlEvaluation:
    v = ir.logging.audit_logging
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if not v:
        return ControlEvaluation(CS.FAIL, {"audit_logging": False})
    return ControlEvaluation(CS.PASS, {"audit_logging": True})


def _eval_ntp_configured(ir: SecurityIR) -> ControlEvaluation:
    v = ir.ntp.enabled
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if not v:
        return ControlEvaluation(CS.FAIL, {"ntp_enabled": False}, "No NTP server configured; log timestamps are not reliably synchronized")
    return ControlEvaluation(CS.PASS, {"ntp_enabled": True, "servers": ir.ntp.servers})


def _eval_snmp_secure(ir: SecurityIR) -> ControlEvaluation:
    if not ir.snmp.enabled:
        return ControlEvaluation(CS.NOT_APPLICABLE, {"snmp_enabled": False})
    if ir.snmp.version in ("1", "2c") and ir.snmp.community_strings_present:
        return ControlEvaluation(
            CS.FAIL,
            {"snmp_version": ir.snmp.version, "community_strings_present": True},
            "SNMP v1/v2c with community strings is unauthenticated and unencrypted",
        )
    if ir.snmp.version == "3":
        return ControlEvaluation(CS.PASS, {"snmp_version": "3"})
    return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {"snmp_version": ir.snmp.version})


def _eval_unrestricted_acl(ir: SecurityIR) -> ControlEvaluation:
    unrestricted = [r.model_dump() for r in ir.access_control.rules if r.is_unrestricted]
    if not ir.access_control.rules:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if unrestricted:
        return ControlEvaluation(CS.FAIL, {"unrestricted_rules": unrestricted}, "One or more access-control rules permit any-source/any-destination traffic")
    return ControlEvaluation(CS.PASS, {"unrestricted_rules": []})


def _eval_management_plane_exposure(ir: SecurityIR) -> ControlEvaluation:
    if not ir.internet_exposed:
        return ControlEvaluation(CS.PASS, {"internet_exposed": False})
    risky = ir.management.telnet_enabled or ir.management.http_management
    if risky:
        return ControlEvaluation(
            CS.FAIL,
            {"internet_exposed": True, "telnet_enabled": ir.management.telnet_enabled, "http_management": ir.management.http_management},
            "Insecure management protocol reachable from an internet-facing interface",
        )
    return ControlEvaluation(CS.PASS, {"internet_exposed": True, "telnet_enabled": False, "http_management": False})


def _eval_insecure_services(ir: SecurityIR) -> ControlEvaluation:
    if ir.insecure_services:
        return ControlEvaluation(CS.FAIL, {"insecure_services": ir.insecure_services})
    return ControlEvaluation(CS.PASS, {"insecure_services": []})


def _eval_unused_services(ir: SecurityIR) -> ControlEvaluation:
    if ir.unused_services:
        return ControlEvaluation(CS.FAIL, {"unused_services": ir.unused_services})
    return ControlEvaluation(CS.PASS, {"unused_services": []})


def _eval_session_timeout(ir: SecurityIR) -> ControlEvaluation:
    v = ir.management.session_timeout_seconds
    if v is None:
        return ControlEvaluation(CS.INSUFFICIENT_EVIDENCE, {})
    if v == 0 or v > 900:
        return ControlEvaluation(CS.FAIL, {"session_timeout_seconds": v}, "Administrative session timeout is disabled or exceeds 15 minutes")
    return ControlEvaluation(CS.PASS, {"session_timeout_seconds": v})


CONTROLS: tuple[ControlDefinition, ...] = (
    ControlDefinition(
        "telnet_disabled", "Telnet Disabled", "Telnet must not be used for administrative access.",
        "management_plane", Severity.HIGH, (_cis("4.5"), _nist("AC-17")), _eval_telnet_disabled,
    ),
    ControlDefinition(
        "http_management_disabled", "HTTP Management Disabled", "Unencrypted HTTP must not be used for device management.",
        "management_plane", Severity.HIGH, (_cis("4.5"), _nist("SC-8")), _eval_http_management_disabled,
    ),
    ControlDefinition(
        "ssh_version_2", "SSH Protocol Version >= 2", "SSH version 1 is cryptographically broken; version 2+ is required.",
        "management_plane", Severity.HIGH, (_cis("4.5"), _nist("SC-13")), _eval_ssh_version,
    ),
    ControlDefinition(
        "management_encryption_in_use", "Encrypted Management Enabled", "Management access must use an encrypted transport (HTTPS).",
        "management_plane", Severity.MEDIUM, (_cis("4.5"), _nist("SC-8")), _eval_management_encryption,
    ),
    ControlDefinition(
        "password_policy_minimum_length", "Minimum Password Length", "Passwords must meet a minimum length baseline.",
        "authentication", Severity.MEDIUM, (_cis("5.2"), _nist("IA-5")), _eval_password_policy,
    ),
    ControlDefinition(
        "privileged_access_restricted", "Privileged Access Restricted", "Enable/privileged access must use a strong, distinct secret mechanism.",
        "authentication", Severity.HIGH, (_cis("5.4"), _nist("AC-6")), _eval_privileged_access_restricted,
    ),
    ControlDefinition(
        "mfa_enforced", "Multi-Factor Authentication", "Administrative access should be protected by MFA where representable.",
        "authentication", Severity.HIGH, (_cis("6.1"), _nist("IA-2(1)")), _eval_mfa,
    ),
    ControlDefinition(
        "no_default_credentials", "No Default Credential Indicators", "Configuration must not contain default/well-known credential patterns.",
        "authentication", Severity.CRITICAL, (_cis("5.2"), _nist("IA-5")), _eval_default_credentials,
    ),
    ControlDefinition(
        "logging_enabled", "Logging Enabled", "Device-level logging must be enabled.",
        "logging", Severity.MEDIUM, (_cis("8.2"), _nist("AU-2")), _eval_logging_enabled,
    ),
    ControlDefinition(
        "remote_syslog_configured", "Remote Syslog Configured", "Logs must be forwarded to a centralized/remote syslog server.",
        "logging", Severity.MEDIUM, (_cis("8.9"), _nist("AU-4")), _eval_remote_syslog,
    ),
    ControlDefinition(
        "audit_logging_enabled", "Audit Logging Enabled", "Administrative actions must be captured via accounting/audit logging.",
        "logging", Severity.MEDIUM, (_cis("8.5"), _nist("AU-6")), _eval_audit_logging,
    ),
    ControlDefinition(
        "ntp_configured", "NTP Configured", "An NTP source must be configured for reliable log timestamps.",
        "logging", Severity.LOW, (_cis("8.4"), _nist("AU-8")), _eval_ntp_configured,
    ),
    ControlDefinition(
        "snmp_secure", "Secure SNMP Configuration", "SNMP must use v3 or avoid default/weak community strings.",
        "management_plane", Severity.HIGH, (_cis("4.5"), _nist("SC-8")), _eval_snmp_secure,
    ),
    ControlDefinition(
        "no_unrestricted_acl_rules", "No Unrestricted ACL Rules", "Access-control rules must not permit any-source/any-destination traffic.",
        "access_control", Severity.CRITICAL, (_cis("4.4"), _nist("SC-7")), _eval_unrestricted_acl,
    ),
    ControlDefinition(
        "management_plane_not_internet_exposed", "Management Plane Not Internet-Exposed", "Insecure management protocols must not be reachable from internet-facing interfaces.",
        "access_control", Severity.CRITICAL, (_cis("12.4"), _nist("SC-7")), _eval_management_plane_exposure,
    ),
    ControlDefinition(
        "no_insecure_services", "No Insecure Services Enabled", "Deprecated/insecure services must be disabled.",
        "hardening", Severity.MEDIUM, (_cis("4.8"), _nist("CM-7")), _eval_insecure_services,
    ),
    ControlDefinition(
        "no_unused_services", "No Unused Services Enabled", "Unnecessary services must be disabled to reduce attack surface.",
        "hardening", Severity.LOW, (_cis("4.8"), _nist("CM-7")), _eval_unused_services,
    ),
    ControlDefinition(
        "session_timeout_configured", "Administrative Session Timeout", "Administrative sessions must time out after a bounded period of inactivity.",
        "management_plane", Severity.MEDIUM, (_cis("4.3"), _nist("AC-11")), _eval_session_timeout,
    ),
)
