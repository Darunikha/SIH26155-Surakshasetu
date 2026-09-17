from app.compliance.engine import run_compliance
from app.compliance.models import ComplianceStatus
from app.normalization.ir_schema import SecurityIR


def _weak_ir() -> SecurityIR:
    ir = SecurityIR()
    ir.management.telnet_enabled = True
    ir.management.ssh_enabled = True
    ir.management.ssh_version = 1
    ir.management.http_management = True
    ir.management.https_management = False
    ir.management.session_timeout_seconds = 0
    ir.authentication.privileged_access_restricted = False
    ir.authentication.default_credentials_detected = True
    ir.logging.enabled = False
    ir.logging.remote_syslog = False
    ir.logging.audit_logging = False
    ir.ntp.enabled = False
    ir.snmp.enabled = True
    ir.snmp.version = "2c"
    ir.snmp.community_strings_present = True
    return ir


def _hardened_ir() -> SecurityIR:
    ir = SecurityIR()
    ir.management.telnet_enabled = False
    ir.management.ssh_enabled = True
    ir.management.ssh_version = 2
    ir.management.http_management = False
    ir.management.https_management = True
    ir.management.session_timeout_seconds = 300
    ir.authentication.privileged_access_restricted = True
    ir.authentication.default_credentials_detected = False
    ir.authentication.password_policy.minimum_length = 16
    ir.logging.enabled = True
    ir.logging.remote_syslog = True
    ir.logging.syslog_servers = ["10.0.0.5"]
    ir.logging.audit_logging = True
    ir.ntp.enabled = True
    ir.ntp.servers = ["10.0.0.9"]
    ir.snmp.enabled = True
    ir.snmp.version = "3"
    return ir


def test_weak_configuration_produces_many_failures():
    result = run_compliance(_weak_ir())
    telnet = next(c for c in result["controls"] if c["control_id"] == "telnet_disabled")
    assert telnet["status"] == ComplianceStatus.FAIL.value
    assert telnet["severity"] == "HIGH"
    assert result["status_counts"]["FAIL"] > result["status_counts"]["PASS"]


def test_hardened_configuration_passes_relevant_controls():
    result = run_compliance(_hardened_ir())
    by_id = {c["control_id"]: c for c in result["controls"]}
    assert by_id["telnet_disabled"]["status"] == ComplianceStatus.PASS.value
    assert by_id["ssh_version_2"]["status"] == ComplianceStatus.PASS.value
    assert by_id["snmp_secure"]["status"] == ComplianceStatus.PASS.value
    assert by_id["no_default_credentials"]["status"] == ComplianceStatus.PASS.value


def test_compliance_score_is_higher_for_hardened_config():
    weak_score = run_compliance(_weak_ir())["compliance_score"]
    hardened_score = run_compliance(_hardened_ir())["compliance_score"]
    assert hardened_score > weak_score


def test_ai_cannot_appear_anywhere_in_compliance_result():
    # Deterministic engine output must contain no AI-related keys -- the
    # compliance verdict is never influenced by the AI service (spec section 17).
    result = run_compliance(_weak_ir())
    serialized_keys = set()
    for c in result["controls"]:
        serialized_keys.update(c.keys())
    assert not any("ai" in k.lower() for k in serialized_keys)


def test_framework_coverage_never_claims_full_coverage():
    result = run_compliance(_weak_ir())
    for info in result["framework_coverage"].values():
        if info["total_controls"] is not None:
            assert info["implemented_controls"] <= info["total_controls"]
            if info["coverage_percent"] is not None:
                assert info["coverage_percent"] < 100.0
