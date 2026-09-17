from app.compliance.engine import run_compliance
from app.compliance.findings import derive_findings
from app.normalization.ir_schema import SecurityIR
from app.risk.engine import calculate_risk


def _internet_exposed_ir() -> SecurityIR:
    ir = SecurityIR()
    ir.internet_exposed = True
    ir.management.telnet_enabled = True
    ir.management.http_management = True
    return ir


def _internal_only_ir() -> SecurityIR:
    ir = SecurityIR()
    ir.internet_exposed = False
    ir.management.telnet_enabled = False
    ir.management.http_management = False
    ir.management.https_management = True
    ir.management.ssh_enabled = True
    ir.management.ssh_version = 2
    ir.authentication.privileged_access_restricted = True
    ir.logging.enabled = True
    ir.logging.remote_syslog = True
    ir.logging.audit_logging = True
    ir.ntp.enabled = True
    return ir


def test_risk_score_is_bounded_0_to_100():
    ir = _internet_exposed_ir()
    compliance = run_compliance(ir)
    findings = derive_findings(compliance, device_id="D1", scan_id="S1")
    risk = calculate_risk(ir, compliance, findings, {"criticality": "critical", "internet_exposure": True})
    assert 0.0 <= risk["risk_score"] <= 100.0


def test_internet_exposed_critical_asset_scores_higher_than_internal_low_criticality():
    exposed_ir = _internet_exposed_ir()
    exposed_compliance = run_compliance(exposed_ir)
    exposed_findings = derive_findings(exposed_compliance, device_id="D1", scan_id="S1")
    exposed_risk = calculate_risk(exposed_ir, exposed_compliance, exposed_findings, {"criticality": "critical", "internet_exposure": True})

    internal_ir = _internal_only_ir()
    internal_compliance = run_compliance(internal_ir)
    internal_findings = derive_findings(internal_compliance, device_id="D2", scan_id="S2")
    internal_risk = calculate_risk(internal_ir, internal_compliance, internal_findings, {"criticality": "low", "internet_exposure": False})

    assert exposed_risk["risk_score"] > internal_risk["risk_score"]
    assert exposed_risk["risk_level"] in ("HIGH", "CRITICAL")
    assert internal_risk["risk_level"] in ("LOW", "MEDIUM")


def test_risk_level_bands_match_documented_thresholds():
    from app.risk.engine import _risk_level

    assert _risk_level(0) == "LOW"
    assert _risk_level(30) == "LOW"
    assert _risk_level(31) == "MEDIUM"
    assert _risk_level(60) == "MEDIUM"
    assert _risk_level(61) == "HIGH"
    assert _risk_level(80) == "HIGH"
    assert _risk_level(81) == "CRITICAL"
    assert _risk_level(100) == "CRITICAL"


def test_asset_context_change_changes_risk_score():
    ir = _internet_exposed_ir()
    compliance = run_compliance(ir)
    findings = derive_findings(compliance, device_id="D1", scan_id="S1")
    low_crit = calculate_risk(ir, compliance, findings, {"criticality": "low", "internet_exposure": True})
    high_crit = calculate_risk(ir, compliance, findings, {"criticality": "critical", "internet_exposure": True})
    assert high_crit["risk_score"] > low_crit["risk_score"]
