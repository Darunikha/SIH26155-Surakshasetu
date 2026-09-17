from app.optimizer.aco import AcoParams, aco_order, compare_strategies, greedy_risk_order, severity_only_order
from app.optimizer.profiles import build_profiles

FINDINGS = [
    {"finding_id": "F1", "control_id": "no_default_credentials", "severity": "CRITICAL", "category": "authentication"},
    {"finding_id": "F2", "control_id": "telnet_disabled", "severity": "HIGH", "category": "management_plane"},
    {"finding_id": "F3", "control_id": "http_management_disabled", "severity": "HIGH", "category": "management_plane"},
    {"finding_id": "F4", "control_id": "management_plane_not_internet_exposed", "severity": "CRITICAL", "category": "access_control"},
    {"finding_id": "F5", "control_id": "ntp_configured", "severity": "LOW", "category": "logging"},
]


def test_build_profiles_respects_declared_dependency():
    profiles = build_profiles(FINDINGS)
    f4 = next(p for p in profiles if p.finding_id == "F4")
    assert set(f4.depends_on) == {"F2", "F3"}


def test_severity_only_order_places_criticals_first_and_respects_dependency():
    profiles = build_profiles(FINDINGS)
    order = severity_only_order(profiles)
    assert order.index("F1") < order.index("F5")  # CRITICAL before LOW
    assert order.index("F2") < order.index("F4")  # dependency respected
    assert order.index("F3") < order.index("F4")


def test_greedy_risk_order_is_a_valid_permutation_respecting_dependency():
    profiles = build_profiles(FINDINGS)
    order = greedy_risk_order(profiles)
    assert sorted(order) == sorted(p.finding_id for p in profiles)
    assert order.index("F2") < order.index("F4")
    assert order.index("F3") < order.index("F4")


def test_aco_order_is_a_valid_permutation_respecting_dependency():
    profiles = build_profiles(FINDINGS)
    order = aco_order(profiles, AcoParams(n_ants=5, n_iterations=5, seed=1))
    assert sorted(order) == sorted(p.finding_id for p in profiles)
    assert order.index("F2") < order.index("F4")
    assert order.index("F3") < order.index("F4")


def test_aco_is_deterministic_given_a_fixed_seed():
    profiles = build_profiles(FINDINGS)
    order1 = aco_order(profiles, AcoParams(n_ants=5, n_iterations=5, seed=7))
    order2 = aco_order(profiles, AcoParams(n_ants=5, n_iterations=5, seed=7))
    assert order1 == order2


def test_compare_strategies_reports_real_measured_metrics_for_all_three():
    result = compare_strategies(FINDINGS, potential_attack_paths=[], aco_params=AcoParams(n_ants=5, n_iterations=5, seed=1))
    assert set(result["strategies"].keys()) == {"severity_only", "greedy_risk", "aco"}
    for metrics in result["strategies"].values():
        assert metrics["runtime_ms"] >= 0
        assert 0.0 <= metrics["risk_reduction_percent"] <= 100.0
        assert metrics["residual_risk"] >= 0


def test_never_fabricates_attack_paths_removed_beyond_available_paths():
    paths = [{"exposed_services": ["telnet"], "label": "Potential Attack Path"}]
    result = compare_strategies(FINDINGS, potential_attack_paths=paths, aco_params=AcoParams(n_ants=5, n_iterations=5, seed=1))
    for metrics in result["strategies"].values():
        assert metrics["attack_paths_removed"] <= metrics["total_potential_paths"]
