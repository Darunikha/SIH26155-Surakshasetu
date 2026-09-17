"""Ant Colony Optimization for remediation sequencing (spec section 23).

ACO decides *order*, never *whether* something is a finding -- that stays
the deterministic compliance engine's job. This is a real, from-scratch ACO
(pheromone matrix over "which finding follows which," heuristic = risk
reduction per unit cost, evaporation + reinforcement each iteration) run
against an actual objective function, compared against two honest
baselines (severity-only, greedy risk-ratio) on the same objective.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass

from app.optimizer.profiles import SEVERITY_RANK, FindingProfile

START = "__START__"


def _dependencies_satisfied(fp: FindingProfile, placed: set[str]) -> bool:
    return all(dep in placed for dep in fp.depends_on)


def severity_only_order(profiles: list[FindingProfile]) -> list[str]:
    remaining = {p.finding_id: p for p in profiles}
    placed: list[str] = []
    placed_set: set[str] = set()
    while remaining:
        candidates = [p for p in remaining.values() if _dependencies_satisfied(p, placed_set)]
        candidates.sort(key=lambda p: (SEVERITY_RANK.get(p.severity, 9), p.finding_id))
        chosen = candidates[0]
        placed.append(chosen.finding_id)
        placed_set.add(chosen.finding_id)
        del remaining[chosen.finding_id]
    return placed


def greedy_risk_order(profiles: list[FindingProfile]) -> list[str]:
    remaining = {p.finding_id: p for p in profiles}
    placed: list[str] = []
    placed_set: set[str] = set()
    while remaining:
        candidates = [p for p in remaining.values() if _dependencies_satisfied(p, placed_set)]
        candidates.sort(key=lambda p: (p.risk_reduction / max(p.cost, 0.1)), reverse=True)
        chosen = candidates[0]
        placed.append(chosen.finding_id)
        placed_set.add(chosen.finding_id)
        del remaining[chosen.finding_id]
    return placed


@dataclass
class AcoParams:
    n_ants: int = 20
    n_iterations: int = 60
    alpha: float = 1.0  # pheromone importance
    beta: float = 2.0  # heuristic importance
    evaporation_rate: float = 0.4
    q: float = 100.0  # pheromone deposit scale
    seed: int | None = 42


def _heuristic(fp: FindingProfile) -> float:
    return max(fp.risk_reduction / max(fp.cost, 0.1), 1e-6)


def _construct_ant_solution(
    profiles_by_id: dict[str, FindingProfile],
    pheromone: dict[tuple[str, str], float],
    params: AcoParams,
    rng: random.Random,
) -> list[str]:
    remaining = dict(profiles_by_id)
    placed: list[str] = []
    placed_set: set[str] = set()
    current = START

    while remaining:
        candidates = [p for p in remaining.values() if _dependencies_satisfied(p, placed_set)]
        weights = []
        for c in candidates:
            tau = pheromone.get((current, c.finding_id), 1.0)
            eta = _heuristic(c)
            weights.append((tau ** params.alpha) * (eta ** params.beta))

        total = sum(weights)
        if total <= 0:
            chosen = rng.choice(candidates)
        else:
            r = rng.uniform(0, total)
            upto = 0.0
            chosen = candidates[-1]
            for c, w in zip(candidates, weights):
                upto += w
                if upto >= r:
                    chosen = c
                    break

        placed.append(chosen.finding_id)
        placed_set.add(chosen.finding_id)
        del remaining[chosen.finding_id]
        current = chosen.finding_id

    return placed


def _sequence_objective(profiles_by_id: dict[str, FindingProfile], sequence: list[str]) -> float:
    """Fitness to MINIMIZE: time-weighted residual risk across the
    remediation timeline plus cumulative cost. Front-loading high
    risk-reduction-per-cost findings lowers this value."""
    total_risk = sum(p.risk_reduction for p in profiles_by_id.values())
    residual = total_risk
    area_under_residual = 0.0
    cumulative_cost = 0.0

    for finding_id in sequence:
        fp = profiles_by_id[finding_id]
        area_under_residual += residual
        residual -= fp.risk_reduction
        cumulative_cost += fp.cost

    n = max(len(sequence), 1)
    avg_residual_risk = area_under_residual / n
    return avg_residual_risk + 0.5 * cumulative_cost


def aco_order(profiles: list[FindingProfile], params: AcoParams | None = None) -> list[str]:
    params = params or AcoParams()
    rng = random.Random(params.seed)
    profiles_by_id = {p.finding_id: p for p in profiles}

    all_ids = list(profiles_by_id.keys())
    pheromone: dict[tuple[str, str], float] = {}
    for a in [START] + all_ids:
        for b in all_ids:
            if a != b:
                pheromone[(a, b)] = 1.0

    best_sequence = None
    best_score = float("inf")

    for _ in range(params.n_iterations):
        iteration_solutions: list[tuple[list[str], float]] = []
        for _ant in range(params.n_ants):
            seq = _construct_ant_solution(profiles_by_id, pheromone, params, rng)
            score = _sequence_objective(profiles_by_id, seq)
            iteration_solutions.append((seq, score))
            if score < best_score:
                best_score = score
                best_sequence = seq

        # Evaporation
        for edge in pheromone:
            pheromone[edge] *= 1 - params.evaporation_rate

        # Reinforcement: better (lower-score) solutions deposit more pheromone.
        for seq, score in iteration_solutions:
            deposit = params.q / (1.0 + score)
            prev = START
            for finding_id in seq:
                pheromone[(prev, finding_id)] = pheromone.get((prev, finding_id), 0.0) + deposit
                prev = finding_id

    return best_sequence or []


def evaluate_sequence(
    profiles_by_id: dict[str, FindingProfile],
    sequence: list[str],
    *,
    budget: int,
    control_to_paths_affected: dict[str, int],
    total_potential_paths: int,
) -> dict:
    """Measures the state after remediating the first `budget` findings in
    this order -- the practically meaningful comparison point, since a real
    remediation cycle has limited capacity per sprint."""
    total_risk = sum(p.risk_reduction for p in profiles_by_id.values())
    completed = sequence[:budget]

    risk_reduced = sum(profiles_by_id[fid].risk_reduction for fid in completed)
    operational_cost = sum(profiles_by_id[fid].cost for fid in completed)
    disruption = sum(profiles_by_id[fid].disruption for fid in completed)
    residual_risk = round(total_risk - risk_reduced, 2)

    paths_removed = sum(
        control_to_paths_affected.get(profiles_by_id[fid].control_id, 0) for fid in completed
    )
    paths_removed = min(paths_removed, total_potential_paths)

    return {
        "sequence": completed,
        "full_sequence": sequence,
        "residual_risk": residual_risk,
        "risk_reduced": round(risk_reduced, 2),
        "risk_reduction_percent": round((risk_reduced / total_risk) * 100, 2) if total_risk else 0.0,
        "operational_cost": round(operational_cost, 2),
        "disruption_estimate": round(disruption, 2),
        "attack_paths_removed": paths_removed,
        "total_potential_paths": total_potential_paths,
    }


def compare_strategies(
    findings: list[dict],
    potential_attack_paths: list[dict],
    *,
    budget: int | None = None,
    aco_params: AcoParams | None = None,
) -> dict:
    from app.optimizer.profiles import CONTROL_TO_SERVICE, build_profiles

    profiles = build_profiles(findings)
    profiles_by_id = {p.finding_id: p for p in profiles}
    budget = budget if budget is not None else max(1, len(profiles) // 3)

    control_to_paths_affected: dict[str, int] = {}
    for control_id, service in CONTROL_TO_SERVICE.items():
        count = sum(1 for path in potential_attack_paths if service in (path.get("exposed_services") or []))
        control_to_paths_affected[control_id] = count

    results = {}
    for strategy_name, order_fn in (
        ("severity_only", severity_only_order),
        ("greedy_risk", greedy_risk_order),
    ):
        t0 = time.perf_counter()
        sequence = order_fn(profiles)
        runtime_ms = (time.perf_counter() - t0) * 1000
        metrics = evaluate_sequence(
            profiles_by_id, sequence, budget=budget,
            control_to_paths_affected=control_to_paths_affected,
            total_potential_paths=len(potential_attack_paths),
        )
        metrics["runtime_ms"] = round(runtime_ms, 4)
        metrics["objective_score"] = round(_sequence_objective(profiles_by_id, sequence), 2)
        results[strategy_name] = metrics

    t0 = time.perf_counter()
    aco_sequence = aco_order(profiles, aco_params)
    aco_runtime_ms = (time.perf_counter() - t0) * 1000
    aco_metrics = evaluate_sequence(
        profiles_by_id, aco_sequence, budget=budget,
        control_to_paths_affected=control_to_paths_affected,
        total_potential_paths=len(potential_attack_paths),
    )
    aco_metrics["runtime_ms"] = round(aco_runtime_ms, 4)
    aco_metrics["objective_score"] = round(_sequence_objective(profiles_by_id, aco_sequence), 2)
    results["aco"] = aco_metrics

    return {"budget": budget, "strategies": results}
