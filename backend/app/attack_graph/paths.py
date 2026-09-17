"""Derives "Potential Attack Path" entries from the attack graph (spec
section 22). Paths are actual `networkx.all_simple_paths` results from an
Internet entry point to a critical asset -- never a hard-coded topology --
ranked by the number/severity of related findings so the highest-risk paths
surface first. Always labeled as *potential*, never confirmed exploitation.
"""
from __future__ import annotations

import networkx as nx

from app.attack_graph.builder import NODE_ASSET, NODE_DEVICE, NODE_INTERNET, NODE_SERVICE

_MAX_PATH_LENGTH = 8
_SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3}


def _services_exposed_by_devices(g: nx.DiGraph, path: list[str]) -> list[str]:
    """Services hang off a device as a side-branch (device --service_exposure--
    service), not on the literal Internet->Asset node sequence -- reaching a
    device on the path exposes everything attached to it, so collect those
    rather than only nodes literally in `path`."""
    services: list[str] = []
    for node in path:
        if g.nodes[node].get("type") != NODE_DEVICE:
            continue
        for succ in g.successors(node):
            if g.nodes[succ].get("type") == NODE_SERVICE:
                services.append(g.nodes[succ].get("label", succ))
    return services


def find_potential_attack_paths(g: nx.DiGraph, findings: list[dict]) -> list[dict]:
    internet_nodes = [n for n, d in g.nodes(data=True) if d.get("type") == NODE_INTERNET]
    asset_nodes = [n for n, d in g.nodes(data=True) if d.get("type") == NODE_ASSET]

    if not internet_nodes or not asset_nodes:
        return []

    finding_risk_score = sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)

    paths: list[dict] = []
    for src in internet_nodes:
        for dst in asset_nodes:
            try:
                simple_paths = list(nx.all_simple_paths(g, src, dst, cutoff=_MAX_PATH_LENGTH))
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                continue
            for path in simple_paths:
                step_labels = [g.nodes[n].get("label", n) for n in path]
                exposed_services_on_path = _services_exposed_by_devices(g, path)
                paths.append(
                    {
                        "path": path,
                        "steps": step_labels,
                        "hop_count": len(path) - 1,
                        "exposed_services": exposed_services_on_path,
                        # Path-level risk contribution: shorter paths through
                        # exposed insecure services combined with the
                        # device's actual finding severity mix.
                        "risk_contribution": finding_risk_score + len(exposed_services_on_path) * 10,
                        "label": "Potential Attack Path",
                    }
                )

    paths.sort(key=lambda p: p["risk_contribution"], reverse=True)
    return paths
