"""Attack-graph construction from the Security IR (spec section 22).

Uses NetworkX. Every node/edge is derived from actual IR content
(interfaces, zones, exposed management services, asset context) -- nothing
here is a hard-coded topology. Results are always described as "Potential
Attack Path," never confirmed exploitation.
"""
from __future__ import annotations

import networkx as nx

from app.normalization.ir_schema import SecurityIR

NODE_INTERNET = "internet"
NODE_DEVICE = "device"
NODE_INTERFACE = "interface"
NODE_ZONE = "zone"
NODE_SERVICE = "service"
NODE_ASSET = "asset"


def build_attack_graph(ir: SecurityIR, *, device_id: str, device_name: str, asset_context: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    device_node = f"device:{device_id}"
    g.add_node(device_node, type=NODE_DEVICE, label=device_name)

    has_internet_facing = any(i.internet_facing for i in ir.network.interfaces) or ir.internet_exposed
    internet_node = "internet:INTERNET"
    if has_internet_facing:
        g.add_node(internet_node, type=NODE_INTERNET, label="Internet")

    for iface in ir.network.interfaces:
        iface_node = f"interface:{device_id}:{iface.name}"
        g.add_node(iface_node, type=NODE_INTERFACE, label=iface.name, internet_facing=iface.internet_facing)
        if iface.internet_facing:
            g.add_edge(internet_node, iface_node, relation="reachability")
            g.add_edge(iface_node, device_node, relation="connectivity")
        else:
            g.add_edge(device_node, iface_node, relation="connectivity")

    exposed_services = []
    if ir.management.telnet_enabled:
        exposed_services.append(("telnet", 23))
    if ir.management.http_management:
        exposed_services.append(("http", 80))
    if ir.management.ssh_enabled and (ir.management.ssh_version or 2) < 2:
        exposed_services.append(("ssh-v1", 22))
    if ir.snmp.enabled and ir.snmp.version in ("1", "2c") and ir.snmp.community_strings_present:
        exposed_services.append(("snmp", 161))

    for name, port in exposed_services:
        svc_node = f"service:{device_id}:{name}"
        g.add_node(svc_node, type=NODE_SERVICE, label=name, port=port)
        g.add_edge(device_node, svc_node, relation="service_exposure")

    for zone in ir.network.zones:
        zone_node = f"zone:{device_id}:{zone.name}"
        g.add_node(zone_node, type=NODE_ZONE, label=zone.name)
        g.add_edge(device_node, zone_node, relation="zone_membership")

    criticality = str(asset_context.get("criticality", "medium")).lower()
    if criticality in ("high", "critical"):
        asset_label = asset_context.get("business_role") or f"{device_name} Critical Asset"
        asset_node = f"asset:{device_id}"
        g.add_node(asset_node, type=NODE_ASSET, label=asset_label, criticality=criticality)
        # An internal (non-internet-facing) interface represents the path
        # toward whatever this device fronts/protects.
        internal_ifaces = [i for i in ir.network.interfaces if not i.internet_facing]
        source_nodes = (
            [f"interface:{device_id}:{i.name}" for i in internal_ifaces] if internal_ifaces else [device_node]
        )
        for src in source_nodes:
            g.add_edge(src, asset_node, relation="protects")

    return g


def serialize_graph(g: nx.DiGraph) -> dict:
    return {
        "nodes": [{"id": n, **data} for n, data in g.nodes(data=True)],
        "edges": [{"source": u, "target": v, **data} for u, v, data in g.edges(data=True)],
    }
