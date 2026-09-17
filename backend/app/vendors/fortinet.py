"""Fortinet FortiOS configuration parser.

FortiOS config syntax is block-structured: `config <section>` / `edit <name>`
/ `set <key> <value>` / `next` / `end`. This parser extracts the same
security-relevant fields as the Cisco parser but reads FortiOS syntax,
proving out the "same IR field, different vendor command" normalization
the spec requires (section 15).
"""
from __future__ import annotations

import re

from app.normalization.ir_schema import (
    AclRule,
    Interface,
    SecurityIR,
    UnmappedCommand,
    Zone,
)

SIGNATURE_HINTS = (
    "config system interface",
    "config firewall policy",
    "set allowaccess",
    "config system global",
    "next\nend",
    "fortios",
)

# See app/vendors/cisco.py's REFERENCE_SNIPPETS for why this is separate from
# SIGNATURE_HINTS -- these feed the embedding-similarity detection signal in
# app/vendors/registry.py.
REFERENCE_SNIPPETS = (
    'config firewall policy\n edit 1\n set srcintf "port1"\n set dstintf "port2"\n set action accept\n next\nend',
    'config system interface\n edit "port1"\n set mode static\n set ip 192.168.1.1 255.255.255.0\n next\nend',
    'config vpn ipsec phase1-interface\n edit "to_branch"\n set interface "wan1"\n next\nend',
    'config system admin\n edit "admin"\n set accprofile "super_admin"\n next\nend',
)

_EXTERNAL_HINTS = ("wan", "outside", "internet", "untrust")


def _edit_blocks(section_body: str) -> list[tuple[str, str]]:
    """Return (edit_name, block_body) pairs within a `config` section."""
    return re.findall(r"edit\s+\"?([^\"\n]+)\"?\s*\n((?:(?!edit\s|end\s*$).*\n?)*?)next", section_body, re.M)


def _config_section(text: str, section_name: str) -> str | None:
    m = re.search(
        rf"config {re.escape(section_name)}\s*\n((?:(?!^config\s|^end\s*$).*\n?)*)^end",
        text,
        re.M,
    )
    return m.group(1) if m else None


def _set_value(block: str, key: str) -> str | None:
    m = re.search(rf"set {re.escape(key)}\s+(.+)", block, re.I)
    return m.group(1).strip().strip('"') if m else None


class FortiOSParser:
    vendor_name = "Fortinet"
    implemented = True
    REFERENCE_SNIPPETS = REFERENCE_SNIPPETS

    def detect_confidence(self, text: str) -> float:
        lowered = text.lower()
        hits = sum(1 for hint in SIGNATURE_HINTS if hint in lowered)
        return min(1.0, hits / 3)

    def parse(self, text: str) -> SecurityIR:
        ir = SecurityIR()
        ir.device.vendor = "Fortinet"
        ir.device.os = "FortiOS"

        if m := re.search(r"#config-version=\S*?-(\d+\.\d+\.\d+)", text):
            ir.device.version = m.group(1)
        if m := re.search(r"set hostname\s+\"?([^\"\n]+)\"?", text, re.I):
            ir.device.hostname = m.group(1)

        # --- Management plane ---
        if m := re.search(r"set ssh-version\s+(\d)", text, re.I):
            ir.management.ssh_version = int(m.group(1))
            ir.management.ssh_enabled = True

        global_section = _config_section(text, "system global") or ""
        if _set_value(global_section, "admin-ssh-v1") == "enable":
            ir.management.ssh_version = 1

        # Allowaccess on interfaces determines telnet/http/https/ssh exposure.
        telnet_enabled = False
        http_mgmt = False
        https_mgmt = False
        ssh_enabled = ir.management.ssh_enabled or False

        iface_section = _config_section(text, "system interface") or ""
        for name, block in _edit_blocks(iface_section):
            allowaccess = (_set_value(block, "allowaccess") or "").lower()
            if "telnet" in allowaccess:
                telnet_enabled = True
            if re.search(r"\bhttp\b", allowaccess):
                http_mgmt = True
            if "https" in allowaccess:
                https_mgmt = True
            if "ssh" in allowaccess:
                ssh_enabled = True

            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", _set_value(block, "ip") or "")
            role = (_set_value(block, "role") or "").lower()
            internet_facing = role == "wan" or any(h in name.lower() for h in _EXTERNAL_HINTS)
            ir.network.interfaces.append(
                Interface(
                    name=name,
                    ip_address=ip_match.group(1) if ip_match else None,
                    internet_facing=internet_facing,
                    enabled=_set_value(block, "status") != "down",
                )
            )

        ir.management.telnet_enabled = telnet_enabled
        ir.management.http_management = http_mgmt
        ir.management.https_management = https_mgmt
        ir.management.ssh_enabled = ssh_enabled
        ir.internet_exposed = any(i.internet_facing for i in ir.network.interfaces)

        if m := re.search(r"set idle-timeout\s+(\d+)", text, re.I):
            ir.management.session_timeout_seconds = int(m.group(1)) * 60

        # --- Authentication ---
        pw_policy_section = _config_section(text, "system password-policy") or ""
        if m := re.search(r"set minimum-length\s+(\d+)", pw_policy_section, re.I):
            ir.authentication.password_policy.minimum_length = int(m.group(1))
        ir.authentication.aaa_enabled = bool(re.search(r"config user (radius|tacacs\+|ldap)", text, re.I))
        ir.authentication.mfa = bool(re.search(r"set two-factor\s+\w*(?<!disable)$", text, re.I | re.M)) or None

        # --- Logging ---
        syslog_section = _config_section(text, "log syslogd setting") or ""
        syslog_status = _set_value(syslog_section, "status")
        syslog_server = _set_value(syslog_section, "server")
        ir.logging.enabled = syslog_status == "enable" or bool(re.search(r"set status\s+enable", text, re.I))
        ir.logging.remote_syslog = syslog_status == "enable" and bool(syslog_server)
        ir.logging.syslog_servers = [syslog_server] if syslog_server else []
        ir.logging.audit_logging = bool(re.search(r"config log .*setting", text, re.I))

        # --- NTP ---
        ntp_section = _config_section(text, "system ntp") or ""
        ir.ntp.enabled = _set_value(ntp_section, "ntpsync") == "enable"
        ntp_servers = re.findall(r"set server\s+\"?([\w.\-]+)\"?", ntp_section)
        ir.ntp.servers = ntp_servers

        # --- SNMP ---
        snmp_section = _config_section(text, "system snmp sysinfo") or ""
        ir.snmp.enabled = _set_value(snmp_section, "status") == "enable" or bool(
            re.search(r"config system snmp community", text, re.I)
        )
        community_section = _config_section(text, "system snmp community") or ""
        communities = _edit_blocks(community_section)
        ir.snmp.community_strings_present = len(communities) > 0
        if communities:
            ir.snmp.version = "2c"
        if re.search(r"config system snmp user", text, re.I):
            ir.snmp.version = "3"

        # --- Zones ---
        zone_section = _config_section(text, "system zone") or ""
        for name, _block in _edit_blocks(zone_section):
            ir.network.zones.append(Zone(name=name))

        # --- Firewall policy (ACL) ---
        policy_section = _config_section(text, "firewall policy") or ""
        for name, block in _edit_blocks(policy_section):
            action = (_set_value(block, "action") or "deny").lower()
            src = (_set_value(block, "srcaddr") or "any").lower()
            dst = (_set_value(block, "dstaddr") or "any").lower()
            svc = (_set_value(block, "service") or "any").lower()
            is_unrestricted = action == "accept" and src == "all" and dst == "all" and svc in ("all", "any")
            ir.access_control.rules.append(
                AclRule(
                    name=f"policy-{name}",
                    action="permit" if action == "accept" else "deny",
                    source=src,
                    destination=dst,
                    service=svc,
                    is_unrestricted=is_unrestricted,
                )
            )

        # --- Insecure services ---
        if ir.management.telnet_enabled:
            ir.insecure_services.append("telnet")
        if ir.management.http_management:
            ir.insecure_services.append("http_management")

        # --- Unmapped commands (top-level `set`/`config` lines we don't recognize) ---
        known_section_names = {
            "system interface",
            "system global",
            "system password-policy",
            "log syslogd setting",
            "system ntp",
            "system snmp sysinfo",
            "system snmp community",
            "system snmp user",
            "system zone",
            "firewall policy",
        }
        for idx, line in enumerate(text.split("\n"), start=1):
            stripped = line.strip()
            m = re.match(r"config\s+(.+)", stripped, re.I)
            if m and m.group(1).lower() not in known_section_names and not m.group(1).lower().startswith(("user ", "log ")):
                ir.unmapped_commands.append(UnmappedCommand(raw_line=stripped, line_number=idx))

        return ir
