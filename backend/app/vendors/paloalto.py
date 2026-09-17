"""Palo Alto Networks PAN-OS configuration parser.

Supports the two real PAN-OS export formats:
  1. The native XML running-config (`<config>...</config>`), parsed with
     `xml.etree.ElementTree`.
  2. The "set"-command CLI format (`set deviceconfig system hostname ...`),
     which is line/regex-parseable like Cisco/FortiOS.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from app.normalization.ir_schema import (
    AclRule,
    Interface,
    SecurityIR,
    UnmappedCommand,
    Zone,
)

SIGNATURE_HINTS = (
    "set deviceconfig",
    "set network interface",
    "set rulebase security rules",
    "set vsys",
    "pan-os",
    "panos",
    "<devices><entry",
)

# See app/vendors/cisco.py's REFERENCE_SNIPPETS for why this is separate from
# SIGNATURE_HINTS -- these feed the embedding-similarity detection signal in
# app/vendors/registry.py.
REFERENCE_SNIPPETS = (
    "set rulebase security rules Allow-Web from trust to untrust source any destination any application web-browsing action allow",
    "set network interface ethernet1/1 layer3 ip 10.1.1.1/24",
    "set zone trust network layer3 ethernet1/1",
    "set deviceconfig system dns-setting servers primary 8.8.8.8",
    "set vsys vsys1 import network interface ethernet1/1",
)

_EXTERNAL_HINTS = ("untrust", "outside", "wan", "internet")

_KNOWN_SET_PREFIXES = (
    "set deviceconfig",
    "set network",
    "set vsys",
    "set zone",
    "set rulebase",
    "set shared",
    "set mgt-config",
    "set address",
    "set service",
    "set application",
)


class PanOSParser:
    vendor_name = "PaloAlto"
    implemented = True
    REFERENCE_SNIPPETS = REFERENCE_SNIPPETS

    def detect_confidence(self, text: str) -> float:
        lowered = text.lower()
        hits = sum(1 for hint in SIGNATURE_HINTS if hint in lowered)
        score = min(1.0, hits / 3)
        if text.strip().startswith("<") and "panorama" in lowered or "<config" in lowered:
            score = max(score, 0.6)
        return score

    def parse(self, text: str) -> SecurityIR:
        stripped = text.strip()
        if stripped.startswith("<"):
            return self._parse_xml(text)
        return self._parse_set_commands(text)

    # --- XML format -----------------------------------------------------

    def _parse_xml(self, text: str) -> SecurityIR:
        ir = SecurityIR()
        ir.device.vendor = "PaloAlto"
        ir.device.os = "PAN-OS"

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid PAN-OS XML configuration: {exc}") from exc

        hostname_el = root.find(".//deviceconfig/system/hostname")
        if hostname_el is not None:
            ir.device.hostname = hostname_el.text

        # Management profile flags (ssh/https/http/telnet).
        ssh_enabled = https_enabled = http_enabled = telnet_enabled = False
        for profile in root.findall(".//interface-management-profile/entry"):
            def _yes(tag: str) -> bool:
                el = profile.find(tag)
                return el is not None and (el.text or "").strip().lower() == "yes"

            ssh_enabled = ssh_enabled or _yes("ssh")
            https_enabled = https_enabled or _yes("https")
            http_enabled = http_enabled or _yes("http")
            telnet_enabled = telnet_enabled or _yes("telnet")

        ir.management.ssh_enabled = ssh_enabled
        ir.management.ssh_version = 2 if ssh_enabled else None  # PAN-OS mgmt SSH is v2-only
        ir.management.https_management = https_enabled
        ir.management.http_management = http_enabled
        ir.management.telnet_enabled = telnet_enabled

        idle_el = root.find(".//mgt-config/idle-timeout")
        if idle_el is not None:
            try:
                ir.management.session_timeout_seconds = int(idle_el.text) * 60
            except (TypeError, ValueError):
                pass

        # Password complexity.
        minlen_el = root.find(".//password-complexity/minimum-length")
        if minlen_el is not None:
            try:
                ir.authentication.password_policy.minimum_length = int(minlen_el.text)
            except (TypeError, ValueError):
                pass

        # Logging / syslog.
        syslog_servers = [
            (el.text or "").strip()
            for el in root.findall(".//log-settings/syslog//server")
            if el.text
        ]
        ir.logging.syslog_servers = syslog_servers
        ir.logging.remote_syslog = len(syslog_servers) > 0
        ir.logging.enabled = True  # PAN-OS logs by default; explicit disable is rare/unsupported

        # NTP.
        ntp_servers = [
            (el.text or "").strip()
            for el in root.findall(".//ntp-servers//ntp-server-address")
            if el.text
        ]
        ir.ntp.servers = ntp_servers
        ir.ntp.enabled = len(ntp_servers) > 0

        # SNMP.
        snmp_communities = root.findall(".//snmp-setting//snmp-community-string")
        ir.snmp.community_strings_present = len(snmp_communities) > 0
        ir.snmp.enabled = len(snmp_communities) > 0

        # Zones.
        for zone_entry in root.findall(".//vsys/entry/zone/entry"):
            name = zone_entry.get("name")
            if name:
                ir.network.zones.append(Zone(name=name))

        # Interfaces (layer3 ethernet).
        for entry in root.findall(".//network/interface/ethernet/entry"):
            name = entry.get("name") or "unknown"
            ip_entry = entry.find(".//layer3/ip/entry")
            ip_address = ip_entry.get("name").split("/")[0] if ip_entry is not None and ip_entry.get("name") else None
            internet_facing = any(h in name.lower() for h in _EXTERNAL_HINTS)
            ir.network.interfaces.append(Interface(name=name, ip_address=ip_address, internet_facing=internet_facing))

        # Zone-based internet exposure (untrust zone members).
        for zone_entry in root.findall(".//vsys/entry/zone/entry"):
            zname = (zone_entry.get("name") or "").lower()
            if any(h in zname for h in _EXTERNAL_HINTS):
                for member in zone_entry.findall(".//network/layer3/member"):
                    for iface in ir.network.interfaces:
                        if iface.name == (member.text or ""):
                            iface.internet_facing = True

        ir.internet_exposed = any(i.internet_facing for i in ir.network.interfaces)

        # Security rules (ACL-equivalent).
        for rule in root.findall(".//rulebase/security/rules/entry"):
            action = (rule.findtext("action") or "deny").lower()
            source_members = [m.text for m in rule.findall("source/member") if m.text]
            dest_members = [m.text for m in rule.findall("destination/member") if m.text]
            src = source_members[0] if source_members else "any"
            dst = dest_members[0] if dest_members else "any"
            is_unrestricted = action == "allow" and src == "any" and dst == "any"
            ir.access_control.rules.append(
                AclRule(
                    name=rule.get("name"),
                    action="permit" if action == "allow" else "deny",
                    source=src,
                    destination=dst,
                    is_unrestricted=is_unrestricted,
                )
            )

        if ir.management.telnet_enabled:
            ir.insecure_services.append("telnet")
        if ir.management.http_management:
            ir.insecure_services.append("http_management")

        return ir

    # --- "set" command format --------------------------------------------

    def _parse_set_commands(self, text: str) -> SecurityIR:
        ir = SecurityIR()
        ir.device.vendor = "PaloAlto"
        ir.device.os = "PAN-OS"

        if m := re.search(r"set deviceconfig system hostname\s+(\S+)", text, re.I):
            ir.device.hostname = m.group(1)

        mgmt_profiles = re.findall(
            r"set network profiles interface-management-profile\s+\S+\s+(ssh|https|http|telnet)\s+(yes|no)",
            text,
            re.I,
        )
        flags = {k.lower(): v.lower() == "yes" for k, v in mgmt_profiles}
        ir.management.ssh_enabled = flags.get("ssh", False)
        ir.management.ssh_version = 2 if flags.get("ssh") else None
        ir.management.https_management = flags.get("https", False)
        ir.management.http_management = flags.get("http", False)
        ir.management.telnet_enabled = flags.get("telnet", False)

        if m := re.search(r"set mgt-config idle-timeout\s+(\d+)", text, re.I):
            ir.management.session_timeout_seconds = int(m.group(1)) * 60

        if m := re.search(r"set shared password-complexity minimum-length\s+(\d+)", text, re.I):
            ir.authentication.password_policy.minimum_length = int(m.group(1))

        syslog_servers = re.findall(r"set shared log-settings syslog\s+\S+\s+server\s+\S+\s+server\s+(\S+)", text, re.I)
        ir.logging.syslog_servers = syslog_servers
        ir.logging.remote_syslog = len(syslog_servers) > 0
        ir.logging.enabled = True

        ntp_servers = re.findall(r"set deviceconfig system ntp-servers \S+ ntp-server-address\s+(\S+)", text, re.I)
        ir.ntp.servers = ntp_servers
        ir.ntp.enabled = len(ntp_servers) > 0

        snmp_matches = re.findall(r"snmp-community-string\s+(\S+)", text, re.I)
        ir.snmp.community_strings_present = len(snmp_matches) > 0
        ir.snmp.enabled = len(snmp_matches) > 0

        for m in re.finditer(r"set zone\s+(\S+)\s+network", text, re.I):
            ir.network.zones.append(Zone(name=m.group(1)))
        for m in re.finditer(r"set vsys\s+\S+\s+zone\s+(\S+)\s+network", text, re.I):
            ir.network.zones.append(Zone(name=m.group(1)))

        for m in re.finditer(
            r"set network interface ethernet\s+(\S+)\s+layer3 ip\s+(\d{1,3}(?:\.\d{1,3}){3})", text, re.I
        ):
            name, ip = m.groups()
            internet_facing = any(h in name.lower() for h in _EXTERNAL_HINTS)
            ir.network.interfaces.append(Interface(name=name, ip_address=ip, internet_facing=internet_facing))

        # Mark interfaces in an untrust/outside zone as internet-facing.
        for zm in re.finditer(r"set (?:vsys\s+\S+\s+)?zone\s+(\S+)\s+network layer3\s+\[?\s*([^\]\n]+)\]?", text, re.I):
            zone_name, members_str = zm.groups()
            if any(h in zone_name.lower() for h in _EXTERNAL_HINTS):
                for member in members_str.split():
                    for iface in ir.network.interfaces:
                        if iface.name == member:
                            iface.internet_facing = True

        ir.internet_exposed = any(i.internet_facing for i in ir.network.interfaces)

        for m in re.finditer(
            r"set rulebase security rules\s+(\S+)\s+from\s+(\S+)\s+to\s+(\S+)\s+source\s+(\S+)\s+destination\s+(\S+)\s+application\s+\S+\s+service\s+\S+\s+action\s+(\S+)",
            text,
            re.I,
        ):
            name, _frm, _to, src, dst, action = m.groups()
            is_unrestricted = action.lower() == "allow" and src.lower() == "any" and dst.lower() == "any"
            ir.access_control.rules.append(
                AclRule(name=name, action="permit" if action.lower() == "allow" else "deny", source=src, destination=dst, is_unrestricted=is_unrestricted)
            )

        if ir.management.telnet_enabled:
            ir.insecure_services.append("telnet")
        if ir.management.http_management:
            ir.insecure_services.append("http_management")

        for idx, line in enumerate(text.split("\n"), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(_KNOWN_SET_PREFIXES):
                continue
            if stripped.startswith("set "):
                ir.unmapped_commands.append(UnmappedCommand(raw_line=stripped, line_number=idx))

        return ir
