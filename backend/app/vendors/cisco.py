"""Cisco IOS / IOS-XE configuration parser.

Line/block-oriented parser (Cisco IOS config is not a nested structured
format like XML/JSON -- it's an ordered, indentation-free command stream
grouped into "interface"/"line" sub-blocks terminated implicitly by the next
top-level command or `!`). This is a deep, real implementation for the
fields the compliance/risk/attack-graph engines actually consume.
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
    "ip ssh version",
    "line vty",
    "interface gigabitethernet",
    "interface fastethernet",
    "enable secret",
    "ip access-list",
    "no service password-recovery",
    "ios-xe",
)

# A handful of short, representative real Cisco IOS/IOS-XE config lines used
# for the embedding-similarity detection signal in app/vendors/registry.py --
# distinct from SIGNATURE_HINTS (exact substrings) so a config that phrases
# things slightly differently can still be recognized semantically.
REFERENCE_SNIPPETS = (
    "interface GigabitEthernet0/1\n description Uplink to Core Switch\n ip address 10.0.0.1 255.255.255.0\n no shutdown",
    "line vty 0 4\n transport input ssh\n login local\n exec-timeout 10 0",
    "access-list 101 deny ip any any log",
    "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0",
    "enable secret 5 $1$abcd$somehashvalue",
)

_DEFAULT_CREDENTIAL_PATTERNS = (
    re.compile(r"username\s+(cisco|admin|administrator)\s+.*(?:password|secret)\s+(?:\d\s+)?(cisco|admin|password|123456)", re.I),
)

_EXTERNAL_HINTS = ("outside", "wan", "internet", "external", "untrust")

# Command prefixes we explicitly understand -- anything else at top level
# that doesn't match becomes an "unmapped command" for adaptive learning.
_KNOWN_TOP_LEVEL_PREFIXES = (
    "version",
    "hostname",
    "enable secret",
    "enable password",
    "username",
    "aaa",
    "ip ssh",
    "ip http",
    "ip domain",
    "ip name-server",
    "no ip http",
    "no ip domain",
    "line ",
    "interface ",
    "zone security",
    "zone-pair",
    "access-list",
    "ip access-list",
    "logging",
    "ntp server",
    "ntp source",
    "snmp-server",
    "security passwords",
    "service password-encryption",
    "no service password-recovery",
    "clock timezone",
    "banner",
    "archive",
    "crypto",
    "exit",
    "end",
    "!",
    "boot",
    "spanning-tree",
    "vlan",
    "ip route",
    "ip nat",
    "ip cef",
    "no ip source-route",
)


class CiscoIOSParser:
    vendor_name = "Cisco"
    implemented = True
    REFERENCE_SNIPPETS = REFERENCE_SNIPPETS

    def detect_confidence(self, text: str) -> float:
        lowered = text.lower()
        hits = sum(1 for hint in SIGNATURE_HINTS if hint in lowered)
        score = min(1.0, hits / 4)
        if re.search(r"^\s*!\s*$", text, re.M) and "interface" in lowered:
            score = max(score, 0.5)
        return score

    def parse(self, text: str) -> SecurityIR:
        ir = SecurityIR()
        lines = text.split("\n")

        ir.device.vendor = "Cisco"
        ir.device.os = "IOS-XE" if "ios-xe" in text.lower() else "IOS"

        if m := re.search(r"^hostname\s+(\S+)", text, re.M | re.I):
            ir.device.hostname = m.group(1)
        if m := re.search(r"version\s+(\d+\.\d+)", text, re.M):
            ir.device.version = m.group(1)

        # --- Management plane ---
        if m := re.search(r"^\s*ip ssh version\s+(\d)", text, re.M | re.I):
            ir.management.ssh_version = int(m.group(1))
            ir.management.ssh_enabled = True
        elif re.search(r"^\s*ip ssh ", text, re.M | re.I):
            ir.management.ssh_enabled = True

        if re.search(r"^\s*no ip http server", text, re.M | re.I):
            ir.management.http_management = False
        elif re.search(r"^\s*ip http server", text, re.M | re.I):
            ir.management.http_management = True

        if re.search(r"^\s*ip http secure-server", text, re.M | re.I):
            ir.management.https_management = True

        # Telnet: look inside `line vty` blocks for `transport input`.
        vty_blocks = re.findall(r"line vty[^\n]*\n((?:\s+\S.*\n?)*)", text, re.I)
        telnet_enabled = False
        timeout_seconds: int | None = None
        for block in vty_blocks:
            if re.search(r"transport input\s+.*(telnet|all)", block, re.I):
                telnet_enabled = True
            if re.search(r"transport input\s+ssh\s*$", block, re.I | re.M):
                pass  # explicit ssh-only; telnet_enabled stays as found above
            if not re.search(r"transport input", block, re.I):
                # Cisco default (no explicit restriction) permits telnet.
                telnet_enabled = telnet_enabled or True
            if m := re.search(r"exec-timeout\s+(\d+)\s+(\d+)", block):
                timeout_seconds = int(m.group(1)) * 60 + int(m.group(2))
        if vty_blocks:
            ir.management.telnet_enabled = telnet_enabled
        ir.management.session_timeout_seconds = timeout_seconds

        # --- Authentication ---
        ir.authentication.aaa_enabled = bool(re.search(r"^\s*aaa new-model", text, re.M | re.I))
        if m := re.search(r"security passwords min-length\s+(\d+)", text, re.I):
            ir.authentication.password_policy.minimum_length = int(m.group(1))
        ir.authentication.privileged_access_restricted = bool(
            re.search(r"^\s*enable secret", text, re.M | re.I)
        ) and not re.search(r"^\s*enable password\s", text, re.M | re.I)
        ir.authentication.default_credentials_detected = any(
            p.search(text) for p in _DEFAULT_CREDENTIAL_PATTERNS
        )
        ir.authentication.mfa = None  # not representable from IOS config alone

        # --- Logging ---
        ir.logging.enabled = not bool(re.search(r"^\s*no logging on", text, re.M | re.I))
        syslog_servers = re.findall(r"^\s*logging (?:host )?(\d{1,3}(?:\.\d{1,3}){3})", text, re.M | re.I)
        ir.logging.syslog_servers = syslog_servers
        ir.logging.remote_syslog = len(syslog_servers) > 0
        ir.logging.audit_logging = bool(re.search(r"^\s*aaa accounting", text, re.M | re.I))

        # --- NTP ---
        ntp_servers = re.findall(r"^\s*ntp server\s+(\S+)", text, re.M | re.I)
        ir.ntp.servers = ntp_servers
        ir.ntp.enabled = len(ntp_servers) > 0

        # --- SNMP ---
        snmp_communities = re.findall(r"^\s*snmp-server community\s+(\S+)", text, re.M | re.I)
        ir.snmp.community_strings_present = len(snmp_communities) > 0
        ir.snmp.enabled = len(snmp_communities) > 0 or bool(re.search(r"^\s*snmp-server", text, re.M | re.I))
        if re.search(r"snmp-server group .*\bv3\b", text, re.I):
            ir.snmp.version = "3"
        elif snmp_communities:
            ir.snmp.version = "2c"

        # --- Interfaces ---
        for iface_match in re.finditer(
            r"^interface\s+(\S+)\s*\n((?:^[ \t]+\S.*\n?)*)", text, re.M
        ):
            name, block = iface_match.group(1), iface_match.group(2)
            desc_match = re.search(r"description\s+(.+)", block, re.I)
            description = desc_match.group(1) if desc_match else ""
            ip_match = re.search(r"ip address\s+(\d{1,3}(?:\.\d{1,3}){3})", block)
            shutdown = bool(re.search(r"^\s*shutdown", block, re.M | re.I))
            internet_facing = any(hint in description.lower() or hint in name.lower() for hint in _EXTERNAL_HINTS)
            ir.network.interfaces.append(
                Interface(
                    name=name,
                    ip_address=ip_match.group(1) if ip_match else None,
                    internet_facing=internet_facing,
                    enabled=not shutdown,
                )
            )

        ir.internet_exposed = any(i.internet_facing for i in ir.network.interfaces)

        for zm in re.finditer(r"^zone security\s+(\S+)", text, re.M | re.I):
            ir.network.zones.append(Zone(name=zm.group(1)))

        # --- ACLs ---
        for acl_match in re.finditer(
            r"^access-list\s+\d+\s+(permit|deny)\s+\S+\s+(\S+)\s+(\S+)", text, re.M | re.I
        ):
            action, src, dst = acl_match.groups()
            is_unrestricted = action.lower() == "permit" and src.lower() == "any" and dst.lower() == "any"
            ir.access_control.rules.append(
                AclRule(action=action.lower(), source=src, destination=dst, is_unrestricted=is_unrestricted)
            )
        for name_match in re.finditer(
            r"^ip access-list extended\s+(\S+)\s*\n((?:^\s+\S.*\n?)*)", text, re.M
        ):
            acl_name, block = name_match.groups()
            for rule_match in re.finditer(r"(permit|deny)\s+(\S+)\s+(any|\S+)\s+(any|\S+)", block, re.I):
                action, _proto, src, dst = rule_match.groups()
                is_unrestricted = action.lower() == "permit" and src.lower() == "any" and dst.lower() == "any"
                ir.access_control.rules.append(
                    AclRule(name=acl_name, action=action.lower(), source=src, destination=dst, is_unrestricted=is_unrestricted)
                )

        # --- Insecure / unused services ---
        if ir.management.telnet_enabled:
            ir.insecure_services.append("telnet")
        if ir.management.http_management:
            ir.insecure_services.append("http_management")
        if re.search(r"^\s*ip finger", text, re.M | re.I) or re.search(r"^\s*service finger", text, re.M | re.I):
            ir.unused_services.append("finger")
        if re.search(r"^\s*ip bootp server", text, re.M | re.I):
            ir.unused_services.append("bootp")

        # --- Unmapped commands (adaptive learning input) ---
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            if any(stripped.lower().startswith(p) for p in _KNOWN_TOP_LEVEL_PREFIXES):
                continue
            if line.startswith((" ", "\t")):
                continue  # sub-block line, handled by its parent block parser
            ir.unmapped_commands.append(UnmappedCommand(raw_line=stripped, line_number=idx))

        return ir
