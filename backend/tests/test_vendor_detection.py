from app.vendors.cisco import CiscoIOSParser
from app.vendors.fortinet import FortiOSParser
from app.vendors.paloalto import PanOSParser
from app.vendors.registry import detect_vendor

CISCO_SAMPLE = """
version 17.3
hostname Cisco-RTR-01
ip ssh version 1
line vty 0 4
 transport input telnet ssh
interface GigabitEthernet0/0
 description Connection to Internet WAN
 ip address 203.0.113.5 255.255.255.0
snmp-server community public RO
access-list 101 permit ip any any
"""

FORTINET_SAMPLE = """
config system global
    set hostname "FortiGate-01"
    set ssh-version 2
end
config system interface
    edit "wan1"
        set ip 198.51.100.10 255.255.255.0
        set allowaccess ping https ssh http telnet
        set role wan
    next
end
"""

PALOALTO_SAMPLE = """
set deviceconfig system hostname PA-FW-01
set network profiles interface-management-profile mgmt-profile ssh yes
set network profiles interface-management-profile mgmt-profile telnet no
set rulebase security rules ALLOW-ALL from any to any source any destination any application any service any action allow
"""


def test_cisco_detection_confidence_high_for_cisco_sample():
    parser = CiscoIOSParser()
    assert parser.detect_confidence(CISCO_SAMPLE) > 0.5


def test_fortinet_detection_confidence_high_for_fortinet_sample():
    parser = FortiOSParser()
    assert parser.detect_confidence(FORTINET_SAMPLE) > 0.5


def test_paloalto_detection_confidence_high_for_paloalto_sample():
    parser = PanOSParser()
    assert parser.detect_confidence(PALOALTO_SAMPLE) > 0.5


def test_registry_detects_cisco_as_top_candidate():
    result = detect_vendor(CISCO_SAMPLE)
    assert result.vendor == "Cisco"
    assert result.implemented is True


def test_registry_metadata_hint_is_authoritative():
    result = detect_vendor("this text is ambiguous", metadata_hint="Fortinet")
    assert result.vendor == "Fortinet"
    assert result.confidence == 1.0
    assert result.method == "metadata"


def test_cisco_parser_extracts_expected_ir_fields():
    ir = CiscoIOSParser().parse(CISCO_SAMPLE)
    assert ir.device.vendor == "Cisco"
    assert ir.management.ssh_version == 1
    assert ir.management.telnet_enabled is True
    assert ir.snmp.community_strings_present is True
    assert any(r.is_unrestricted for r in ir.access_control.rules)
    assert ir.internet_exposed is True


def test_fortinet_parser_extracts_expected_ir_fields():
    ir = FortiOSParser().parse(FORTINET_SAMPLE)
    assert ir.device.vendor == "Fortinet"
    assert ir.management.ssh_version == 2
    assert ir.management.telnet_enabled is True  # wan1 allowaccess includes telnet
    assert ir.internet_exposed is True


def test_paloalto_parser_extracts_expected_ir_fields():
    ir = PanOSParser().parse(PALOALTO_SAMPLE)
    assert ir.device.vendor == "PaloAlto"
    assert ir.management.ssh_enabled is True
    assert ir.management.telnet_enabled is False
    assert any(r.is_unrestricted for r in ir.access_control.rules)


# A Juniper-shaped config that deliberately avoids every literal substring in
# Juniper's SIGNATURE_HINTS ("set system host-name", "set interfaces",
# "junos") -- the old pure-signature scorer would give this exactly 0.0. It
# closely echoes two of Juniper's REFERENCE_SNIPPETS (app/vendors/registry.py)
# almost verbatim, though, so the embedding-similarity signal should still
# recognize it as Juniper.
JUNIPER_SAMPLE_WITHOUT_SIGNATURE_HITS = """
set security zones security-zone trust interfaces ge-0/0/0.0
set firewall family inet filter protect-re term allow-ssh from protocol tcp
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
"""


def test_hybrid_detection_recognizes_semantically_similar_config_without_signature_hits():
    from app.vendors.registry import _PARSERS  # white-box: confirm the premise, not just the outcome

    juniper_parser = _PARSERS["Juniper"]
    assert juniper_parser.detect_confidence(JUNIPER_SAMPLE_WITHOUT_SIGNATURE_HITS) == 0.0

    result = detect_vendor(JUNIPER_SAMPLE_WITHOUT_SIGNATURE_HITS)
    assert result.vendor == "Juniper"
    assert result.embedding_score > 0.5
    assert result.confidence > 0.5
    assert result.method == "embedding"
