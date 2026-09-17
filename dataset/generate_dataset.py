#!/usr/bin/env python3
"""
generate_dataset.py

Synthetic dataset generator for training a small LLM (via QLoRA fine-tuning)
to understand network/security configuration semantics: parsing vendor CLI
syntax, classifying findings by risk, proposing remediations, explaining why
a pattern matters, translating between vendors, and handling unknown/edge
inputs gracefully.

IMPORTANT — provenance (two layers, see real_references.py for full detail):

1. The vendor CLI rule-parsing/classification task itself (5-tuple ACL rules,
   risk labels, vendor-to-vendor translation) is SYNTHETIC by construction —
   there is no "real dataset" of labeled ACL rules to source, so this part is
   generated from well-known public CLI syntax (Cisco IOS, Juniper JunOS,
   PAN-OS, FortiOS, Linux iptables/nftables/ufw/sshd/sysctl, Windows netsh)
   plus general security engineering knowledge (e.g. "permit ip any any" is
   overly broad; Telnet/FTP are cleartext; default SNMP community strings are
   weak).

2. The `security_explanation` category (and the "control" field attached to
   `finding_classification` hardening-item rows) is grounded in REAL, sourced
   reference material fetched live and stored in real_references.py:
     - Verbatim control text from NIST SP 800-53 Rev 5 (public domain, US
       federal government work — from NIST/CSRC's own OSCAL catalog).
     - Real DISA STIG rule IDs/titles/fixes for Cisco IOS, Palo Alto, Juniper,
       RHEL 9, and Windows Server 2022 (DISA STIGs are public domain / DoD
       unlimited-distribution works).
     - The 35 real control IDs/titles from NCIIPC's own publicly published
       Guidelines for Protection of CII V2.0 (nciipc.gov.in).
     - The 18 real CIS Controls v8.1 top-level names, and the 93 real
       ISO/IEC 27001:2022 Annex A control IDs/titles — labels/outline only,
       NOT the licensed/paywalled full benchmark or standard text (see
       real_references.py and the dataset README for why those two are
       intentionally left at the label level).

Usage:
    python3 generate_dataset.py --count 5000 --seed 42 --out-prefix security_config_dataset
"""

import argparse
import ipaddress
import json
import random

import real_references as RR

# --------------------------------------------------------------------------
# Reference data pools
# --------------------------------------------------------------------------

VENDORS = [
    "cisco_ios",
    "juniper_junos",
    "palo_alto",
    "fortinet",
    "linux_iptables",
    "linux_nftables",
    "linux_ufw",
    "windows_netsh",
]

VENDOR_LABEL = {
    "cisco_ios": "Cisco IOS / IOS-XE",
    "juniper_junos": "Juniper JunOS",
    "palo_alto": "Palo Alto PAN-OS",
    "fortinet": "Fortinet FortiOS",
    "linux_iptables": "Linux iptables",
    "linux_nftables": "Linux nftables",
    "linux_ufw": "Linux ufw",
    "windows_netsh": "Windows (netsh advfirewall)",
}

# service name -> (port, L4 protocol, tag)
SERVICES = {
    "ssh":       (22,   "tcp", "remote_access_encrypted"),
    "telnet":    (23,   "tcp", "remote_access_cleartext"),
    "http":      (80,   "tcp", "web_cleartext"),
    "https":     (443,  "tcp", "web_encrypted"),
    "ftp":       (21,   "tcp", "file_transfer_cleartext"),
    "ftps":      (990,  "tcp", "file_transfer_encrypted"),
    "smtp":      (25,   "tcp", "email"),
    "dns":       (53,   "udp", "infrastructure"),
    "snmp":      (161,  "udp", "monitoring_weak_auth_risk"),
    "snmptrap":  (162,  "udp", "monitoring"),
    "ntp":       (123,  "udp", "infrastructure"),
    "rdp":       (3389, "tcp", "remote_access_high_value"),
    "smb":       (445,  "tcp", "file_share_high_value"),
    "mysql":     (3306, "tcp", "database"),
    "postgres":  (5432, "tcp", "database"),
    "mssql":     (1433, "tcp", "database"),
    "ldap":      (389,  "tcp", "directory_cleartext"),
    "ldaps":     (636,  "tcp", "directory_encrypted"),
    "syslog":    (514,  "udp", "logging_cleartext"),
    "tftp":      (69,   "udp", "file_transfer_no_auth"),
    "vnc":       (5900, "tcp", "remote_access_weak_auth_risk"),
    "sip":       (5060, "udp", "voice"),
    "modbus":    (502,  "tcp", "ics_scada_no_auth_by_design"),
    "dnp3":      (20000,"tcp", "ics_scada_no_auth_by_design"),
}

NETWORKS_ANY = ["any"]
NETWORKS_SPECIFIC = [
    "10.10.0.0/16", "10.20.30.0/24", "192.168.1.0/24", "192.168.50.0/24",
    "172.16.5.0/24", "172.20.0.0/16", "203.0.113.0/24", "198.51.100.0/24",
    "10.0.0.5/32", "10.0.0.100/32", "192.168.1.10/32", "172.16.5.20/32",
]

CRITICAL_INFRA_CONTEXTS = [
    "a power-grid SCADA control network",
    "a core banking data center segment",
    "a telecom operator's core network",
    "a water treatment ICS environment",
    "a government critical-infrastructure WAN edge",
    "a payment-processing DMZ",
    "an airport operational technology (OT) network",
    "a hospital clinical network segment",
]

RNG = random.Random()


# --------------------------------------------------------------------------
# Address / rendering helpers
# --------------------------------------------------------------------------

def pick_addr(allow_any_weight=0.35):
    if RNG.random() < allow_any_weight:
        return "any"
    return RNG.choice(NETWORKS_SPECIFIC)


def cisco_addr(addr):
    if addr == "any":
        return "any"
    net = ipaddress.ip_network(addr, strict=False)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    wildcard = ipaddress.IPv4Address(int(net.hostmask))
    return f"{net.network_address} {wildcard}"


def fortinet_addr(addr):
    return "all" if addr == "any" else addr


def iptables_addr_flag(addr, flag):
    if addr == "any":
        return ""
    return f" {flag} {addr}"


def render_rule(vendor, action, src, dst, svc_name, port, proto, rule_id=None):
    """Render a 5-tuple rule into a vendor's native CLI syntax."""
    rule_id = rule_id or RNG.randint(100, 199)
    allow = action == "ALLOW"

    if vendor == "cisco_ios":
        verb = "permit" if allow else "deny"
        return (f"access-list {rule_id} {verb} {proto} {cisco_addr(src)} "
                f"{cisco_addr(dst)} eq {port}")

    if vendor == "juniper_junos":
        verb = "permit" if allow else "deny"
        return (
            f"set security policies from-zone TRUST to-zone UNTRUST policy RULE{rule_id} "
            f"match source-address {src} destination-address {dst} application {svc_name}\n"
            f"set security policies from-zone TRUST to-zone UNTRUST policy RULE{rule_id} then {verb}"
        )

    if vendor == "palo_alto":
        verb = "allow" if allow else "deny"
        return (
            f"set rulebase security rules RULE{rule_id} from any to any "
            f"source {src} destination {dst} application {svc_name} "
            f"service application-default action {verb}"
        )

    if vendor == "fortinet":
        verb = "accept" if allow else "deny"
        return (
            "config firewall policy\n"
            f"    edit {rule_id}\n"
            f"        set srcintf \"any\"\n"
            f"        set dstintf \"any\"\n"
            f"        set srcaddr \"{fortinet_addr(src)}\"\n"
            f"        set dstaddr \"{fortinet_addr(dst)}\"\n"
            f"        set service \"{svc_name.upper()}\"\n"
            f"        set action {verb}\n"
            f"        set schedule \"always\"\n"
            "    next\n"
            "end"
        )

    if vendor == "linux_iptables":
        verb = "ACCEPT" if allow else "DROP"
        return (f"iptables -A INPUT{iptables_addr_flag(src, '-s')}"
                f"{iptables_addr_flag(dst, '-d')} -p {proto} --dport {port} -j {verb}")

    if vendor == "linux_nftables":
        verb = "accept" if allow else "drop"
        parts = ["add rule inet filter input"]
        if src != "any":
            parts.append(f"ip saddr {src}")
        if dst != "any":
            parts.append(f"ip daddr {dst}")
        parts.append(f"{proto} dport {port} {verb}")
        return " ".join(parts)

    if vendor == "linux_ufw":
        verb = "allow" if allow else "deny"
        return f"ufw {verb} from {src} to {dst} port {port} proto {proto}"

    if vendor == "windows_netsh":
        verb = "allow" if allow else "block"
        return (f'netsh advfirewall firewall add rule name="RULE{rule_id}_{svc_name.upper()}" '
                f"dir=in action={verb} remoteip={src} localip={dst} "
                f"protocol={proto} localport={port}")

    raise ValueError(vendor)


# --------------------------------------------------------------------------
# Risk assessment logic (shared "ground truth" the model should learn)
# --------------------------------------------------------------------------

HIGH_RISK_TAGS = {
    "remote_access_cleartext", "file_transfer_cleartext", "monitoring_weak_auth_risk",
    "remote_access_high_value", "file_share_high_value", "directory_cleartext",
    "file_transfer_no_auth", "remote_access_weak_auth_risk", "ics_scada_no_auth_by_design",
}


def assess_rule(action, src, dst, svc_name, tag):
    if action == "DENY":
        return "NONE", "Explicit deny rule; reduces attack surface and requires no remediation."

    if src == "any" and dst == "any":
        return ("CRITICAL",
                "Unrestricted any-to-any rule permits all traffic regardless of source, "
                "destination, or protocol, violating least-privilege / default-deny network design.")

    if src == "any" and tag in HIGH_RISK_TAGS:
        return ("HIGH",
                f"Rule exposes {svc_name} to any source. This service is commonly targeted "
                "because it is either unauthenticated, cleartext, or a high-value management/"
                "data protocol, and should be restricted to specific trusted hosts.")

    if src == "any":
        return ("MEDIUM",
                f"Rule permits {svc_name} from any source to a specific destination. "
                "Source should be scoped to known/trusted networks to reduce exposure.")

    if dst == "any":
        return ("MEDIUM",
                f"Rule permits {svc_name} from a specific source to any destination, which is "
                "broader than typically required and should be scoped to intended destinations.")

    return ("LOW",
            f"Rule permits {svc_name} between specifically scoped source and destination "
            "networks, consistent with least-privilege access control.")


def remediation_for(action, src, dst, svc_name, port, proto, risk):
    if action == "DENY" or risk in ("NONE", "LOW"):
        return "No remediation required; rule already follows least-privilege scoping."
    fixes = []
    if src == "any":
        fixes.append(f"restrict the source to the specific administrative or application "
                      f"network(s) that require {svc_name} access (avoid 'any')")
    if dst == "any":
        fixes.append("restrict the destination to the specific host(s) or subnet that must "
                      "receive this traffic")
    if svc_name in ("telnet", "ftp", "tftp", "http", "ldap", "syslog"):
        fixes.append(f"replace {svc_name} with its encrypted equivalent where available "
                      "(e.g. SSH instead of Telnet, SFTP/FTPS instead of FTP, HTTPS instead of HTTP, "
                      "LDAPS instead of LDAP, syslog over TLS instead of plaintext syslog)")
    if svc_name == "snmp":
        fixes.append("move from SNMPv1/v2c community strings to SNMPv3 with authentication "
                      "and privacy (authPriv)")
    if not fixes:
        fixes.append("apply an explicit allow-list and add logging for auditability")
    return "Recommended remediation: " + "; ".join(fixes) + "."


# --------------------------------------------------------------------------
# OS / device hardening directive templates (beyond 5-tuple ACL rules)
# --------------------------------------------------------------------------

def hardening_items():
    items = []

    for val in ["yes", "no", "prohibit-password"]:
        compliant = val != "yes"
        items.append(dict(
            vendor="linux_sshd", snippet=f"PermitRootLogin {val}",
            compliant=compliant, service="sshd", control="ac-3",
            reason=("Direct root login over SSH is disabled or restricted to key-based auth."
                     if compliant else
                     "Direct root login over SSH is permitted with a password, allowing an "
                     "attacker who guesses/brute-forces the root password full system access."),
            fix="Set 'PermitRootLogin no' (or 'prohibit-password' if key-based root access is "
                "explicitly required) in sshd_config and restart sshd."))

    for val in ["yes", "no"]:
        compliant = val == "no"
        items.append(dict(
            vendor="linux_sshd", snippet=f"PasswordAuthentication {val}",
            compliant=compliant, service="sshd", control="ia-5",
            reason=("Password authentication is disabled; only stronger key-based authentication "
                     "is accepted." if compliant else
                     "Password authentication is enabled over SSH, exposing the service to "
                     "credential-stuffing and brute-force attacks."),
            fix="Set 'PasswordAuthentication no' and enforce SSH key-based authentication instead."))

    for val in [1, 2]:
        compliant = val == 2
        items.append(dict(
            vendor="linux_sshd", snippet=f"Protocol {val}",
            compliant=compliant, service="sshd", control="sc-13",
            reason=("SSH Protocol 2 is in use, which fixes multiple cryptographic weaknesses "
                     "present in Protocol 1." if compliant else
                     "SSH Protocol 1 is enabled, which has known cryptographic weaknesses "
                     "(e.g. susceptibility to man-in-the-middle attacks) and is deprecated."),
            fix="Remove the 'Protocol 1' directive (or set 'Protocol 2') so only SSHv2 is accepted."))

    for n in [3, 4, 5, 6, 8, 10]:
        compliant = n <= 4
        items.append(dict(
            vendor="linux_sshd", snippet=f"MaxAuthTries {n}",
            compliant=compliant, service="sshd", control="ac-7",
            reason=(f"MaxAuthTries is set to {n}, a tight limit that reduces the window for "
                     "online brute-force attempts." if compliant else
                     f"MaxAuthTries is set to {n}, allowing many authentication attempts per "
                     "connection and increasing brute-force exposure."),
            fix="Lower MaxAuthTries to 4 or fewer and pair with fail2ban / account lockout."))

    for val in [0, 1]:
        compliant = val == 0
        items.append(dict(
            vendor="linux_sysctl", snippet=f"net.ipv4.conf.all.accept_source_route = {val}",
            compliant=compliant, service="kernel_network_stack", control="sc-7",
            reason=("Source-routed packets are rejected, preventing an attacker from specifying "
                     "an arbitrary return path to bypass routing controls." if compliant else
                     "Source-routed packets are accepted, which can allow an attacker to bypass "
                     "network routing/segmentation controls."),
            fix="Set 'net.ipv4.conf.all.accept_source_route = 0' in /etc/sysctl.conf and reload."))

    for val in [0, 1]:
        compliant = val == 1
        items.append(dict(
            vendor="linux_sysctl", snippet=f"net.ipv4.tcp_syncookies = {val}",
            compliant=compliant, service="kernel_network_stack", control="sc-5",
            reason=("SYN cookies are enabled, mitigating SYN-flood denial-of-service attacks."
                     if compliant else
                     "SYN cookies are disabled, leaving the host more vulnerable to SYN-flood "
                     "denial-of-service attacks."),
            fix="Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.conf and reload."))

    for val in [0, 1]:
        compliant = val == 0
        items.append(dict(
            vendor="linux_sysctl", snippet=f"net.ipv4.icmp_echo_ignore_broadcasts = {val}",
            compliant=compliant, service="kernel_network_stack", control="sc-5",
            reason=("Broadcast ICMP echo requests are ignored, preventing use of this host in "
                     "a Smurf-style amplification attack." if compliant else
                     "Broadcast ICMP echo requests are answered, which can allow this host to be "
                     "abused in a Smurf-style amplification/DoS attack."),
            fix="Set 'net.ipv4.icmp_echo_ignore_broadcasts = 1' in /etc/sysctl.conf and reload."))

    for n in [4, 6, 8, 10, 12, 14]:
        compliant = n >= 12
        items.append(dict(
            vendor="linux_pam", snippet=f"password requisite pam_pwquality.so minlen={n}",
            compliant=compliant, service="password_policy", control="ia-5",
            reason=(f"Minimum password length is set to {n} characters, meeting common baseline "
                     "password-strength guidance." if compliant else
                     f"Minimum password length is only {n} characters, below common baseline "
                     "password-strength guidance and easier to brute-force."),
            fix="Set 'minlen=14' (or the org's approved minimum) in pam_pwquality.so."))

    for community, ver in [("public", "1"), ("private", "2c"), ("public", "2c"),
                            ("Str0ng-Rand0m-Str1ng!", "3")]:
        compliant = ver == "3" and community not in ("public", "private")
        items.append(dict(
            vendor="cisco_ios", snippet=f'snmp-server community {community} RO',
            compliant=compliant, service="snmp", control="ia-3",
            reason=(f"SNMPv{ver} with a non-default community string / authPriv is configured, "
                     "reducing risk of unauthorized device polling or reconfiguration." if compliant
                     else f"SNMP is configured with the well-known default community string "
                     f"'{community}' on SNMPv{ver}, which is unauthenticated/weakly authenticated "
                     "and allows any client that knows (or guesses) the string to read or "
                     "potentially modify device configuration."),
            fix="Migrate to SNMPv3 with authPriv, remove default community strings, and restrict "
                "SNMP access to a management-only ACL."))

    for val in ["never", "0", "5", "10", "15"]:
        compliant = val not in ("never", "0")
        items.append(dict(
            vendor="cisco_ios", snippet=f"line vty 0 4\n exec-timeout {val if val not in ('never',) else '0 0'}",
            compliant=compliant, service="vty_session", control="sc-10",
            reason=("An idle VTY (Telnet/SSH management) session timeout is configured, closing "
                     "abandoned administrative sessions automatically." if compliant else
                     "VTY sessions never time out, so an unattended, unlocked administrative "
                     "session stays open indefinitely and could be hijacked."),
            fix="Configure 'exec-timeout 10 0' (or your org's approved value) under line vty."))

    for val in ["password", "secret"]:
        compliant = val == "secret"
        items.append(dict(
            vendor="cisco_ios", snippet=f"enable {val} cisco123",
            compliant=compliant, service="privileged_exec", control="ia-5",
            reason=("'enable secret' stores the privileged-exec password as a salted hash."
                     if compliant else
                     "'enable password' stores the privileged-exec password in a weakly "
                     "reversible/cleartext-equivalent form in the running configuration."),
            fix="Replace 'enable password' with 'enable secret' using a strong, unique passphrase."))

    for enabled in [True, False]:
        items.append(dict(
            vendor="cisco_ios", snippet=("transport input telnet\n" if enabled else
                                          "transport input ssh\n"),
            compliant=not enabled, service="vty_transport", control="ma-4",
            reason=("Telnet is enabled for remote administration, transmitting credentials and "
                     "session data in cleartext." if enabled else
                     "Only SSH is permitted for remote administration, encrypting the "
                     "management session."),
            fix="Set 'transport input ssh' under line vty and remove Telnet access."))

    for enabled in [True, False]:
        items.append(dict(
            vendor="windows_powershell",
            snippet=(f"Set-SmbServerConfiguration -EnableSMB1Protocol ${'true' if enabled else 'false'}"),
            compliant=not enabled, service="smb", control="cm-7",
            reason=("SMBv1 is disabled, removing a legacy protocol with known critical "
                     "vulnerabilities (e.g. exploited by WannaCry/EternalBlue-class malware)."
                     if not enabled else
                     "SMBv1 remains enabled, a legacy protocol with known critical "
                     "vulnerabilities that should be disabled on modern systems."),
            fix="Run 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' and confirm no "
                "legacy clients depend on SMBv1."))

    for n in [0, 3, 5, 10]:
        compliant = 0 < n <= 5
        items.append(dict(
            vendor="windows_secedit", snippet=f"LockoutBadCount = {n}",
            compliant=compliant, service="account_lockout", control="ac-7",
            reason=(f"Account lockout threshold is {n} (disabled), so an attacker can attempt "
                     "unlimited password guesses without triggering a lockout." if n == 0 else
                     (f"Account lockout threshold of {n} balances usability with brute-force "
                      "resistance." if compliant else
                      f"Account lockout threshold of {n} is higher than typical guidance, "
                      "allowing more guesses before lockout.")),
            fix="Set the account lockout threshold to 5 or fewer invalid attempts."))

    for enabled in [True, False]:
        items.append(dict(
            vendor="linux_auditd",
            snippet=("auditd.service: enabled, rules loaded from /etc/audit/rules.d/"
                     if enabled else "auditd.service: disabled"),
            compliant=enabled, service="audit_logging", control="au-12",
            reason=("The Linux audit daemon is enabled and loading rules, providing tamper-evident "
                     "logging of security-relevant events." if enabled else
                     "The Linux audit daemon is disabled, so security-relevant events "
                     "(privileged commands, file access, auth attempts) are not being recorded."),
            fix="Enable and start auditd, and load a baseline rule set (e.g. from a CIS/STIG "
                "audit rules template)."))

    for enabled in [True, False]:
        items.append(dict(
            vendor="fortinet", snippet=f"config system ntp\n    set ntpsync enable\n    set authentication {'enable' if enabled else 'disable'}\nend",
            compliant=enabled, service="ntp", control="ia-3",
            reason=("NTP authentication is enabled, preventing an on-path attacker from spoofing "
                     "time-sync responses and skewing the device clock (which can undermine "
                     "log correlation and certificate validation)." if enabled else
                     "NTP authentication is disabled, allowing an on-path attacker to spoof "
                     "time-sync responses and skew the device clock."),
            fix="Enable NTP authentication (e.g. symmetric key or autokey) on all NTP clients "
                "and servers."))

    for enabled in [True, False]:
        items.append(dict(
            vendor="palo_alto",
            snippet=f"set deviceconfig system update-server disable-certificate-validation {'yes' if enabled else 'no'}",
            compliant=not enabled, service="tls_validation", control="sc-17",
            reason=("Certificate validation for the update server is enforced, preventing a "
                     "man-in-the-middle from serving malicious updates." if not enabled else
                     "Certificate validation for the update server is disabled, allowing a "
                     "man-in-the-middle attacker to potentially serve malicious software updates."),
            fix="Remove the certificate-validation bypass so the firewall verifies the update "
                "server's TLS certificate."))

    return items


HARDENING_ITEMS = hardening_items()


# --------------------------------------------------------------------------
# Category generators — each returns (instruction, input, output)
# --------------------------------------------------------------------------

def gen_finding_classification():
    if RNG.random() < 0.55:
        vendor = RNG.choice(VENDORS)
        action = RNG.choice(["ALLOW", "ALLOW", "ALLOW", "DENY"])  # allow-weighted
        src = pick_addr(0.45)
        dst = pick_addr(0.25)
        svc_name, (port, proto, tag) = RNG.choice(list(SERVICES.items()))
        config = render_rule(vendor, action, src, dst, svc_name, port, proto)
        risk, reason = assess_rule(action, src, dst, svc_name, tag)
        remediation = remediation_for(action, src, dst, svc_name, port, proto, risk)
        instruction = "Analyze this network configuration."
        output = {
            "source": src.upper() if src == "any" else src,
            "destination": dst.upper() if dst == "any" else dst,
            "protocol": proto.upper(),
            "service": svc_name,
            "action": action,
            "risk": risk,
            "reason": reason,
            "remediation": remediation,
        }
        return instruction, config, output, vendor
    else:
        item = RNG.choice(HARDENING_ITEMS)
        instruction = f"Analyze this {VENDOR_LABEL.get(item['vendor'], item['vendor'])} configuration setting."
        control_id = item.get("control")
        output = {
            "service": item["service"],
            "compliant": item["compliant"],
            "risk": "NONE" if item["compliant"] else RNG.choice(["MEDIUM", "HIGH"]),
            "reason": item["reason"],
            "remediation": "No remediation required." if item["compliant"] else item["fix"],
            "nist_800_53_control": (f"{control_id.upper()} ({RR.NIST_CONTROLS[control_id]['title']})"
                                     if control_id else None),
        }
        return instruction, item["snippet"], output, item["vendor"]


def gen_vendor_normalization():
    vendor = RNG.choice(VENDORS)
    action = RNG.choice(["ALLOW", "DENY"])
    src = pick_addr(0.4)
    dst = pick_addr(0.3)
    svc_name, (port, proto, tag) = RNG.choice(list(SERVICES.items()))
    config = render_rule(vendor, action, src, dst, svc_name, port, proto)
    instruction = ("Normalize this vendor-specific network configuration into a vendor-neutral "
                   "JSON representation (do not assess risk, only extract fields).")
    output = {
        "vendor": VENDOR_LABEL[vendor],
        "action": action,
        "source": src,
        "destination": dst,
        "protocol": proto.upper(),
        "service": svc_name,
        "port": port,
    }
    return instruction, config, output, vendor


def gen_remediation():
    vendor = RNG.choice(VENDORS)
    src = pick_addr(0.6)
    dst = pick_addr(0.25)
    svc_name, (port, proto, tag) = RNG.choice(list(SERVICES.items()))
    action = "ALLOW"
    config = render_rule(vendor, action, src, dst, svc_name, port, proto)
    risk, reason = assess_rule(action, src, dst, svc_name, tag)
    remediation = remediation_for(action, src, dst, svc_name, port, proto, risk)

    finding = {
        "source": src, "destination": dst, "protocol": proto.upper(),
        "service": svc_name, "action": action, "risk": risk, "reason": reason,
    }
    instruction = "Given this security finding, provide a remediation plan."
    tightened_src = "10.10.0.0/24" if src == "any" else src
    tightened_dst = "10.0.0.5/32" if dst == "any" else dst
    fixed_config = render_rule(vendor, action, tightened_src, tightened_dst, svc_name, port, proto)
    output = {
        "remediation": remediation,
        "example_fixed_config": fixed_config,
        "priority": "P1" if risk == "CRITICAL" else ("P2" if risk == "HIGH" else "P3"),
    }
    return instruction, json.dumps(finding), output, vendor


def _trim(stmt, max_chars=380):
    """Trim a real NIST control statement at a clause boundary, never mid-word."""
    if len(stmt) <= max_chars:
        return stmt
    cut = stmt.rfind("; ", 0, max_chars)
    if cut == -1:
        cut = stmt.rfind(". ", 0, max_chars)
    if cut == -1:
        cut = max_chars
    return stmt[:cut].rstrip(" ;.") + "..."


def _nist_citation(control_id):
    c = RR.NIST_CONTROLS.get(control_id)
    if not c:
        return ""
    return (f"NIST SP 800-53 Rev 5 {control_id.upper()} ({c['title']}) states: "
            f"\"{_trim(c['statement'])}\"")


def _maybe_cross_refs():
    """Randomly append 0-2 real cross-references (NCIIPC / ISO / CIS) as extra sentences."""
    extras = []
    if RNG.random() < 0.5:
        cid, family, title = RNG.choice(
            [c for c in RR.NCIIPC_CONTROLS if c[0] in RR.NCIIPC_RELEVANT])
        extras.append(f"Under NCIIPC's Guidelines for Protection of CII (V2.0), this falls "
                       f"under {cid} – {title} ({family}).")
    if RNG.random() < 0.4:
        iso_id, iso_title = RNG.choice(
            [c for c in RR.ISO_27001_ANNEX_A if c[0] in RR.ISO_RELEVANT])
        extras.append(f"It also maps to ISO/IEC 27001:2022 Annex A {iso_id} ({iso_title}).")
    if RNG.random() < 0.35:
        num, title = RNG.choice(RR.CIS_CONTROLS_V8)
        extras.append(f"At a program level this sits under CIS Controls v8.1 Control {num} "
                       f"({title}).")
    return " ".join(extras)


def gen_security_explanation():
    context = RNG.choice(CRITICAL_INFRA_CONTEXTS)
    style = RNG.random()

    if style < 0.55:
        # Real DISA STIG rule, real mapped NIST 800-53 control text quoted verbatim.
        rule = RNG.choice(RR.REAL_STIG_RULES)
        instruction = (f"Why does the configuration below matter for security hardening in "
                        f"{context}? Cite the relevant STIG rule and control family.")
        output = (f"{rule['stig']} {rule['vuln_id']} (\"{rule['title']}\", severity "
                   f"{rule['severity']}) applies here. {rule['fix']} "
                   f"{_nist_citation(rule['control'])}. In {context}, unaddressed findings "
                   f"like this widen the attack surface available to an adversary who gains a "
                   f"foothold. {_maybe_cross_refs()}").strip()
        return instruction, rule["example"], output, rule["vendor"]

    elif style < 0.8:
        # Real NIST 800-53 control quoted directly, paired with a representative ACL rule.
        control_id = RNG.choice(["ac-4", "ac-3", "ac-17", "cm-7", "sc-7", "sc-5", "sc-10",
                                  "ia-5", "ia-2", "au-2", "ac-6", "ac-7"])
        vendor = RNG.choice(VENDORS)
        src = "any"
        dst = pick_addr(0.3)
        svc_name, (port, proto, tag) = RNG.choice(list(SERVICES.items()))
        config = render_rule(vendor, "ALLOW", src, dst, svc_name, port, proto)
        risk, reason = assess_rule("ALLOW", src, dst, svc_name, tag)
        instruction = (f"Explain, in plain language, why this configuration is a concern in "
                        f"{context}, and cite the relevant NIST 800-53 control.")
        output = (f"{reason} {_nist_citation(control_id)} In {context}, an over-broad rule "
                   f"widens the blast radius if a single host is compromised. "
                   f"{_maybe_cross_refs()}").strip()
        return instruction, config, output, vendor

    else:
        # NCIIPC-framed: real hardening item + real NCIIPC control + real NIST cross-cite.
        item = RNG.choice(HARDENING_ITEMS)
        ncc = RNG.choice([c for c in RR.NCIIPC_CONTROLS if c[0] in RR.NCIIPC_RELEVANT])
        cid, family, title = ncc
        instruction = (f"Why does the setting below matter for security hardening in "
                        f"{context}? Reference NCIIPC's CII guidelines and the matching "
                        f"NIST control.")
        control_id = item.get("control")
        output = (f"{item['reason']} This falls under NCIIPC's Guidelines for Protection of "
                   f"Critical Information Infrastructure (V2.0), control {cid} – {title} "
                   f"({family}). {_nist_citation(control_id) if control_id else ''} "
                   f"{_maybe_cross_refs()}").strip()
        return instruction, item["snippet"], output, item["vendor"]


def gen_cross_vendor_equivalence():
    vendor_from, vendor_to = RNG.sample(VENDORS, 2)
    action = RNG.choice(["ALLOW", "DENY"])
    src = pick_addr(0.4)
    dst = pick_addr(0.3)
    svc_name, (port, proto, tag) = RNG.choice(list(SERVICES.items()))
    config_from = render_rule(vendor_from, action, src, dst, svc_name, port, proto)
    config_to = render_rule(vendor_to, action, src, dst, svc_name, port, proto)
    instruction = (f"Translate this {VENDOR_LABEL[vendor_from]} configuration into the "
                    f"equivalent {VENDOR_LABEL[vendor_to]} configuration.")
    output = {
        "source_vendor": VENDOR_LABEL[vendor_from],
        "target_vendor": VENDOR_LABEL[vendor_to],
        "equivalent_config": config_to,
        "notes": (f"Both configurations express the same intent: {action} {svc_name} "
                  f"({proto.upper()}/{port}) from {src} to {dst}. Only vendor-specific "
                  "syntax and object-naming conventions differ."),
    }
    return instruction, config_from, output, f"{vendor_from}->{vendor_to}"


MADEUP_KEYWORDS = ["quantumfirewall", "hyperroute", "zerotrustify", "autoshield", "nebula-acl",
                    "flowguardx", "cryptoport", "edgesentinel", "meshpolicy", "deepfilter"]
VENDOR_PREFIXES = ["device", "router", "switch", "firewall"]
DEVICE_WORDS = ["switch", "router", "firewall", "access point", "core switch"]
NOISE_WORDS = ["clicking", "buzzing", "humming", "grinding", "intermittent static"]
DSL_WORDS = ["letmein", "ruleA", "myrule", "temp-allow", "test123", "grandfathered",
             "legacy-rule", "unnamed", "draft-policy", "misc"]
NON_ENGLISH_SNIPPETS = [
    "Сonfig: разрешить весь трафик на порту {port}  # Russian, ambiguous vendor",
    "config: {port} கடவுச்சொல் இல்லாமல் அனுமதி  # Tamil fragment, ambiguous vendor",
    "config : autoriser tout le trafic sur le port {port}  # French, vendor unspecified",
    "配置：允许端口 {port} 的所有流量  # Chinese, ambiguous vendor",
    "config: पोर्ट {port} पर सभी ट्रैफ़िक की अनुमति दें  # Hindi fragment, ambiguous vendor",
    "설정: 포트 {port}에서 모든 트래픽 허용  # Korean, ambiguous vendor",
]


def _unknown_variants():
    svc_name, (port, proto, _tag) = RNG.choice(list(SERVICES.items()))
    kind = RNG.choice([
        "mid_sentence_cutoff", "empty", "question", "bad_keyword", "sql_like",
        "made_up_dsl", "xml_missing", "hardware_complaint", "bad_target",
        "output_not_config", "non_english", "binary_placeholder",
    ])

    if kind == "mid_sentence_cutoff":
        rule_id = RNG.randint(100, 999)
        octet = RNG.randint(1, 254)
        letter = RNG.choice("ABCDEF")
        return (f"access-list {rule_id} permit {proto} any host 10.0.0.{octet}  "
                f"<-- line continues on next page, see appendix {letter}")
    if kind == "empty":
        return RNG.choice(["", " ", "\t", "\n\n", "   \n   "])
    if kind == "question":
        vendor_word = RNG.choice(list(VENDOR_LABEL.values()))
        return f"What port does {svc_name} normally use on {vendor_word}?"
    if kind == "bad_keyword":
        prefix = RNG.choice(VENDOR_PREFIXES)
        madeup = RNG.choice(MADEUP_KEYWORDS)
        return f"{prefix}(config)# ??? unrecognized keyword '{madeup}' at '^'"
    if kind == "sql_like":
        action = RNG.choice(["allow", "deny"])
        rule_id = RNG.randint(1, 999)
        return f"UPDATE firewall_rules SET action='{action}' WHERE id={rule_id}; COMMIT;"
    if kind == "made_up_dsl":
        word = RNG.choice(DSL_WORDS)
        a = pick_addr(0.5)
        b = pick_addr(0.5)
        return f"policy {{ rule '{word}' {{ from {a} to {b} port {port} }} }}  # made-up DSL, not a real vendor syntax"
    if kind == "xml_missing":
        src = pick_addr(0.5)
        return f'<config><rule action="???" src="{src}" dst="??" service="{svc_name}"/></config>  <!-- fields missing -->'
    if kind == "hardware_complaint":
        device = RNG.choice(DEVICE_WORDS)
        noise = RNG.choice(NOISE_WORDS)
        return f"the {device} was making a {noise} noise near port {port}, then it went down, please advise"
    if kind == "bad_target":
        return f"iptables -A INPUT -p {proto} --dport {port} -j THISISNOTAVALIDTARGET"
    if kind == "output_not_config":
        return f"router# show {svc_name} status   (command output, not a configuration line)"
    if kind == "non_english":
        return RNG.choice(NON_ENGLISH_SNIPPETS).format(port=port)
    # binary_placeholder
    rule_id = RNG.randint(1, 9999)
    return f"firewall-rule-{rule_id}.cfg (binary file, cannot display as text)"


def gen_unknown_syntax():
    snippet = _unknown_variants()
    instruction = "Analyze this configuration snippet."
    output = {
        "recognized": False,
        "reason": "Input does not match a known, complete vendor configuration syntax "
                  "(Cisco IOS, JunOS, PAN-OS, FortiOS, iptables/nftables/ufw, or Windows netsh), "
                  "or is empty/truncated/ambiguous.",
        "suggestion": "Provide the full configuration line(s) in a supported vendor syntax, or "
                      "specify the vendor and platform explicitly so the rule can be parsed.",
    }
    return instruction, snippet, output, "unknown"


def gen_edge_case():
    kind = RNG.choice(["object_group", "no_explicit_action", "ipv6", "fqdn", "commented_out",
                        "log_only", "partial_match"])
    svc_name, (port, proto, tag) = RNG.choice(list(SERVICES.items()))
    vendor = {  # actual vendor of the syntax used in each branch below
        "object_group": "cisco_ios",
        "no_explicit_action": "juniper_junos",
        "ipv6": "cisco_ios",
        "fqdn": "palo_alto",
        "commented_out": None,  # set per comment_style below
        "log_only": "cisco_ios",
        "partial_match": "cisco_ios",
    }[kind]

    if kind == "object_group":
        rule_id = RNG.randint(100, 999)
        group_name = RNG.choice(["TRUSTED_HOSTS", "ADMIN_HOSTS", "MGMT_SUBNETS", "PARTNER_NET",
                                  "BRANCH_OFFICES", "VENDOR_SUPPORT"])
        config = f"access-list {rule_id} permit {proto} object-group {group_name} any eq {port}"
        output = {
            "recognized_partially": True,
            "risk": "INDETERMINATE",
            "reason": (f"Rule references an object-group ('{group_name}') whose members are not "
                       "defined in the provided input; source scope — and therefore risk — "
                       "cannot be determined without resolving group membership."),
            "remediation": "Provide the object-group definition (expanded member list) before "
                            "classifying this rule.",
        }
    elif kind == "no_explicit_action":
        rule_id = RNG.randint(1, 999)
        config = (f"set security policies from-zone TRUST to-zone UNTRUST policy RULE{rule_id} "
                  f"match source-address any destination-address any application {svc_name}")
        output = {
            "recognized_partially": True,
            "risk": "INDETERMINATE",
            "reason": ("The match criteria are defined but no explicit 'then permit' or "
                       "'then deny' action is present in this snippet, so the resulting "
                       "action (and therefore risk) cannot be confirmed."),
            "remediation": "Include the 'then permit/deny' action line for a complete "
                            "classification.",
        }
    elif kind == "ipv6":
        addr = RNG.choice(["2001:db8::/32", "::/0", "fe80::/10"])
        config = f"ipv6 access-list V6-ACL\n permit {proto} {addr} any eq {port}"
        risk = "CRITICAL" if addr == "::/0" else "MEDIUM"
        output = {
            "recognized_partially": True,
            "protocol_family": "IPv6",
            "risk": risk,
            "reason": (f"IPv6 rule permitting {svc_name} from {addr}. "
                       + ("'::/0' is the IPv6 equivalent of 'any', so this is as broad as an "
                          "any-to-any IPv4 rule." if addr == "::/0" else
                          "Scope is broader than a single host/subnet and should be reviewed "
                          "against intended IPv6 addressing.")),
            "remediation": "Apply the same least-privilege scoping used for IPv4 rules to the "
                            "IPv6 rule set; do not assume IPv6 is out of scope for hardening.",
        }
    elif kind == "fqdn":
        fqdn = RNG.choice(["partner-api.example.com", "vendor-update.example.net",
                            "*.cloud-provider.example"])
        config = f"set rulebase security rules RULE77 destination {fqdn} application {svc_name} action allow"
        output = {
            "recognized_partially": True,
            "risk": "INDETERMINATE",
            "reason": (f"Destination is expressed as an FQDN ('{fqdn}') rather than an IP/CIDR. "
                       "Risk depends on DNS resolution at enforcement time and whether the FQDN "
                       "uses a wildcard, which cannot be fully assessed from static text alone."),
            "remediation": "Confirm the resolved IP range(s) behind the FQDN and whether a "
                            "wildcard domain is intentionally broad; pin to specific hosts where "
                            "possible.",
        }
    elif kind == "commented_out":
        rule_id = RNG.randint(100, 999)
        comment_style, vendor, raw = RNG.choice([
            ("cisco", "cisco_ios", f"! access-list {rule_id} permit {proto} any any eq {port}  (commented out / inactive)"),
            ("linux", "linux_iptables", f"# iptables -A INPUT -p {proto} --dport {port} -j ACCEPT  (commented out / inactive)"),
            ("paloalto", "palo_alto", f"set rulebase security rules RULE{rule_id} disabled yes  # {svc_name} rule present but disabled"),
            ("fortinet", "fortinet", f"config firewall policy\n    edit {rule_id}\n        set status disable  # {svc_name}\n    next\nend"),
        ])
        config = raw
        output = {
            "recognized_partially": True,
            "risk": "NONE",
            "reason": f"The {svc_name} rule is commented out / disabled and therefore not active "
                      "in the running configuration; it has no current effect on traffic.",
            "remediation": "No action needed while inactive; if this rule is re-enabled, it must "
                            "be re-reviewed since an overly broad version of it could otherwise "
                            "be a CRITICAL any-to-any finding.",
        }
    elif kind == "log_only":
        rule_id = RNG.randint(100, 999)
        config = f"access-list {rule_id} permit {proto} any any eq {port} log"
        risk_val, reason = assess_rule("ALLOW", "any", "any", svc_name, tag)
        output = {
            "recognized_partially": True,
            "risk": risk_val,
            "reason": reason + " The 'log' keyword adds visibility but does not reduce the "
                      "underlying access risk.",
            "remediation": "Logging alone does not remediate an overly broad rule; scope the "
                            "source/destination in addition to keeping logging enabled.",
        }
    else:  # partial_match
        rule_id = RNG.randint(100, 999)
        octet = RNG.randint(0, 254)
        config = f"access-list {rule_id} permit {proto} 10.10.{octet}.0"
        output = {
            "recognized_partially": True,
            "risk": "INDETERMINATE",
            "reason": ("The line is truncated — a wildcard mask (or 'host'/'any' keyword) and "
                       "destination clause are missing, so the actual match scope is unclear."),
            "remediation": "Provide the complete ACL line, including wildcard mask and "
                            "destination, before classifying.",
        }

    instruction = "Analyze this network configuration."
    return instruction, config, output, vendor


CATEGORY_GENERATORS = {
    "finding_classification": (gen_finding_classification, 1300),
    "vendor_normalization": (gen_vendor_normalization, 700),
    "remediation": (gen_remediation, 900),
    "security_explanation": (gen_security_explanation, 700),
    "cross_vendor_equivalence": (gen_cross_vendor_equivalence, 700),
    "unknown_syntax": (gen_unknown_syntax, 350),
    "edge_cases": (gen_edge_case, 350),
}


def build_dataset(total_target):
    scale = total_target / sum(n for _, n in CATEGORY_GENERATORS.values())
    seen = set()
    rows = []
    idx = 1
    for category, (fn, base_n) in CATEGORY_GENERATORS.items():
        target_n = max(1, round(base_n * scale))
        attempts = 0
        produced = 0
        max_attempts = target_n * 40 + 200
        while produced < target_n and attempts < max_attempts:
            attempts += 1
            instruction, inp, output, vendor = fn()
            key = (instruction, inp, json.dumps(output, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "id": f"secconf-{idx:05d}",
                "category": category,
                "vendor": vendor,
                "instruction": instruction,
                "input": inp,
                "output": output,
            })
            idx += 1
            produced += 1
        if produced < target_n:
            print(f"WARNING: only produced {produced}/{target_n} unique rows for {category}")
    RNG.shuffle(rows)
    # renumber ids after shuffle for a clean sequential id, keep original order info out
    for i, row in enumerate(rows, start=1):
        row["id"] = f"secconf-{i:05d}"
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-prefix", type=str, default="security_config_dataset")
    args = parser.parse_args()

    RNG.seed(args.seed)
    rows = build_dataset(args.count)

    jsonl_path = f"{args.out_prefix}.jsonl"
    json_path = f"{args.out_prefix}.json"

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)

    # summary
    from collections import Counter
    cat_counts = Counter(r["category"] for r in rows)
    vendor_counts = Counter(r["vendor"] for r in rows)
    print(f"Total rows: {len(rows)}")
    print("By category:")
    for c, n in cat_counts.most_common():
        print(f"  {c}: {n}")
    print("Top vendors:")
    for v, n in vendor_counts.most_common(15):
        print(f"  {v}: {n}")


if __name__ == "__main__":
    main()
