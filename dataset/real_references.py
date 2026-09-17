"""
real_references.py

Authoritative, real reference data used to ground the dataset's citations in
actual published text/IDs, instead of invented placeholder sentences.

Sources and how each was obtained (all fetched live, September 2026):

- NIST_CONTROLS: verbatim control titles + statement text for a curated set of
  37 controls from NIST SP 800-53 Rev 5, extracted from the official OSCAL
  JSON catalog published by NIST/CSRC on GitHub
  (usnistgov/oscal-content, nist.gov/SP800-53/rev5/json/...). NIST SP 800-53
  is a U.S. federal government work and is in the public domain — verbatim
  use is legally unrestricted. Organization-defined-parameter placeholders
  ("{{ insert: param, ... }}") were replaced with "[organization-defined
  parameters]" for readability; wording is otherwise unmodified.

- REAL_STIG_RULES: a curated subset of real DISA STIG rules (Vulnerability
  ID, title, mapped NIST control, severity, and fix summary) for the
  technologies this dataset's vendor CLI examples cover: Cisco IOS Router NDM
  STIG, Palo Alto Networks NDM STIG, Juniper Router RTR STIG, Red Hat
  Enterprise Linux 9 STIG, and Microsoft Windows Server 2022 STIG. Sourced
  from cyber.trackr.live, a reference site that republishes DISA's published
  STIG content (DISA STIGs are U.S. DoD works and are public domain /
  unlimited distribution per DISA's own release notices). Fix text below is
  paraphrased/condensed from the real fix guidance, not always a verbatim
  quote of the full STIG fix text — treat "fix" as a faithful summary, and
  pull the authoritative full text from the STIG itself (e.g. via
  public.cyber.mil or a STIG viewer) before using this in anything that
  needs to cite exact STIG language.

- NCIIPC_CONTROLS: the 35 named controls (across 5 control families: PC, IC,
  OC, DR, RA) from NCIIPC's own publicly published "Guidelines for Protection
  of Critical Information Infrastructure" (Version 2.0), hosted at
  nciipc.gov.in/documents/NCIIPC_Guidelines_V2.pdf. IDs and titles only —
  not the full guideline text.

- CIS_CONTROLS_V8: the 18 top-level CIS Critical Security Controls v8.1
  names. These top-level names are CIS's own publicly published, freely
  cited framework outline (distinct from the numbered CIS Benchmark
  recommendation text, which is licensed and NOT reproduced here — see the
  dataset README for why).

- ISO_27001_ANNEX_A: the 93 Annex A control IDs and short titles from
  ISO/IEC 27001:2022, which are widely published as a free reference outline
  by training providers and ISO itself. This is the control *list*
  (equivalent to a table of contents), not the paywalled normative
  requirement text of the standard, which was not accessed.
"""

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(_HERE, "nist_controls_clean.json"), encoding="utf-8") as _f:
    NIST_CONTROLS = json.load(_f)  # {"ac-2": {"title": ..., "statement": ...}, ...}


# vendor keys match generate_dataset.py's VENDORS / hardening "vendor" tags
REAL_STIG_RULES = [
    # ---- Cisco IOS Router NDM STIG V3R8 ----
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215662", vendor="cisco_ios",
         example='line vty 0 4\n session-limit 2', title="Limit concurrent management sessions", control="ac-10", severity="Medium",
         fix="Restrict simultaneous administrative connections; configure a session limit "
             "or reduce the number of configured VTY lines."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215667", vendor="cisco_ios",
         example='access-class MGMT-ACL in\n! (applied under line vty 0 4)', title="Enforce management information flow control", control="ac-4", severity="Medium",
         fix="Apply access-class ACLs to VTY lines to restrict management access to approved "
             "source networks."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215668", vendor="cisco_ios",
         example='login block-for 900 attempts 3 within 120', title="Enforce login attempt lockout", control="ac-7", severity="Medium",
         fix="Configure 'login block-for 900 attempts 3 within 120' to block further attempts "
             "for 15 minutes after 3 failed logins within 2 minutes."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215669", vendor="cisco_ios",
         example='banner login ^C\nAuthorized uses only. All activity may be monitored.\n^C', title="Display the required Notice and Consent banner", control="ac-8", severity="Medium",
         fix="Configure 'banner login' with the organization's approved system-use "
             "notification text."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215678", vendor="cisco_ios",
         example='ip http server\nservice finger\ntftp-server flash:/config', title="Disable unnecessary services", control="cm-7", severity="High",
         fix="Remove unsecure protocols and services (Telnet, HTTP, finger, TFTP, bootp, "
             "identd, small-servers) from the running configuration."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215687", vendor="cisco_ios",
         example='enable password cisco123', title="Encrypt stored passwords", control="ia-5", severity="High",
         fix="Enable 'service password-encryption' (and prefer 'enable secret' over "
             "'enable password') so credentials are not stored in cleartext-equivalent form."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215688", vendor="cisco_ios",
         example='line vty 0 4\n exec-timeout 0 0', title="Terminate idle management sessions", control="sc-10", severity="High",
         fix="Set 'exec-timeout 5 0' (5 minutes or less) on console and VTY lines; configure "
             "the HTTP management timeout to 5 minutes or less."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215696", vendor="cisco_ios",
         example='snmp-server community public RO', title="Authenticate SNMP using a FIPS-validated HMAC", control="ia-3", severity="Medium",
         fix="Use SNMPv3 with SHA authentication (e.g. 'snmp-server user V3USER ... auth sha') "
             "instead of SNMPv1/v2c community strings."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215697", vendor="cisco_ios",
         example='snmp-server user V3USER V3GROUP v3 noauth', title="Encrypt SNMP traffic", control="ac-17", severity="Medium",
         fix="Configure SNMPv3 privacy with AES ('snmp-server user ... priv aes 256')."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215698", vendor="cisco_ios",
         example='ntp server 192.0.2.10', title="Authenticate NTP sources", control="ia-3", severity="Medium",
         fix="Configure NTP authentication keys and mark them trusted so time-sync responses "
             "cannot be spoofed by an on-path attacker."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215699", vendor="cisco_ios",
         example='ip ssh server algorithm mac hmac-sha1', title="Use a FIPS-validated HMAC to protect remote maintenance sessions",
         control="ma-4", severity="High",
         fix="Use SSHv2 with a strong MAC algorithm, e.g. "
             "'ip ssh server algorithm mac hmac-sha2-256'."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215700", vendor="cisco_ios",
         example='ip ssh server algorithm encryption 3des-cbc', title="Encrypt remote maintenance sessions", control="ma-4", severity="High",
         fix="Configure strong SSH encryption algorithms, e.g. "
             "'ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr'."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215709", vendor="cisco_ios",
         example='aaa authentication login default local', title="Use at least two authentication servers", control="cm-6", severity="High",
         fix="Configure RADIUS/TACACS+ with a local fallback, e.g. "
             "'aaa authentication login default group radius local'."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-220136", vendor="cisco_ios",
         example='logging host 192.0.2.20', title="Send audit records to at least two syslog servers", control="au-4", severity="High",
         fix="Configure at least two 'logging host x.x.x.x' destinations."),
    dict(stig="Cisco IOS Router NDM STIG", vuln_id="V-215701", vendor="cisco_ios",
         example='! no control-plane policing (CoPP) configured', title="Protect against denial-of-service attacks", control="sc-5", severity="Medium",
         fix="Implement Control Plane Policing (CoPP) with class-based traffic classification "
             "and rate limiting for control-plane traffic."),

    # ---- Palo Alto Networks NDM STIG V3R1 ----
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228639", vendor="palo_alto",
         example='set shared authentication-profile AUTH-PROF lockout failed-attempts 10', title="Enforce a limit of 3 consecutive invalid logon attempts", control="ac-7",
         severity="Medium",
         fix="Set the authentication profile's Failed Attempts to 3 (with an appropriate "
             "lockout time)."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228645", vendor="palo_alto",
         example='set deviceconfig system service-disable no', title="Prohibit unnecessary functions, ports, protocols, and services",
         control="cm-7", severity="Medium",
         fix="Review configured services and disable anything not explicitly authorized; use "
             "SNMPv3 only."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228647", vendor="palo_alto",
         example='set shared authentication-profile AUTH-PROF method local-database', title="Implement replay-resistant authentication for privileged accounts",
         control="ia-2", severity="Medium",
         fix="Use Kerberos, or LDAP with TLS, or RADIUS in FIPS mode for administrator "
             "authentication."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228655", vendor="palo_alto",
         example='set deviceconfig system telnet yes\nset deviceconfig system http yes', title="Prohibit unencrypted protocols for privileged account access", control="ia-5",
         severity="Medium",
         fix="Disable Telnet and HTTP under Management Interface Settings; permit only SSH "
             "and HTTPS."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228658", vendor="palo_alto",
         example='set deviceconfig system idle-timeout 60', title="Terminate management sessions after 10 minutes of inactivity", control="sc-10",
         severity="High",
         fix="Set the Idle Timeout to 10 minutes or less under device management settings."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228669", vendor="palo_alto",
         example='set deviceconfig system telnet yes', title="Use secure protocols for nonlocal maintenance", control="ma-4", severity="High",
         fix="Confirm Telnet and HTTP are disabled; use SSH and HTTPS only."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228670", vendor="palo_alto",
         example='set snmp-setting access-setting version v2c', title="Prohibit SNMP versions 1 and 2; use SNMPv3 only", control="ma-4", severity="High",
         fix="Configure SNMPv3 with authenticated/encrypted views and users; update all trap "
             "server configuration to v3."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228676", vendor="palo_alto",
         example='# admin account still using factory-default password', title="Change the default administrator account password", control="cm-6",
         severity="High",
         fix="Change the default 'admin' account password immediately after initial setup."),
    dict(stig="Palo Alto Networks NDM STIG", vuln_id="V-228678", vendor="palo_alto",
         example='set deviceconfig system ntp-servers primary-ntp-server authentication-type none', title="Authenticate NTP sources", control="ia-3", severity="Medium",
         fix="Set NTP authentication type to Symmetric Key or Autokey (not none)."),

    # ---- Juniper Router RTR STIG V3R1 ----
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217011", vendor="juniper_junos",
         example='! no firewall filter applied to lo0 or interfaces', title="Enforce approved authorizations for information flow control", control="ac-4",
         severity="Medium",
         fix="Implement firewall filters that allow/deny traffic explicitly by source, "
             "destination, port, and protocol."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217017", vendor="juniper_junos",
         example='set system services telnet\nset system services finger', title="Disable non-essential capabilities", control="cm-7", severity="Low",
         fix="Remove unnecessary services (Telnet, FTP, finger) from the system services "
             "configuration."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217018", vendor="juniper_junos",
         example='! no loopback filter / control-plane policing configured', title="Protect against denial-of-service attacks via control plane protection",
         control="sc-5", severity="Medium",
         fix="Implement control-plane policing (CoPP-equivalent firewall filters) with "
             "traffic classification and rate limiting on the loopback filter."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217019", vendor="juniper_junos",
         example='! lo0 has no unit 0 family inet filter input applied', title="Restrict traffic destined to the router itself", control="sc-7", severity="High",
         fix="Apply a receive-path (lo0) filter that limits management traffic to approved "
             "sources only."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217029", vendor="juniper_junos",
         example='set firewall filter PERIMETER term default then accept', title="Deny network traffic by default and allow by exception at the perimeter",
         control="sc-7", severity="High",
         fix="Configure a default-deny policy with explicit permit terms for only the "
             "required traffic (default-deny / allow-by-exception)."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217032", vendor="juniper_junos",
         example='! no bogon/RFC1918 prefix-list filter on external interface', title="Block inbound packets with bogon source addresses", control="sc-7",
         severity="Medium",
         fix="Create prefix-lists and filters that drop RFC 1918 / reserved source addresses "
             "arriving on external interfaces."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217036", vendor="juniper_junos",
         example='set interfaces ge-0/0/0 unit 0 family inet (no rpf-check configured)', title="Restrict outbound packets with illegitimate source addresses", control="sc-5",
         severity="High",
         fix="Enable Unicast Reverse Path Forwarding (uRPF) on internal-facing interfaces."),
    dict(stig="Juniper Router RTR STIG", vuln_id="V-217025", vendor="juniper_junos",
         example='set firewall filter DENY-LOG term deny then discard  (no syslog action)', title="Log all dropped packets", control="au-3", severity="Low",
         fix="Add a syslog action to filter deny terms and enable firewall logging."),

    # ---- Red Hat Enterprise Linux 9 STIG V1R2 ----
    dict(stig="RHEL 9 STIG", vuln_id="V-257985", vendor="linux_sshd",
         example='PermitRootLogin yes', title="SSH daemon must not allow root logins", control="ac-3", severity="Medium",
         fix="Set 'PermitRootLogin no' in /etc/ssh/sshd_config."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257984", vendor="linux_sshd",
         example='PermitEmptyPasswords yes', title="SSH daemon must not allow blank passwords", control="ia-5", severity="High",
         fix="Ensure 'PermitEmptyPasswords no' (or remove any override permitting it) in "
             "sshd_config."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257989", vendor="linux_sshd",
         example='Ciphers aes128-cbc,3des-cbc', title="SSH daemon must use only DoD-approved ciphers", control="sc-13",
         severity="Medium",
         fix="Restrict the 'Ciphers' directive in sshd_config to FIPS/DoD-approved algorithms "
             "only."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257995", vendor="linux_sshd",
         example='# ClientAliveCountMax / ClientAliveInterval not set', title="SSH daemon must terminate unresponsive connections", control="sc-10",
         severity="Medium",
         fix="Set 'ClientAliveCountMax' and 'ClientAliveInterval' so unresponsive sessions are "
             "disconnected automatically."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257996", vendor="linux_sshd",
         example='# no idle-session timeout configured in sshd_config', title="SSH daemon must disconnect idle sessions after 10 minutes", control="sc-10",
         severity="Medium",
         fix="Set ClientAliveInterval/ClientAliveCountMax so idle SSH sessions are dropped "
             "within 10 minutes."),
    dict(stig="RHEL 9 STIG", vuln_id="V-258007", vendor="linux_sshd",
         example='X11Forwarding yes', title="SSH daemon must disable X11 forwarding", control="ac-3", severity="Medium",
         fix="Set 'X11Forwarding no' in sshd_config."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257957", vendor="linux_sysctl",
         example='net.ipv4.tcp_syncookies = 0', title="TCP SYN cookies must be enabled", control="sc-5", severity="Medium",
         fix="Set 'net.ipv4.tcp_syncookies = 1' via sysctl."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257963", vendor="linux_sysctl",
         example='net.ipv4.conf.all.accept_redirects = 1', title="ICMP redirects must not be accepted (IPv4)", control="sc-5", severity="Medium",
         fix="Set 'net.ipv4.conf.all.accept_redirects = 0' via sysctl."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257966", vendor="linux_sysctl",
         example='net.ipv4.icmp_echo_ignore_broadcasts = 0', title="Broadcast ICMP echo requests must not be answered", control="sc-5",
         severity="Medium",
         fix="Set 'net.ipv4.icmp_echo_ignore_broadcasts = 1' via sysctl."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257970", vendor="linux_sysctl",
         example='net.ipv4.ip_forward = 1', title="IPv4 forwarding must be disabled unless the system is a router", control="sc-7",
         severity="Medium",
         fix="Set 'net.ipv4.ip_forward = 0' unless the host is an authorized router."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257826", vendor="linux_pam",
         example='rpm -q vsftpd\nvsftpd-3.0.5-3.el9.x86_64 (installed)', title="FTP server packages must not be installed", control="ia-5", severity="High",
         fix="Uninstall vsftpd or any other FTP server package unless explicitly required."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257831", vendor="linux_pam",
         example='rpm -q telnet-server\ntelnet-server-0.17-85.el9.x86_64 (installed)', title="Telnet server package must not be installed", control="cm-7", severity="Medium",
         fix="Uninstall the telnet-server package."),
    dict(stig="RHEL 9 STIG", vuln_id="V-257835", vendor="linux_pam",
         example='rpm -q tftp-server\ntftp-server-5.2-53.el9.x86_64 (installed)', title="TFTP server package must not be installed", control="cm-7", severity="High",
         fix="Remove tftp-server unless operationally justified and documented."),
    dict(stig="RHEL 9 STIG", vuln_id="V-258084", vendor="linux_pam",
         example='# /etc/sudoers: Defaults !authenticate', title="Sudo must require re-authentication", control="ac-6", severity="Medium",
         fix="Ensure the 'authenticate' option is not disabled in /etc/sudoers."),

    # ---- Microsoft Windows Server 2022 STIG V2R8 ----
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254275", vendor="windows_powershell",
         example='Get-WindowsFeature -Name FS-SMB1\nInstalled : True', title="SMBv1 protocol must not be installed", control="cm-7", severity="Medium",
         fix="Run 'Uninstall-WindowsFeature -Name FS-SMB1' (SMBv1 has known critical "
             "vulnerabilities)."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254276", vendor="windows_powershell",
         example='HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 1', title="SMBv1 must be disabled on the SMB server", control="cm-7", severity="Medium",
         fix="Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 0."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254265", vendor="windows_secedit",
         example='Get-NetFirewallProfile -Profile Domain,Public,Private | Select Enabled\nEnabled : False', title="Host-based firewall must be installed and enabled", control="cm-6",
         severity="Medium",
         fix="Ensure Windows Defender Firewall (or an approved equivalent) is enabled on all "
             "profiles."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254267", vendor="windows_secedit",
         example='net user tempadmin /add   (no /expires date set)', title="Temporary user accounts must expire within 72 hours", control="ac-2",
         severity="Medium",
         fix="Set an account expiration date at creation time, e.g. via "
             "'Net user /expires:[mm/dd/yyyy]'."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254257", vendor="windows_secedit",
         example='# local account created without a password requirement', title="Accounts must require passwords", control="ia-2", severity="Medium",
         fix="Verify the PasswordRequired flag is set for all enabled accounts (PowerShell "
             "check against local/AD accounts)."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254270", vendor="windows_secedit",
         example='Get-WindowsFeature -Name Web-Ftp-Service\nInstalled : True', title="Microsoft FTP service must not be installed", control="cm-7", severity="Medium",
         fix="Remove the FTP server role/feature unless explicitly required and documented "
             "with the ISSO."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254273", vendor="windows_secedit",
         example='Get-WindowsFeature -Name Telnet-Client\nInstalled : True', title="Telnet Client must not be installed", control="cm-7", severity="Medium",
         fix="Remove the Telnet Client feature via Server Manager."),
    dict(stig="Windows Server 2022 STIG", vuln_id="V-254262", vendor="windows_secedit",
         example='# volume BitLocker status: FullyDecrypted', title="Data at rest must employ cryptographic protection", control="sc-28",
         severity="High",
         fix="Enable full-disk or file-level encryption (e.g. BitLocker) for systems that "
             "require data-at-rest protection."),
]

REAL_STIG_BY_VENDOR = {}
for _r in REAL_STIG_RULES:
    REAL_STIG_BY_VENDOR.setdefault(_r["vendor"], []).append(_r)


# NCIIPC "Guidelines for Protection of Critical Information Infrastructure" V2.0
# (nciipc.gov.in/documents/NCIIPC_Guidelines_V2.pdf) — 35 controls, 5 families.
NCIIPC_CONTROLS = [
    ("PC1", "Planning Controls", "Identification of Critical Information Infrastructure"),
    ("PC2", "Planning Controls", "Vertical and Horizontal Interdependencies"),
    ("PC3", "Planning Controls", "Information Security Department"),
    ("PC4", "Planning Controls", "Information Security Policy"),
    ("PC5", "Planning Controls", "Integration Control"),
    ("PC6", "Planning Controls", "VTR Assessment and Mitigation Controls"),
    ("PC7", "Planning Controls", "Security Architecture Controls including Configuration Management"),
    ("PC8", "Planning Controls", "Redundancy Controls"),
    ("PC9", "Planning Controls", "Legacy System Integration"),
    ("PC10", "Planning Controls", "Supply Chain Management"),
    ("PC11", "Planning Controls", "Security Certifications"),
    ("PC12", "Planning Controls", "Physical Security Controls"),
    ("IC1", "Implementation Controls", "Asset and Inventory Control"),
    ("IC2", "Implementation Controls", "Access Control Policies"),
    ("IC3", "Implementation Controls", "Identification and Authentication Control"),
    ("IC4", "Implementation Controls", "Perimeter Protection"),
    ("IC5", "Implementation Controls", "Physical and Environmental Security"),
    ("IC6", "Implementation Controls", "Testing and Evaluation of Hardware and Software"),
    ("OC1", "Operational Controls", "Data Storage: Hashing and Encryption"),
    ("OC2", "Operational Controls", "Incident Management - Response"),
    ("OC3", "Operational Controls", "Training, Awareness and Skill Upgradation"),
    ("OC4", "Operational Controls", "Data Loss Prevention"),
    ("OC5", "Operational Controls", "Penetration Testing"),
    ("OC6", "Operational Controls", "Asset and Inventory Management"),
    ("OC7", "Operational Controls", "Network Device Protection"),
    ("OC8", "Operational Controls", "Cloud Protection"),
    ("OC9", "Operational Controls", "Critical Information Disposal and Transfer"),
    ("OC10", "Operational Controls", "Intranet Security"),
    ("OC11", "Operational Controls", "APT Protection"),
    ("DR1", "Disaster Recovery / Business Continuity", "Contingency Planning - Graceful Degradation"),
    ("DR2", "Disaster Recovery / Business Continuity", "Data Back-up and Recovery Plan, Disaster Recovery Site"),
    ("DR3", "Disaster Recovery / Business Continuity", "Secure and Resilient Architecture Deployment"),
    ("RA1", "Reporting and Accountability", "Mechanism for Threat Reporting to Government Agencies"),
    ("RA2", "Reporting and Accountability", "Periodic Audit and Vulnerability Assessment"),
    ("RA3", "Reporting and Accountability", "Compliance with Security Recommendations"),
]

# Mapping used to attach a plausible NCIIPC control to network/config findings.
NCIIPC_RELEVANT = ["IC2", "IC3", "IC4", "OC7", "OC10", "PC7", "IC6", "OC1", "RA2"]


# CIS Critical Security Controls v8.1 — top-level control names only (the
# licensed numbered benchmark recommendation text is NOT reproduced).
CIS_CONTROLS_V8 = [
    (1, "Inventory and Control of Enterprise Assets"),
    (2, "Inventory and Control of Software Assets"),
    (3, "Data Protection"),
    (4, "Secure Configuration of Enterprise Assets and Software"),
    (5, "Account Management"),
    (6, "Access Control Management"),
    (7, "Continuous Vulnerability Management"),
    (8, "Audit Log Management"),
    (9, "Email and Web Browser Protections"),
    (10, "Malware Defenses"),
    (11, "Data Recovery"),
    (12, "Network Infrastructure Management"),
    (13, "Network Monitoring and Defense"),
    (14, "Security Awareness and Skills Training"),
    (15, "Service Provider Management"),
    (16, "Application Software Security"),
    (17, "Incident Response Management"),
    (18, "Penetration Testing"),
]

# ISO/IEC 27001:2022 Annex A — control IDs and short titles only (the
# paywalled normative requirement text of the standard is NOT reproduced).
ISO_27001_ANNEX_A = [
    ("5.1", "Policies for information security"), ("5.2", "Information security roles and responsibilities"),
    ("5.3", "Segregation of duties"), ("5.4", "Management responsibilities"),
    ("5.5", "Contact with authorities"), ("5.6", "Contact with special interest groups"),
    ("5.7", "Threat intelligence"), ("5.8", "Information security in project management"),
    ("5.9", "Inventory of information and other associated assets"),
    ("5.10", "Acceptable use of information and other associated assets"),
    ("5.11", "Return of assets"), ("5.12", "Classification of information"),
    ("5.13", "Labelling of information"), ("5.14", "Information transfer"),
    ("5.15", "Access control"), ("5.16", "Identity management"),
    ("5.17", "Authentication information"), ("5.18", "Access rights"),
    ("5.19", "Information security in supplier relationships"),
    ("5.20", "Addressing information security within supplier agreements"),
    ("5.21", "Managing information security in the ICT supply chain"),
    ("5.22", "Monitoring, review and change management of supplier services"),
    ("5.23", "Information security for use of cloud services"),
    ("5.24", "Information security incident management planning and preparation"),
    ("5.25", "Assessment and decision on information security events"),
    ("5.26", "Response to information security incidents"),
    ("5.27", "Learning from information security incidents"),
    ("5.28", "Collection of evidence"), ("5.29", "Information security during disruption"),
    ("5.30", "ICT readiness for business continuity"),
    ("5.31", "Identification of legal, statutory, regulatory and contractual requirements"),
    ("5.32", "Intellectual property rights"), ("5.33", "Protection of records"),
    ("5.34", "Privacy and protection of PII"),
    ("5.35", "Independent review of information security"),
    ("5.36", "Compliance with policies and standards for information security"),
    ("5.37", "Documented operating procedures"),
    ("6.1", "Screening"), ("6.2", "Terms and conditions of employment"),
    ("6.3", "Information security awareness, education and training"),
    ("6.4", "Disciplinary process"),
    ("6.5", "Responsibilities after termination or change of employment"),
    ("6.6", "Confidentiality or non-disclosure agreements"), ("6.7", "Remote working"),
    ("6.8", "Information security event reporting"),
    ("7.1", "Physical security perimeter"), ("7.2", "Physical entry controls"),
    ("7.3", "Securing offices, rooms and facilities"),
    ("7.4", "Physical security monitoring"),
    ("7.5", "Protecting against physical and environmental threats"),
    ("7.6", "Working in secure areas"), ("7.7", "Clear desk and clear screen"),
    ("7.8", "Equipment siting and protection"), ("7.9", "Security of assets off-premises"),
    ("7.10", "Storage media"), ("7.11", "Supporting utilities"),
    ("7.12", "Cabling security"), ("7.13", "Equipment maintenance"),
    ("7.14", "Secure disposal or re-use of equipment"),
    ("8.1", "User endpoint devices"), ("8.2", "Privileged access rights"),
    ("8.3", "Information access restriction"), ("8.4", "Access to source code"),
    ("8.5", "Secure authentication"), ("8.6", "Capacity management"),
    ("8.7", "Protection against malware"), ("8.8", "Management of technical vulnerabilities"),
    ("8.9", "Configuration management"), ("8.10", "Information deletion"),
    ("8.11", "Data masking"), ("8.12", "Data leakage prevention"),
    ("8.13", "Information backup"),
    ("8.14", "Redundancy of information processing facilities"), ("8.15", "Logging"),
    ("8.16", "Monitoring activities"), ("8.17", "Clock synchronisation"),
    ("8.18", "Use of privileged utility programs"),
    ("8.19", "Installation of software on operational systems"),
    ("8.20", "Networks security"), ("8.21", "Security of network services"),
    ("8.22", "Segregation of networks"), ("8.23", "Web filtering"),
    ("8.24", "Use of cryptography"), ("8.25", "Secure development life cycle"),
    ("8.26", "Application security requirements"),
    ("8.27", "Secure systems architecture and engineering principles"),
    ("8.28", "Secure coding"),
    ("8.29", "Security testing in development and acceptance"),
    ("8.30", "Outsourced development"),
    ("8.31", "Separation of development, test and production environments"),
    ("8.32", "Change management"), ("8.33", "Test information"),
    ("8.34", "Protection of information systems during audit testing"),
]

# Annex A controls most relevant to network/config-hardening findings, used
# to pick a plausible cross-reference for security_explanation rows.
ISO_RELEVANT = ["8.20", "8.21", "8.22", "8.9", "8.5", "8.2", "8.15", "8.16", "8.24", "5.15"]
