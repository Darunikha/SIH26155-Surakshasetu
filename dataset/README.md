# Security Configuration Semantics Dataset

5,000 synthetic instruction-tuning examples for QLoRA fine-tuning of a small LLM to
understand **network/security configuration semantics** — parsing vendor CLI syntax,
classifying findings by risk, proposing remediations, explaining why a pattern matters,
translating between vendors, and handling unknown/ambiguous input gracefully.

Built for the "Pretrained Small LLM → 4-bit Quantization → QLoRA → Domain Dataset →
Fine-Tuned Adapter → Local Deployment" pipeline described in the project's training
strategy.

## Files

| File | Description |
|---|---|
| `security_config_dataset.jsonl` | Main deliverable — one JSON object per line. Preferred for HuggingFace `datasets.load_dataset("json", data_files=...)`, QLoRA/PEFT training scripts. |
| `security_config_dataset.json` | Same 5,000 rows as a single JSON array (same content as the .jsonl, just wrapped). |
| `generate_dataset.py` | The generator script. Re-run it to regenerate, scale up/down, or extend with new categories/vendors. Imports `real_references.py`. |
| `real_references.py` | The real, sourced reference data (NIST 800-53 control text, DISA STIG rules, NCIIPC controls, CIS/ISO labels) — see **Provenance** below. Required by `generate_dataset.py` at runtime; keep it next to the script. |
| `nist_controls_clean.json` | The extracted NIST SP 800-53 Rev 5 control text that `real_references.py` loads. Keep it next to `real_references.py`. |

## Schema

Each row:

```json
{
  "id": "secconf-00001",
  "category": "finding_classification",
  "vendor": "cisco_ios",
  "instruction": "Analyze this network configuration.",
  "input": "access-list 101 permit ip any any",
  "output": {
    "source": "ANY",
    "destination": "ANY",
    "protocol": "IP",
    "service": "...",
    "action": "ALLOW",
    "risk": "CRITICAL",
    "reason": "Unrestricted any-to-any rule permits all traffic...",
    "remediation": "Restrict source, destination and service."
  }
}
```

`instruction` / `input` / `output` match the alpaca-style shape from the project spec.
`id`, `category`, and `vendor` are extra metadata fields for filtering/stratified
sampling — most loaders will ignore unknown columns, but drop them first if your
training script requires exactly three keys.

**Note on `output` type**: for the structured tasks (classification, normalization,
remediation, cross-vendor translation, unknown/edge-case handling) `output` is a JSON
object, matching the example in the project spec. For `security_explanation` rows,
`output` is a plain string (prose explanation) — this mirrors how a real multi-task
instruction set looks. If your training pipeline needs every `output` to be a string,
run `json.dumps(row["output"])` on the non-string ones during preprocessing (one line).

## Category breakdown (5,000 rows)

| Category | Count | What it teaches |
|---|---:|---|
| `finding_classification` | 1,300 | Given a raw config line (or an OS/device hardening directive), extract fields and classify risk (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`) with a reason. |
| `remediation` | 900 | Given a finding (JSON), produce a remediation plan, a corrected example config, and a priority (P1–P3). |
| `security_explanation` | 700 | Given a config line/setting, explain *why* it matters, framed against a critical-infrastructure context — grounded in **real, quoted** citations: a real DISA STIG rule + real NIST 800-53 control text, or a real NIST control + representative rule, or a real NCIIPC control, each optionally cross-referenced to real ISO 27001 Annex A / CIS Controls v8 labels. See **Provenance** below. |
| `vendor_normalization` | 700 | Given a vendor-specific rule, extract it into a vendor-neutral JSON shape — no risk judgment, pure parsing. |
| `cross_vendor_equivalence` | 700 | Given a rule in one vendor's syntax, produce the equivalent rule in another vendor's syntax. |
| `unknown_syntax` | 350 | Garbled, empty, truncated, non-config, or unsupported-syntax input → the model should say "not recognized" instead of hallucinating a classification. |
| `edge_cases` | 350 | Ambiguous but partially-parseable input: unresolved object-groups, IPv6, FQDN destinations, disabled/commented rules, log-only rules, truncated lines → the model should express calibrated uncertainty (`risk: "INDETERMINATE"`) rather than guessing. |

## Vendors / platforms covered

Network ACL/firewall rule syntax: **Cisco IOS/IOS-XE, Juniper JunOS, Palo Alto PAN-OS,
Fortinet FortiOS, Linux iptables, Linux nftables, Linux ufw, Windows (netsh
advfirewall)**.

OS/device hardening directives (used inside `finding_classification` /
`security_explanation` / `remediation` for variety beyond 5-tuple ACL rules): Linux
`sshd_config`, `sysctl`, PAM password policy, `auditd`; Cisco `snmp-server community`,
VTY `exec-timeout`, `enable secret` vs `enable password`, Telnet vs SSH transport;
Windows `Set-SmbServerConfiguration`, account lockout policy (`secedit`); Fortinet NTP
authentication; Palo Alto update-server certificate validation.

Includes ICS/SCADA protocols (Modbus, DNP3) and critical-infrastructure framing
(power grid, core banking, telecom core, water treatment ICS, government WAN edge,
payment DMZ, airport OT, hospital clinical network) relevant to an NCIIPC-style
problem statement.

## Design notes: risk logic

The ground-truth risk labels follow a simple, consistent rule the model can learn as a
*pattern*, not a lookup table (per the spec: "the model should learn security
configuration semantics, not memorize compliance rules"):

- `DENY` rules → `NONE` (no remediation needed).
- `ALLOW` from `any` to `any` → `CRITICAL`.
- `ALLOW` from `any` for a cleartext/unauthenticated/high-value service (Telnet, FTP,
  TFTP, SNMP, RDP, SMB, LDAP, VNC, Modbus/DNP3, etc.) → `HIGH`.
- `ALLOW` from `any` to a specific destination (lower-risk service) → `MEDIUM`.
- `ALLOW` from specific source to `any` destination → `MEDIUM`.
- `ALLOW` between two specifically-scoped networks → `LOW`.

Remediation text is generated from the same signals (source too broad → scope it;
cleartext service → recommend the encrypted equivalent; SNMP → recommend SNMPv3, etc.),
so the input → output relationship is learnable rather than arbitrary.

## Provenance — important, read this before citing the dataset as "sourced from X"

The dataset has **two layers**, and they're sourced differently. Being precise about
which is which matters if this ends up in a hackathon submission.

**Layer 1 — the vendor CLI rule-parsing/classification task itself** (all of
`finding_classification`'s ACL rows, `vendor_normalization`, `cross_vendor_equivalence`,
`unknown_syntax`, `edge_cases`, and the vendor-CLI half of `remediation`) is
**synthetic by construction**. There is no "real dataset" of labeled ACL rules to pull
from nciipc.gov.in/CIS/NIST/STIGs/ISO for this — those bodies publish *hardening
guidance*, not labeled training examples. This layer is generated from (a) well-known,
publicly documented CLI syntax for the listed vendors — the grammar of an ACL/firewall
rule, not copyrighted prose — and (b) general, widely-taught security engineering
knowledge (e.g. "permit ip any any" is overly broad; Telnet/FTP/TFTP are cleartext;
default SNMP community strings are weak).

**Layer 2 — `security_explanation` (700 rows), plus the `nist_800_53_control` field on
hardening-item `finding_classification` rows** — is now grounded in **real, sourced
material**, fetched live and stored in `real_references.py`:

- **NIST SP 800-53 Rev 5** — verbatim control titles and statement text (37 controls),
  extracted from NIST/CSRC's own official OSCAL JSON catalog
  (`usnistgov/oscal-content` on GitHub). This is a U.S. federal government work and is
  in the public domain, so verbatim quoting is unrestricted.
- **DISA STIGs** — real Vulnerability IDs, titles, severities, and fix guidance (54
  rules) for Cisco IOS Router NDM, Palo Alto Networks NDM, Juniper Router RTR, RHEL 9,
  and Windows Server 2022, sourced from cyber.trackr.live, a reference site that
  republishes DISA's own published STIG content. DISA STIGs are U.S. DoD works
  released for unlimited public distribution. Fix text here is a condensed paraphrase
  of the real fix guidance, not always the verbatim STIG fix-text paragraph — pull the
  authoritative full text from the STIG itself (e.g. via a STIG viewer or
  public.cyber.mil) before citing exact STIG wording in anything official.
- **NCIIPC** — the real 35 control IDs and titles (across 5 families: Planning,
  Implementation, Operational, Disaster Recovery/BCP, Reporting & Accountability) from
  NCIIPC's own publicly published *Guidelines for Protection of Critical Information
  Infrastructure, V2.0* (hosted at `nciipc.gov.in/documents/NCIIPC_Guidelines_V2.pdf`).
  IDs and titles only — not the full guideline body text, which wasn't reproduced.
- **CIS Controls v8.1** and **ISO/IEC 27001:2022 Annex A** — the 18 real top-level CIS
  Control names and the 93 real Annex A control IDs/titles are used as citation labels.
  What's deliberately **not** included is the numbered CIS Benchmark recommendation
  text or the ISO 27001 normative requirement text — both are licensed/paywalled
  documents (CIS Benchmarks require a free account and restrict redistribution; ISO
  27001 is a purchased standard) that were not accessed and cannot legally be bulk
  quoted here. The ID+title lists used are CIS's/commonly-published free outlines, not
  the protected body text.

Concretely, a `security_explanation` row now looks like (real content, not invented):

> *"Cisco IOS Router NDM STIG V-215696 ('Authenticate SNMP using a FIPS-validated HMAC',
> severity Medium) applies here. Use SNMPv3 with SHA authentication instead of
> SNMPv1/v2c community strings. NIST SP 800-53 Rev 5 IA-3 (Device Identification and
> Authentication) states: 'Uniquely identify and authenticate \[organization-defined
> parameters\] before establishing a \[organization-defined parameters\] connection.'
> ... Under NCIIPC's Guidelines for Protection of CII (V2.0), this falls under OC7 –
> Network Device Protection (Operational Controls)."*

**Before using this for a hackathon submission or any real compliance tool**: the
citations above are real, but the *curation* is mine — I picked ~54 STIG rules and 37
NIST controls as a representative starting set, not the complete catalogs (DISA
publishes hundreds of rules per STIG; NIST 800-53 has ~1,000 controls). Treat this as a
solid, honestly-sourced bootstrap, and have a team member spot-check citations against
the primary sources (`public.cyber.mil`, `csrc.nist.gov`, `nciipc.gov.in`) before
presenting any of them as authoritative in a demo or report.

## Regenerating / scaling

```bash
python3 generate_dataset.py --count 5000 --seed 42 --out-prefix security_config_dataset
```

- `--count` — total rows (category proportions scale automatically).
- `--seed` — change for a different random draw; same seed = reproducible output.
- Edit `CATEGORY_GENERATORS` at the bottom of the script to change the per-category
  mix, or add new vendors/services/hardening items to the pools near the top of the
  file to extend coverage (e.g. add Check Point, pfSense, AWS Security Groups).

## Suggested train/val split

The rows are already shuffled. A simple approach:

```python
import json
rows = [json.loads(l) for l in open("security_config_dataset.jsonl", encoding="utf-8")]
split = int(len(rows) * 0.9)
train, val = rows[:split], rows[split:]
```

For a cleaner split, stratify by `category` first so validation isn't skewed toward
whichever category happens to land at the end of the shuffled file.
