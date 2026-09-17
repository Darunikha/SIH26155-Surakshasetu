"""Vendor detection + parser registry (spec section 13).

Detection pipeline: every registered parser is scored against the uploaded
text with TWO independent signals, combined into one final confidence:

  1. Signature score (parser.detect_confidence): fast literal substring/regex
     matching against vendor-specific syntax markers. High precision when it
     fires -- a real Cisco config essentially always contains multiple exact
     Cisco command strings -- but brittle: any config that doesn't happen to
     contain those exact substrings (different phrasing, a partial/redacted
     upload, whitespace quirks) scores 0 even if it's obviously that vendor
     to a human reader.
  2. Embedding score (_embedding_score): cosine similarity between the
     uploaded text and a small set of representative real config snippets
     per vendor (each parser's REFERENCE_SNIPPETS). This is a semantic/
     pattern-recognition signal rather than exact-string matching, so it can
     still recognize a config that's clearly "Juniper-shaped" even when none
     of the specific signature substrings appear verbatim.

final_confidence = max(signature_score, embedding_score) for each vendor.
Justification for max() over a weighted blend: the signature score is
already high-precision when it fires (it requires literal vendor syntax, so
false positives are rare), so blending it downward with a weaker semantic
score would only make a confident, correct signature match look less
certain. Using max() means either signal firing strongly is enough to
recognize the vendor, while both scores stay independently visible on
DetectionResult (confidence is the blended winner, embedding_score is the
winning vendor's raw embedding-similarity score) so a caller can see *why*
a vendor was picked, not just that it was.

A low-confidence result is still returned -- it is never silently treated as
authoritative by the caller (spec section 13: "Never allow an uncertain AI
guess to silently become authoritative"); the API layer routes low-
confidence detections to human confirmation instead of proceeding straight
to parsing.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.normalization.ir_schema import SecurityIR
from app.rag.embedder import embed, embed_batch
from app.vendors.base import NotImplementedParser, VendorParser
from app.vendors.cisco import CiscoIOSParser
from app.vendors.fortinet import FortiOSParser
from app.vendors.paloalto import PanOSParser

# Confidence at/above this threshold is treated as authoritative without
# requiring human confirmation. Below it, the API surfaces the top
# candidate(s) for human review rather than auto-selecting.
AUTHORITATIVE_CONFIDENCE_THRESHOLD = 0.55

_PARSERS: dict[str, VendorParser] = {
    "Cisco": CiscoIOSParser(),
    "Fortinet": FortiOSParser(),
    "PaloAlto": PanOSParser(),
    "Juniper": NotImplementedParser(
        "Juniper",
        ("set system host-name", "set interfaces", "junos"),
        reference_snippets=(
            "set system host-name juniper-router-01",
            "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
            "set security zones security-zone trust interfaces ge-0/0/0.0",
            "set firewall family inet filter protect-re term allow-ssh from protocol tcp",
            "set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254",
        ),
    ),
    "Arista": NotImplementedParser(
        "Arista",
        ("! device: arista", "eos", "interface ethernet"),
        reference_snippets=(
            "! device: arista-switch-01 (DCS-7050, EOS-4.25.1F)",
            "interface Ethernet1\n description Uplink\n switchport mode trunk",
            "ip access-list extended BLOCK-TELNET\n deny tcp any any eq telnet",
            "management ssh\n idle-timeout 15",
            "vlan 10\n name Servers",
        ),
    ),
    "CheckPoint": NotImplementedParser(
        "CheckPoint",
        ("checkpoint", "gaia", "set interface"),
        reference_snippets=(
            "set interface eth0 ipv4-address 192.168.1.1 mask-length 24",
            "set hostname checkpoint-gw-01",
            "add host name web-server ipv4-address 10.0.0.5",
            "set snmp community public read-only",
        ),
    ),
    "SONiC": NotImplementedParser(
        "SONiC",
        ("sonic", "config_db.json"),
        reference_snippets=(
            '{"INTERFACE": {"Ethernet0": {"admin_status": "up"}}}',
            "config vlan add 100",
            "config interface ip add Ethernet0 10.0.0.1/24",
            '{"DEVICE_METADATA": {"localhost": {"hostname": "sonic-switch-01"}}}',
        ),
    ),
}


def _build_reference_embeddings() -> dict[str, list[list[float]]]:
    """Computed once at module load, not per request (embedding a few dozen
    short snippets is cheap once, but doing it on every upload would not
    be). Degrades to an empty list per-vendor on any embedding failure --
    that vendor's embedding_score just becomes 0.0 rather than raising."""
    result: dict[str, list[list[float]]] = {}
    for name, parser in _PARSERS.items():
        snippets = list(getattr(parser, "REFERENCE_SNIPPETS", ()) or ())
        try:
            result[name] = embed_batch(snippets) if snippets else []
        except Exception:
            result[name] = []
    return result


_REFERENCE_EMBEDDINGS: dict[str, list[list[float]]] = _build_reference_embeddings()


def _cosine(a: list[float], b: list[float]) -> float:
    # app/rag/embedder.py's embed()/embed_batch() always return L2-normalized
    # vectors, so a plain dot product is already cosine similarity.
    return sum(x * y for x, y in zip(a, b))


def _embedding_score(query_vector: list[float] | None, vendor: str) -> float:
    if not query_vector:
        return 0.0
    references = _REFERENCE_EMBEDDINGS.get(vendor) or []
    if not references:
        return 0.0
    return max(_cosine(query_vector, ref) for ref in references)


@dataclass
class DetectionResult:
    vendor: str
    platform: str
    confidence: float
    embedding_score: float
    method: str
    implemented: bool
    candidates: list[tuple[str, float]]  # all scored vendors (blended score), for transparency


def get_parser(vendor: str) -> VendorParser | None:
    return _PARSERS.get(vendor)


def list_vendors() -> list[str]:
    return list(_PARSERS.keys())


def detect_vendor(text: str, metadata_hint: str | None = None) -> DetectionResult:
    """Detect the vendor of a configuration.

    1. Explicit metadata hint (e.g. user-selected vendor at upload time) wins
       outright with confidence 1.0.
    2. Otherwise every parser is scored on both signature and embedding
       signals (see module docstring); highest blended score wins.
    """
    if metadata_hint and metadata_hint in _PARSERS:
        parser = _PARSERS[metadata_hint]
        return DetectionResult(
            vendor=metadata_hint,
            platform=getattr(parser, "vendor_name", metadata_hint),
            confidence=1.0,
            embedding_score=0.0,  # not computed -- the explicit hint overrides scoring entirely
            method="metadata",
            implemented=parser.implemented,
            candidates=[(metadata_hint, 1.0)],
        )

    try:
        query_vector = embed(text)
    except Exception:
        query_vector = None

    scores: list[tuple[str, float]] = []
    signals: dict[str, tuple[float, float]] = {}  # vendor -> (signature_score, embedding_score)
    for name, parser in _PARSERS.items():
        try:
            signature_score = parser.detect_confidence(text)
        except Exception:
            signature_score = 0.0
        embedding_score = _embedding_score(query_vector, name)
        signals[name] = (signature_score, embedding_score)
        scores.append((name, max(signature_score, embedding_score)))

    scores.sort(key=lambda t: t[1], reverse=True)
    top_vendor, top_score = scores[0]
    parser = _PARSERS[top_vendor]
    signature_score, embedding_score = signals[top_vendor]

    platform_map = {
        "Cisco": "IOS/IOS-XE",
        "Fortinet": "FortiOS",
        "PaloAlto": "PAN-OS",
    }

    return DetectionResult(
        vendor=top_vendor,
        platform=platform_map.get(top_vendor, top_vendor),
        confidence=round(top_score, 4),
        embedding_score=round(embedding_score, 4),
        method="signature" if signature_score >= embedding_score else "embedding",
        implemented=parser.implemented,
        candidates=scores,
    )


def parse_configuration(vendor: str, text: str) -> SecurityIR:
    parser = get_parser(vendor)
    if parser is None:
        raise ValueError(f"Unknown vendor '{vendor}'")
    if not parser.implemented:
        raise NotImplementedError(
            f"Parser for '{vendor}' is architected but not implemented yet"
        )
    return parser.parse(text)
