"""Vendor parser contract (spec sections 13-14).

Adding a new vendor means implementing this Protocol and registering it in
`registry.py` -- the rest of the pipeline (compliance/risk/attack-graph)
never changes, because everything downstream reads the Security IR, not
vendor syntax.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.normalization.ir_schema import SecurityIR


@dataclass
class DetectionSignal:
    vendor: str
    platform: str
    confidence: float  # 0.0 - 1.0
    method: str  # "metadata" | "signature" | "ai_fallback"


class VendorParser(Protocol):
    vendor_name: str
    implemented: bool  # False => architecture stub, parsing not implemented

    def detect_confidence(self, text: str) -> float:
        """Return 0.0-1.0 confidence this text is this vendor's config."""
        ...

    def parse(self, text: str) -> SecurityIR:
        """Parse raw configuration text into the vendor-neutral Security IR."""
        ...


class NotImplementedParser:
    """Registry stub for vendors whose architecture is planned but whose
    parser has not been built yet. Never silently returns a fabricated IR --
    callers must check `implemented` before calling `parse`."""

    implemented = False

    def __init__(
        self,
        vendor_name: str,
        signature_hints: tuple[str, ...],
        reference_snippets: tuple[str, ...] = (),
    ):
        self.vendor_name = vendor_name
        self._signature_hints = signature_hints
        # Short representative config snippets used for the embedding-
        # similarity detection signal in app/vendors/registry.py -- same
        # attribute name (REFERENCE_SNIPPETS) as the implemented parsers use,
        # so the registry can read it uniformly via getattr().
        self.REFERENCE_SNIPPETS = reference_snippets

    def detect_confidence(self, text: str) -> float:
        lowered = text.lower()
        hits = sum(1 for hint in self._signature_hints if hint in lowered)
        if not self._signature_hints:
            return 0.0
        return min(1.0, hits / len(self._signature_hints)) * 0.6  # capped: unimplemented

    def parse(self, text: str) -> SecurityIR:
        raise NotImplementedError(
            f"A parser for '{self.vendor_name}' is architected but not yet implemented. "
            "This configuration cannot be normalized automatically; use the adaptive "
            "learning / training workflow, or await parser support."
        )
