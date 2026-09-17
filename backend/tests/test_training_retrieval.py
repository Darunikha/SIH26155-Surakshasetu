"""Regression test for the adaptive-learning retrieval loop (spec sections
16, 47): once a human confirms the meaning of one unknown config line, a
second, differently-worded but semantically similar unknown line should
retrieve that confirmed mapping directly -- not trigger a fresh (and
possibly inconsistent, and definitely more expensive) LLM guess."""
from __future__ import annotations

import pytest

from app.ai.service import AIService
from app.db import Collections, connect
from app.rag.embedder import embed
from app.utils.ids import utcnow_iso

pytestmark = pytest.mark.integration


class _LLMShouldNotBeCalled:
    """Stub Ollama client that fails the test loudly if the retrieval step
    doesn't short-circuit before reaching the LLM."""

    model = "test-model"

    async def generate(self, *args, **kwargs):
        raise AssertionError("LLM was called even though a confirmed similar mapping existed")

    async def chat(self, *args, **kwargs):
        raise AssertionError("LLM was called even though a confirmed similar mapping existed")


class _StubReturnsJSON:
    """Stub Ollama client used for the no-match path -- proves the LLM path
    still works and is correctly tagged, without a real Ollama call."""

    model = "test-model"

    async def generate(self, *args, **kwargs):
        return '{"category": "Other", "meaning": "stub interpretation", "confidence": 0.3}'


@pytest.mark.asyncio
async def test_similar_confirmed_mapping_short_circuits_llm_call():
    db = connect()
    vendor = "TestVendor-Retrieval"
    confirmed_line = "set ip helper-address 10.0.0.5 on vlan99"
    reworded_line = "set ip helper-address 10.0.0.5 on vlan100"

    await db[Collections.TRAINING_EXAMPLES].insert_one(
        {
            "vendor": vendor,
            "raw_line": confirmed_line,
            "category": "DHCP Relay",
            "ir_field_path": "management.dhcp_relay",
            "meaning": "Forwards DHCP broadcasts to a relay address for this VLAN.",
            "source": "human_confirmed",
            "embedding": embed(confirmed_line),
            "created_at": utcnow_iso(),
        }
    )

    try:
        ai = AIService(client=_LLMShouldNotBeCalled())
        result = await ai.interpret_unknown_syntax(raw_line=reworded_line, vendor=vendor, db=db)

        assert result["source"] == "human_confirmed_similar"
        assert result["category"] == "DHCP Relay"
        assert result["meaning"] == "Forwards DHCP broadcasts to a relay address for this VLAN."
        assert result["confidence"] == 1.0
        assert result["matched_raw_line"] == confirmed_line
    finally:
        await db[Collections.TRAINING_EXAMPLES].delete_many({"vendor": vendor})


@pytest.mark.asyncio
async def test_unrelated_unknown_line_falls_through_to_llm_and_is_tagged():
    db = connect()
    vendor = "TestVendor-NoMatch"

    ai = AIService(client=_StubReturnsJSON())
    result = await ai.interpret_unknown_syntax(
        raw_line="some line nobody has ever confirmed a meaning for", vendor=vendor, db=db
    )
    assert result["source"] == "llm_suggestion"
    assert result["category"] == "Other"


@pytest.mark.asyncio
async def test_confirmed_mapping_for_a_different_vendor_does_not_match():
    """A confirmed mapping must not leak across vendors -- FortiOS and Cisco
    syntax can share vocabulary (e.g. "interface"), but a match confirmed for
    one vendor should never short-circuit another vendor's identical-looking
    line."""
    db = connect()
    vendor_a = "TestVendor-A"
    vendor_b = "TestVendor-B"
    line = "set some vendor specific knob to a value"

    await db[Collections.TRAINING_EXAMPLES].insert_one(
        {
            "vendor": vendor_a,
            "raw_line": line,
            "category": "Whatever",
            "ir_field_path": "x.y",
            "meaning": "Confirmed only for vendor A.",
            "source": "human_confirmed",
            "embedding": embed(line),
            "created_at": utcnow_iso(),
        }
    )

    try:
        ai = AIService(client=_StubReturnsJSON())
        result = await ai.interpret_unknown_syntax(raw_line=line, vendor=vendor_b, db=db)
        assert result["source"] == "llm_suggestion"
    finally:
        await db[Collections.TRAINING_EXAMPLES].delete_many({"vendor": vendor_a})
