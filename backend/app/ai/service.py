"""AI service: explanation, remediation suggestion, and unknown-syntax
interpretation (spec sections 16, 24, 35). Every method degrades to
AIUnavailableError -- never a fabricated response -- when Ollama is not
reachable, per the local-first architecture (spec section 51).

Secrets are never sent: callers pass already-redacted evidence (dicts built
from the Security IR / findings), never raw configuration text.
"""
from __future__ import annotations

import json
import re

from app.ai.ollama_client import OllamaClient
from app.ai.prompts import (
    SYSTEM_PROMPT,
    finding_explanation_prompt,
    optimizer_summary_prompt,
    risk_summary_prompt,
    unknown_syntax_prompt,
)


class AIService:
    def __init__(self, client: OllamaClient | None = None):
        self.client = client or OllamaClient()

    async def is_available(self) -> bool:
        return await self.client.is_available()

    async def explain_finding(self, *, finding: dict, vendor: str, platform: str, rag_context: str = "") -> dict:
        prompt = finding_explanation_prompt(finding=finding, vendor=vendor, platform=platform, rag_context=rag_context)
        text = await self.client.generate(prompt, system=SYSTEM_PROMPT)
        return {
            "finding_id": finding.get("finding_id"),
            "explanation": text,
            "model": self.client.model,
            "ai_available": True,
        }

    async def interpret_unknown_syntax(self, *, raw_line: str, vendor: str, db=None) -> dict:
        """Closes the adaptive-learning loop (spec sections 16, 47): before
        asking the LLM anything, check whether a human has already confirmed
        the meaning of a semantically similar line for this vendor. If so,
        that confirmed mapping is returned directly -- cheaper and more
        trustworthy than a fresh guess, and it's what makes one human
        confirmation actually generalize to future similar lines instead of
        only ever matching that exact line again.

        `db` is optional so this method still works (skipping straight to
        the LLM) for any caller that doesn't have a database handle; the one
        current caller (app/api/training.py's ai_suggest) always passes it.
        """
        if db is not None:
            try:
                from app.ai.similar_mappings import find_similar_confirmed_mapping

                match = await find_similar_confirmed_mapping(db, vendor=vendor, raw_line=raw_line)
            except Exception:
                match = None
            if match is not None:
                return {
                    "category": match["category"],
                    "meaning": match["meaning"],
                    "confidence": 1.0,
                    "source": "human_confirmed_similar",
                    "matched_raw_line": match["raw_line"],
                    "similarity_score": match["similarity_score"],
                }

        prompt = unknown_syntax_prompt(raw_line=raw_line, vendor=vendor)
        text = await self.client.generate(prompt, system=SYSTEM_PROMPT, temperature=0.1)

        parsed = self._extract_json(text)
        if parsed is None:
            # Model didn't return valid JSON -- surface the raw text rather
            # than fabricating structured fields we don't actually have.
            return {
                "category": "Unknown",
                "meaning": text.strip() or "Model did not return a parseable interpretation.",
                "confidence": 0.0,
                "raw_model_output": text,
                "source": "llm_suggestion",
            }

        return {
            "category": parsed.get("category", "Unknown"),
            "meaning": parsed.get("meaning", ""),
            "confidence": float(parsed.get("confidence", 0.0)),
            "raw_model_output": text,
            "source": "llm_suggestion",
        }

    async def generate_remediation(self, *, finding: dict, vendor: str, platform: str, rag_context: str = "") -> dict:
        explanation = await self.explain_finding(finding=finding, vendor=vendor, platform=platform, rag_context=rag_context)
        commands = self._extract_commands(explanation["explanation"])
        return {
            "finding_id": finding.get("finding_id"),
            "vendor": vendor,
            "platform": platform,
            "explanation": explanation["explanation"],
            "suggested_commands": commands,
            "confidence_note": (
                "Commands are extracted from the model's response and are NOT guaranteed correct for your "
                "exact software version -- validate in a lab before applying (spec section 25: SIMULATED only)."
            ),
        }

    async def summarize_risk(self, *, risk_score: float, risk_level: str, risk_factors: dict, top_findings: list[dict]) -> dict:
        prompt = risk_summary_prompt(
            risk_score=risk_score, risk_level=risk_level, risk_factors=risk_factors, top_findings=top_findings
        )
        text = await self.client.generate(prompt, system=SYSTEM_PROMPT)
        return {"summary": text, "model": self.client.model, "ai_available": True}

    async def summarize_optimizer(self, *, strategies: dict, findings_by_id: dict) -> dict:
        prompt = optimizer_summary_prompt(strategies=strategies, findings_by_id=findings_by_id)
        text = await self.client.generate(prompt, system=SYSTEM_PROMPT)
        return {"summary": text, "model": self.client.model, "ai_available": True}

    async def chat(self, messages: list[dict]) -> str:
        full_messages = [{"role": "system", "content": SYSTEM_PROMPT}, *messages]
        return await self.client.chat(full_messages)

    @staticmethod
    def _extract_json(text: str) -> dict | None:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _extract_commands(text: str) -> list[str]:
        """Pulls fenced/backtick code lines out of the model's explanation.
        Never invents commands beyond what the model actually returned."""
        commands = []
        for block in re.findall(r"```(?:[a-zA-Z]*)\n(.*?)```", text, re.DOTALL):
            commands.extend(line.strip() for line in block.splitlines() if line.strip())
        if not commands:
            commands = [line.strip("` ") for line in re.findall(r"`([^`]+)`", text)]
        return commands


async def get_ai_status() -> dict:
    service = AIService()
    available = await service.is_available()
    return {
        "available": available,
        "model": service.client.model,
        "endpoint": service.client.base_url,
        "message": None if available else (
            "Ollama is not reachable. Install Ollama and run "
            f"`ollama pull {service.client.model}` to enable AI features."
        ),
    }
