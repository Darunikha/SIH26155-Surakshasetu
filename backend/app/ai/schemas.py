from __future__ import annotations

from pydantic import BaseModel


class FindingExplanation(BaseModel):
    finding_id: str
    explanation: str
    model: str
    ai_available: bool = True


class UnknownSyntaxInterpretation(BaseModel):
    category: str
    meaning: str
    confidence: float
    raw_model_output: str


class RemediationSuggestion(BaseModel):
    finding_id: str
    vendor: str
    platform: str
    explanation: str
    suggested_commands: list[str]
    confidence_note: str
