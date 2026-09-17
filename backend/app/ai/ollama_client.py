"""HTTP client for a local Ollama instance (spec sections 24, 51).

Fully implemented, but Ollama itself is NOT installed/pulled in this
environment per explicit instruction -- calls will raise AIUnavailableError
until a real Ollama server is running at OLLAMA_URL with OLLAMA_MODEL
pulled. Nothing in this module ever fabricates a response when the
connection fails.
"""
from __future__ import annotations

import httpx

from app.ai.exceptions import AIUnavailableError
from app.config import get_settings


class OllamaClient:
    def __init__(self, base_url: str | None = None, model: str | None = None, timeout: float = 60.0):
        settings = get_settings()
        self.base_url = base_url or settings.ollama_url
        self.model = model or settings.ollama_model
        self.timeout = timeout

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def generate(self, prompt: str, *, system: str | None = None, temperature: float = 0.2) -> str:
        """Single-turn generation against /api/generate."""
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=payload)
        except httpx.HTTPError as exc:
            raise AIUnavailableError(
                f"Could not reach Ollama at {self.base_url}. Install Ollama and run "
                f"`ollama pull {self.model}` to enable AI features. ({exc})"
            ) from exc

        if resp.status_code == 404:
            raise AIUnavailableError(
                f"Model '{self.model}' is not pulled on this Ollama instance. Run `ollama pull {self.model}`."
            )
        if resp.status_code != 200:
            raise AIUnavailableError(f"Ollama returned HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        return data.get("response", "")

    async def chat(self, messages: list[dict], *, temperature: float = 0.2) -> str:
        """Multi-turn chat against /api/chat -- used by the AI assistant."""
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise AIUnavailableError(f"Could not reach Ollama at {self.base_url}: {exc}") from exc

        if resp.status_code != 200:
            raise AIUnavailableError(f"Ollama returned HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        return data.get("message", {}).get("content", "")
