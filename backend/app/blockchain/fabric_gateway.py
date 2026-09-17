"""HTTP client to the Fabric gateway sidecar (blockchain/gateway-service).

This is the ONLY place in the Python codebase that talks to Hyperledger
Fabric, and it does so indirectly -- Fabric's officially-supported client
SDKs are Go/Node/Java, so the actual `@hyperledger/fabric-gateway` calls
live in the Node sidecar (blockchain/gateway-service). This module just
does HTTP request/response against that internal-only service.
"""
from __future__ import annotations

import httpx

from app.blockchain.exceptions import BlockchainUnavailableError
from app.config import get_settings


class FabricGateway:
    def __init__(self, base_url: str | None = None, timeout: float = 8.0):
        settings = get_settings()
        self.base_url = base_url or settings.fabric_gateway_sidecar_url
        self.channel = settings.fabric_channel
        self.chaincode = settings.fabric_chaincode
        self.timeout = timeout

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.base_url}/health")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def submit_transaction(self, function_name: str, args: list[str]) -> dict:
        """Submits (writes) a transaction to the ledger via the sidecar."""
        payload = {"channel": self.channel, "chaincode": self.chaincode, "function": function_name, "args": args}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/invoke", json=payload)
        except httpx.HTTPError as exc:
            raise BlockchainUnavailableError(f"Fabric gateway sidecar unreachable: {exc}") from exc

        if resp.status_code != 200:
            raise BlockchainUnavailableError(f"Fabric gateway sidecar returned {resp.status_code}: {resp.text}")
        return resp.json()

    async def evaluate_transaction(self, function_name: str, args: list[str]) -> dict:
        """Evaluates (reads) a transaction without committing to the ledger."""
        payload = {"channel": self.channel, "chaincode": self.chaincode, "function": function_name, "args": args}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/query", json=payload)
        except httpx.HTTPError as exc:
            raise BlockchainUnavailableError(f"Fabric gateway sidecar unreachable: {exc}") from exc

        if resp.status_code != 200:
            raise BlockchainUnavailableError(f"Fabric gateway sidecar returned {resp.status_code}: {resp.text}")
        return resp.json()
