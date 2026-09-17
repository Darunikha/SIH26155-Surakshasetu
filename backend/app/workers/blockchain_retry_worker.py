"""Background loop that retries queued blockchain transactions (spec
section 34). Started once at app startup; runs for the process lifetime."""
from __future__ import annotations

import asyncio
import logging

from app.blockchain.service import retry_pending_transactions
from app.db import get_db

logger = logging.getLogger("sih26155.blockchain.retry_worker")

_RETRY_INTERVAL_SECONDS = 30


async def run_forever() -> None:
    while True:
        try:
            db = get_db()
            result = await retry_pending_transactions(db)
            if result["retried"]:
                logger.info("Blockchain retry pass: %s", result)
        except Exception:
            logger.exception("Blockchain retry worker iteration failed")
        await asyncio.sleep(_RETRY_INTERVAL_SECONDS)
