from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api import assistant as assistant_api
from app.api import auth as auth_api
from app.api import blockchain as blockchain_api
from app.api import configurations as configurations_api
from app.api import dashboard as dashboard_api
from app.api import devices as devices_api
from app.api import findings as findings_api
from app.api import optimizer as optimizer_api
from app.api import projects as projects_api
from app.api import remediation as remediation_api
from app.api import reports as reports_api
from app.api import scans as scans_api
from app.api import training as training_api
from app.config import get_settings
from app.db import close as db_close
from app.db import connect as db_connect
from app.schemas.common import AppError, ErrorCode, fail
from app.utils.ids import new_request_id

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sih26155")

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

app = FastAPI(title="SurakshaSetu Security Compliance Auditor API", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    request.state.request_id = new_request_id()
    response = await call_next(request)
    response.headers["X-Request-Id"] = request.state.request_id
    # Secure headers (spec section 50).
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    request_id = getattr(request.state, "request_id", new_request_id())
    logger.warning("AppError %s: %s (request_id=%s)", exc.code.value, exc.message, request_id)
    return JSONResponse(status_code=exc.status_code, content=fail(exc.code, exc.message, request_id))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", new_request_id())
    logger.exception("Unhandled exception (request_id=%s)", request_id)
    return JSONResponse(
        status_code=500,
        content=fail(ErrorCode.INTERNAL_ERROR, "An unexpected error occurred", request_id),
    )


@app.on_event("startup")
async def on_startup() -> None:
    db_connect()
    logger.info("Connected to MongoDB (app_env=%s)", settings.app_env)
    from app.workers.blockchain_retry_worker import run_forever as blockchain_retry_forever

    app.state.blockchain_retry_task = asyncio.create_task(blockchain_retry_forever())


@app.on_event("shutdown")
async def on_shutdown() -> None:
    task = getattr(app.state, "blockchain_retry_task", None)
    if task:
        task.cancel()
    db_close()


@app.get("/health")
async def health():
    return {"status": "ok", "app_env": settings.app_env}


app.include_router(auth_api.router)
app.include_router(projects_api.router)
app.include_router(devices_api.router)
app.include_router(configurations_api.router)
app.include_router(scans_api.router)
app.include_router(optimizer_api.router)
app.include_router(blockchain_api.router)
app.include_router(findings_api.router)
app.include_router(remediation_api.router)
app.include_router(reports_api.router)
app.include_router(training_api.router)
app.include_router(assistant_api.router)
app.include_router(dashboard_api.router)
