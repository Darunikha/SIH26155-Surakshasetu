"""MongoDB connection (motor async client) -- the operational source of
detailed application data (spec section 6). A single client is created at
app startup and reused for the process lifetime.
"""
from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import get_settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def connect() -> AsyncIOMotorDatabase:
    global _client, _db
    settings = get_settings()
    if not settings.mongodb_uri:
        raise RuntimeError("MONGODB_URI is not configured")
    _client = AsyncIOMotorClient(settings.mongodb_uri, uuidRepresentation="standard")
    _db = _client[settings.mongodb_db_name]
    return _db


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        return connect()
    return _db


def close() -> None:
    global _client, _db
    if _client is not None:
        _client.close()
    _client = None
    _db = None


# --- Collection name constants (single source of truth) ---
class Collections:
    USERS = "users"
    PROJECTS = "projects"
    DEVICES = "devices"
    CONFIGURATIONS = "configurations"
    CONFIGURATION_VERSIONS = "configuration_versions"
    SECURITY_IR = "security_ir"
    FINDINGS = "findings"
    COMPLIANCE_RESULTS = "compliance_results"
    RISK_SCORES = "risk_scores"
    ATTACK_GRAPHS = "attack_graphs"
    OPTIMIZER_RUNS = "optimizer_runs"
    REMEDIATION_PLANS = "remediation_plans"
    REMEDIATION_ACTIONS = "remediation_actions"
    AI_OUTPUTS = "ai_outputs"
    TRAINING_MAPPINGS = "training_mappings"
    TRAINING_EXAMPLES = "training_examples"
    UNKNOWN_PATTERNS = "unknown_patterns"
    REPORTS = "reports"
    AUDITS = "audits"
    AUDIT_LOG = "audit_log"
    BLOCKCHAIN_TRANSACTIONS = "blockchain_transactions"
    BLOCKCHAIN_PENDING_QUEUE = "blockchain_pending_queue"
    SCANS = "scans"
