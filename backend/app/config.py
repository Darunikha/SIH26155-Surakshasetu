"""Central application settings, loaded from environment variables / .env.

No secret ever has a hard-coded default here -- absence just means the
corresponding subsystem reports itself as unavailable rather than the app
pretending to be configured.
"""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    cors_origins: str = "http://localhost:3000"

    # MongoDB
    mongodb_uri: str = ""
    mongodb_db_name: str = "sih26155"

    # Pinecone
    pinecone_api_key: str = ""
    pinecone_index_name: str = "security-knowledge-base"
    pinecone_cloud: str = "aws"
    pinecone_region: str = "us-east-1"

    # Auth
    jwt_secret: str = "insecure-dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = 60

    # Ollama (local LLM)
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b-instruct"

    # Hyperledger Fabric gateway sidecar
    fabric_gateway_sidecar_url: str = "http://localhost:4001"
    fabric_channel: str = "securityaudit"
    fabric_chaincode: str = "security-audit-chaincode"
    fabric_msp_id: str = "Org1MSP"

    # File storage
    upload_storage_dir: str = "./storage/uploads"
    max_upload_size_mb: int = 20

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def upload_storage_path(self) -> Path:
        p = Path(self.upload_storage_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()
