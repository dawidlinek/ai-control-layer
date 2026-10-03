"""Process settings (environment). Policy lives in YAML; only deployment wiring and secrets live here."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACL_", env_file=None, extra="ignore")

    policy_dir: Path = Path("policy")
    database_url: str = "sqlite+aiosqlite:///./.acl-dev.db"
    audit_path: Path = Path("logs/audit.jsonl")
    deterministic: bool = Field(default=False, description="Force mock connectors and mocked model-based controls.")
    log_level: str = "INFO"

    oidc_issuer: str = "http://localhost:8180/realms/acl"
    oidc_jwks_url: str | None = Field(default=None, description="Internal JWKS URL; defaults to issuer certs.")
    oidc_audience: str = "gateway"

    feed_url: str | None = None
    value_hash_salt: SecretStr = SecretStr("dev-only-salt-change-me")
    api_key_pepper: SecretStr = SecretStr("dev-only-pepper-change-me")

    @property
    def jwks_url(self) -> str:
        return self.oidc_jwks_url or f"{self.oidc_issuer}/protocol/openid-connect/certs"


@lru_cache
def get_settings() -> Settings:
    return Settings()
