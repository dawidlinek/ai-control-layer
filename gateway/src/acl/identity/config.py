"""Identity options (environment `ACL_*`). Kept here, not in `acl.settings` (contract-owned)."""

from __future__ import annotations

from datetime import timedelta

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class IdentityOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACL_", env_file=None, extra="ignore")

    api_key_max_group_age_days: float = Field(default=30.0, gt=0)
    """`ACL_API_KEY_MAX_GROUP_AGE_DAYS`: an API key is refused (401 `stale_identity`) when its owner's groups were
    last refreshed by a Keycloak sign-in longer ago than this. Keys never refresh groups themselves."""

    @property
    def api_key_max_group_age(self) -> timedelta:
        return timedelta(days=self.api_key_max_group_age_days)
