"""Policy service options (environment `ACL_POLICY_*`). Kept here, not in `acl.settings` (contract-owned)."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def running_in_container() -> bool:
    return Path("/.dockerenv").exists() or "KUBERNETES_SERVICE_HOST" in os.environ


class PolicyOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACL_POLICY_", env_file=None, extra="ignore")

    watch: bool = True
    force_polling: bool | None = None
    """None = auto: poll inside containers (bind mounts from a Windows/macOS host deliver no inotify events),
    native OS notifications elsewhere. Set `ACL_POLICY_FORCE_POLLING=true|false` to override."""
    poll_delay_ms: int = 300
    debounce_ms: int = 200
    step_ms: int = 50
    settle_ms: int = 150
    """A failed file-triggered reload is re-read once after this delay (editors that save non-atomically)."""
    rescan_interval_s: float = 5.0
    """Safety net: re-read the directory this often even if no event arrived (0 disables)."""
    retire_grace_s: float = 30.0
    """How long a replaced Engine stays open for in-flight requests before `aclose()`."""
    snapshot_timeout_s: float = 5.0
    dry_run_concurrency: int = 8
    dry_run_samples: int = 50

    def effective_force_polling(self) -> bool:
        return running_in_container() if self.force_polling is None else self.force_polling
