"""Process-level insights options (environment, prefix `ACL_INSIGHTS_`). Per-group opt-in and k live in the DB."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class InsightsOptions(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ACL_INSIGHTS_", env_file=None, extra="ignore")

    worker: bool = Field(default=True, description="Run the background recompute loop.")
    interval_s: float = Field(default=3600.0, ge=10.0)
    initial_delay_s: float = Field(default=60.0, ge=0.0)

    k: int = Field(default=5, ge=2, description="Default k (distinct users) until an admin changes it.")
    window_days: int = Field(default=30, ge=1)
    enabled_groups: list[str] = Field(default_factory=list, description="Groups opted in until set in the panel.")
    personal_groups: list[str] = Field(default_factory=list)

    min_cluster_size: int = Field(default=5, ge=2)
    personal_min_cluster_size: int = Field(default=3, ge=2)
    max_prompts_per_group: int = Field(default=3000, ge=10)
    max_text_chars: int = Field(default=2000, ge=100)
    max_examples: int = Field(default=3, ge=0, le=10)
    retry_window_s: float = Field(default=600.0, description="A near-identical prompt within this time is a retry.")
    retry_similarity: float = Field(default=0.9)
    specialist_similarity: float = Field(default=0.35, description="Specialist counts as adequate above this cosine.")

    seed_dir: Path | None = Field(default=None, description="Demo history (`deploy/seed/insights`); never audited.")
    draft_with_llm: bool = Field(default=True, description="Ask the local LLM for drafts (else deterministic only).")
    drafter_timeout_s: float = Field(default=60.0, gt=0)
