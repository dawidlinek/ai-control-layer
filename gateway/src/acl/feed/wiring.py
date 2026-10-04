"""Wiring for the signature feed: store (control dep `signatures`), poller, admin state."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI

from acl.feed.admin import FeedAdminClient, admin_base
from acl.feed.store import SignatureStore
from acl.feed.sync import FeedConfig, FeedSync
from acl.policy.env import resolve
from acl.policy.loader import PolicyLoadError, load_policy_dir
from acl.policy.models import Policy
from acl.settings import Settings

log = logging.getLogger(__name__)


def _startup_policy(settings: Settings) -> Policy | None:
    """Startup hooks run before the first engine exists: read the policy directory directly."""
    try:
        return load_policy_dir(settings.policy_dir).policy
    except (PolicyLoadError, OSError):
        return None


def feed_config(app: FastAPI, settings: Settings) -> FeedConfig | None:
    """Feed location: `ACL_FEED_URL` (deployment) overrides `signatures.feed.url` of the live policy."""
    engine = getattr(app.state, "engine", None)
    policy = engine.policy if engine is not None else _startup_policy(settings)
    feed = policy.signatures.feed if policy is not None else None
    url = settings.feed_url or (resolve(feed.url, required=False) if feed else None)
    if not url:
        return None
    return FeedConfig(
        url=url,
        poll_s=float(feed.poll_s) if feed else 30.0,
        verify=feed.verify if feed else "sha256",
        public_key=resolve(feed.public_key, required=False) if feed else None,
    )


def install(app: FastAPI, settings: Settings) -> None:
    store = SignatureStore(settings.feed_url)
    sync = FeedSync(
        store,
        config=lambda: feed_config(app, settings),
        audit=lambda: getattr(app.state, "audit", None),
    )

    def admin_url() -> str | None:
        cfg = feed_config(app, settings)
        return admin_base(cfg.url if cfg else None, settings.feed_admin_url)

    def admin_token() -> str | None:
        return settings.feed_admin_token.get_secret_value() if settings.feed_admin_token else None

    app.state.feed_admin = FeedAdminClient(admin_url, admin_token)
    app.state.feed_store = store
    app.state.feed_sync = sync
    app.state.control_deps.register("signatures", store)
    if app.state.control_deps.get("settings") is None:
        app.state.control_deps.register("settings", settings)

    async def start(_app: FastAPI) -> None:
        if settings.deterministic:  # tests / offline demo: no background polling (manual sync still works)
            return
        # Best effort first sync so the bundle is active before the first request; never block startup long.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(sync.sync_once(), timeout=2.0)
        sync.start()

    async def stop(_app: FastAPI) -> None:
        await sync.stop()

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
