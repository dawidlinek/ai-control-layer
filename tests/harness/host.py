"""Session-wide engine host: runs the real app lifespan on a dedicated background event loop.

The case runner must evaluate against the same wiring the service uses (installers, control deps such
as the vault and signature store, DB, hot-reloaded engine), not a hand-built `Engine`. The app's
resources (SQLAlchemy async engine, background tasks) are bound to one event loop, so the host owns a
loop in a daemon thread for the whole pytest session and everything that touches the app is submitted
to it with `host.run(coro)`. Test code stays synchronous.

If the app fails to start, the host falls back to `Engine.build(policy)` and says so loudly (a warning,
the terminal summary and `summary.json`'s `extra.engine_host`), so a broken installer can never silently
turn the suite into a test of a different system.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import tempfile
import threading
import warnings
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar

import httpx

from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext
from acl.engine.engine import Engine
from acl.main import create_app
from acl.policy.loader import load_policy_dir
from acl.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
T = TypeVar("T")
log = logging.getLogger("acl.tests.host")


class EngineHost:
    def __init__(
        self,
        *,
        deterministic: bool = True,
        policy_dir: Path | None = None,
        installers: list[str] | None = None,
        allow_anonymous_dev: bool = True,
    ) -> None:
        self.deterministic = deterministic
        self.policy_dir = policy_dir or ROOT / "policy"
        self.installers = installers
        self.allow_anonymous_dev = allow_anonymous_dev
        self.app: Any = None
        self.mode = "stopped"  # "app" | "fallback" | "stopped"
        self.fallback_reason: str | None = None
        self._fallback_engine: Engine | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lifespan: Any = None

    # ---------------------------------------------------------------- loop plumbing

    def _start_loop(self) -> None:
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def _run() -> None:
            asyncio.set_event_loop(loop)
            loop.call_soon(ready.set)
            loop.run_forever()

        self._loop = loop
        self._thread = threading.Thread(target=_run, name="acl-test-host-loop", daemon=True)
        self._thread.start()
        ready.wait(10)

    def run(self, coro: Coroutine[Any, Any, T], timeout: float = 60.0) -> T:
        """Run a coroutine on the host loop and wait for its result (call from test threads only)."""
        if self._loop is None:
            raise RuntimeError("EngineHost is not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    # ---------------------------------------------------------------- lifecycle

    def start(self) -> EngineHost:
        if self.mode != "stopped":
            return self
        self._start_loop()
        self._tmp = tempfile.TemporaryDirectory(prefix="acl-tests-", ignore_cleanup_errors=True)
        tmp = Path(self._tmp.name)
        try:
            settings = Settings(
                policy_dir=self.policy_dir,
                deterministic=self.deterministic,
                database_url=f"sqlite+aiosqlite:///{(tmp / 'acl.db').as_posix()}",
                audit_path=tmp / "audit.jsonl",
                feed_url=None,
            )
            app = create_app(settings, allow_anonymous_dev=self.allow_anonymous_dev, installers=self.installers)
            self._lifespan = app.router.lifespan_context(app)
            self.run(self._lifespan.__aenter__(), timeout=120)
            if app.state.engine is None:
                raise RuntimeError("app started but built no engine (policy load failed?)")
            self.app = app
            self.mode = "app"
        except Exception as exc:
            self._enter_fallback(f"{type(exc).__name__}: {exc}")
        return self

    def _enter_fallback(self, reason: str) -> None:
        self.fallback_reason = reason
        warnings.warn(
            f"ACL test harness: app lifespan failed ({reason}); FALLING BACK to a bare Engine.build(policy). "
            "Controls that need installer-provided services (vault, signatures, ...) may be missing.",
            RuntimeWarning,
            stacklevel=3,
        )
        loaded = load_policy_dir(self.policy_dir)
        self._fallback_engine = Engine.build(loaded.policy, loaded.version)
        self.app = None
        self.mode = "fallback"

    def stop(self) -> None:
        if self.mode == "stopped":
            return
        try:
            if self._lifespan is not None and self.mode == "app":
                self.run(self._lifespan.__aexit__(None, None, None), timeout=30)
            elif self._fallback_engine is not None:
                self.run(self._fallback_engine.aclose(), timeout=30)
        except Exception:
            log.exception("host shutdown failed")
        finally:
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._loop.stop)
                if self._thread is not None:
                    self._thread.join(5)
                if not self._loop.is_running():
                    self._loop.close()
            if self._tmp is not None:
                self._tmp.cleanup()
            self.mode = "stopped"
            self.app = None

    # ---------------------------------------------------------------- use

    @property
    def engine(self) -> Engine:
        """The current engine (re-read each time: policy hot reload swaps the instance)."""
        if self.mode == "app":
            return self.app.state.engine
        if self._fallback_engine is None:
            raise RuntimeError("EngineHost is not started")
        return self._fallback_engine

    def evaluate(self, ctx: InspectionContext) -> Decision:
        return self.run(self.engine.evaluate(ctx), timeout=60)

    def async_client(self, **kw: Any) -> httpx.AsyncClient:
        """In-process client for the app. Create it and use it inside a coroutine run via `host.run`."""
        if self.app is None:
            raise RuntimeError("no app available (host is in fallback mode)")
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://acl.test", **kw)

    def info(self) -> dict[str, Any]:
        eng = self.engine
        return {
            "mode": self.mode,
            "fallback_reason": self.fallback_reason,
            "deterministic": self.deterministic,
            "policy_version": eng.policy_version,
            "controls_enabled": [c.id for c in eng.pipeline.controls],
            "installers": self.installers if self.installers is not None else "acl.main.INSTALLERS",
        }


_HOST: EngineHost | None = None
_LOCK = threading.Lock()


def get_host(*, deterministic: bool | None = None) -> EngineHost:
    """The session-wide host (started on first use)."""
    global _HOST
    with _LOCK:
        if _HOST is None:
            if deterministic is None:
                import os

                deterministic = os.environ.get("ACL_TEST_MODE", "deterministic") != "live"
            _HOST = EngineHost(deterministic=deterministic).start()
            atexit.register(shutdown_host)
        return _HOST


def shutdown_host() -> None:
    global _HOST
    with _LOCK:
        host, _HOST = _HOST, None
    if host is not None:
        host.stop()


def host_if_started() -> EngineHost | None:
    return _HOST
