"""Connector registry: policy → live connectors, availability, kill switch, simple health stats.

`ConnectorRegistry` lives for the whole process (`app.state.connectors`); it outlives policy
reloads, so the in-memory kill switch survives them. `table_for(policy, version)` builds (and caches)
a `RoutingTable` for one compiled policy. Connector instances are reused across policy versions while
their config is unchanged.

Deterministic mode (`settings.deterministic`): every connector is a `MockConnector` that keeps the
policy's tier, and upstream model names are the model ids (so output is stable).
"""

from __future__ import annotations

import logging
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from acl.policy.env import MissingEnv, is_ref, resolve
from acl.policy.models import ConnectorConfig, ModelEntry, Policy
from acl.routing.connectors.base import Connector
from acl.routing.connectors.mock import MockConnector
from acl.routing.connectors.ollama import OllamaConnector
from acl.routing.connectors.openai_compatible import OpenAICompatibleConnector

log = logging.getLogger(__name__)

_MAX_TABLES = 4


@dataclass
class KillSwitch:
    reason: str
    by: str | None
    at: float = field(default_factory=time.time)


@dataclass
class ConnectorHandle:
    id: str
    config: ConnectorConfig
    connector: Connector | None
    unavailable: str | None = None  # e.g. "env LOCAL_LLM_BASE_URL is not set"


@dataclass
class ModelHandle:
    entry: ModelEntry
    upstream_model: str | None
    unavailable: str | None = None

    @property
    def id(self) -> str:
        return self.entry.id


@dataclass
class RoutingTable:
    version: str
    policy: Policy
    registry: ConnectorRegistry
    connectors: dict[str, ConnectorHandle]
    models: dict[str, ModelHandle]

    def connector_problem(self, connector_id: str) -> str | None:
        """Why a connector cannot take traffic right now (None = usable)."""
        h = self.connectors.get(connector_id)
        if h is None:
            return "unknown connector"
        if self.registry.is_killed(connector_id):
            return "kill switch engaged"
        if not h.config.enabled:
            return "connector disabled"
        return h.unavailable

    def model_problem(self, model_id: str) -> str | None:
        m = self.models.get(model_id)
        if m is None:
            return "unknown model"
        if not m.entry.enabled:
            return "model disabled"
        gate = getattr(self.registry, "artifact_gate", None)
        if gate is not None and (problem := gate(m.entry)) is not None:
            return problem
        return m.unavailable or self.connector_problem(m.entry.connector)

    def connector_for(self, model_id: str) -> Connector | None:
        m = self.models.get(model_id)
        h = self.connectors.get(m.entry.connector) if m else None
        return h.connector if h else None


class ConnectorRegistry:
    def __init__(self, *, deterministic: bool = False, environ: Mapping[str, str] | None = None) -> None:
        self.deterministic = deterministic
        self._environ = environ
        self._kills: dict[str, KillSwitch] = {}
        self._instances: dict[tuple[str, str], Connector] = {}
        self._latest: dict[str, Connector] = {}
        self._tables: dict[str, RoutingTable] = {}
        self._latencies: dict[str, deque[float]] = {}
        self._last_error: dict[str, str] = {}
        self._health: dict[str, tuple[float, bool]] = {}
        # 4A: returns why a model's artifact may not load (None = fine); consulted per request, never cached
        self.artifact_gate: Callable[[ModelEntry], str | None] | None = None

    # ------------------------------------------------------------ kill switch

    def set_kill_switch(self, connector_id: str, engaged: bool, reason: str, by: str | None = None) -> None:
        if engaged:
            self._kills[connector_id] = KillSwitch(reason=reason, by=by)
        else:
            self._kills.pop(connector_id, None)

    def is_killed(self, connector_id: str) -> bool:
        return connector_id in self._kills

    def kill_info(self, connector_id: str) -> KillSwitch | None:
        return self._kills.get(connector_id)

    # ------------------------------------------------------------ stats

    def record_success(self, connector_id: str, latency_ms: float) -> None:
        self._latencies.setdefault(connector_id, deque(maxlen=200)).append(latency_ms)

    def record_error(self, connector_id: str, message: str) -> None:
        self._last_error[connector_id] = message[:300]

    def last_error(self, connector_id: str) -> str | None:
        return self._last_error.get(connector_id)

    def latency_p50(self, connector_id: str) -> float | None:
        values = sorted(self._latencies.get(connector_id, ()))
        return values[len(values) // 2] if values else None

    async def healthy(self, connector_id: str, *, ttl_s: float = 15.0) -> bool | None:
        """Cached `Connector.health()`; None if the connector is not instantiated."""
        conn = self._latest.get(connector_id)
        if conn is None:
            return None
        cached = self._health.get(connector_id)
        if cached and time.monotonic() - cached[0] < ttl_s:
            return cached[1]
        try:
            ok = await conn.health()
        except Exception:
            ok = False
        self._health[connector_id] = (time.monotonic(), ok)
        return ok

    # ------------------------------------------------------------ building

    def get(self, connector_id: str) -> Connector | None:
        """Latest instance for a connector id (tests, health)."""
        return self._latest.get(connector_id)

    def table_for(self, policy: Policy, version: str) -> RoutingTable:
        table = self._tables.get(version)
        if table is not None:
            return table
        connectors = {cid: self._build_connector(cid, cfg) for cid, cfg in policy.connectors.items()}
        models = {m.id: self._build_model(m) for m in policy.models}
        table = RoutingTable(version=version, policy=policy, registry=self, connectors=connectors, models=models)
        self._tables[version] = table
        while len(self._tables) > _MAX_TABLES:
            self._tables.pop(next(iter(self._tables)))
        return table

    def _resolve(self, value: str | None) -> tuple[str | None, str | None]:
        """(resolved value, name of the unset env var)."""
        try:
            return resolve(value, self._environ, required=True), None
        except MissingEnv as exc:
            return None, exc.name

    def _build_connector(self, cid: str, cfg: ConnectorConfig) -> ConnectorHandle:
        key = (cid, cfg.model_dump_json())
        if self.deterministic:
            conn = self._instances.get(key) or MockConnector(cid)
            self._instances[key] = self._latest[cid] = conn
            return ConnectorHandle(cid, cfg, conn)

        base_url, missing = self._resolve(cfg.base_url)
        headers: dict[str, str] = {}
        for name, raw in cfg.headers.items():
            value, miss = self._resolve(raw)
            if miss:
                missing = missing or miss
            elif value is not None:
                headers[name] = value
        api_key = None
        if cfg.api_key:
            api_key, miss = self._resolve(cfg.api_key)
            if miss and cfg.tier.value == "cloud":  # a local server (Ollama, vLLM) may run without a key
                missing = missing or miss
        if cfg.type != "mock" and not base_url and not missing:
            missing = "base_url"
        if missing:
            self._latest.pop(cid, None)
            return ConnectorHandle(cid, cfg, None, f"env {missing} is not set")

        conn = self._instances.get(key)
        if conn is None:
            conn = self._make(cid, cfg, base_url or "", api_key, headers)
            self._instances[key] = conn
        self._latest[cid] = conn
        return ConnectorHandle(cid, cfg, conn)

    @staticmethod
    def _make(cid: str, cfg: ConnectorConfig, base_url: str, api_key: str | None, headers: dict[str, str]) -> Connector:
        if cfg.type == "openai_compatible":
            return OpenAICompatibleConnector(cid, base_url, api_key=api_key, headers=headers, timeout_s=cfg.timeout_s)
        if cfg.type == "ollama":
            hdrs = dict(headers)
            if api_key:
                hdrs["Authorization"] = f"Bearer {api_key}"
            return OllamaConnector(cid, base_url, headers=hdrs, timeout_s=cfg.timeout_s)
        return MockConnector(cid)

    def _build_model(self, entry: ModelEntry) -> ModelHandle:
        if self.deterministic:
            return ModelHandle(entry, entry.id)
        if not is_ref(entry.upstream_model):
            return ModelHandle(entry, entry.upstream_model)
        value, missing = self._resolve(entry.upstream_model)
        if missing:
            return ModelHandle(entry, None, f"env {missing} is not set")
        return ModelHandle(entry, value)

    async def aclose(self) -> None:
        for conn in self._instances.values():
            try:
                await conn.aclose()
            except Exception:
                log.exception("closing connector %s failed", conn.id)
        self._instances.clear()
