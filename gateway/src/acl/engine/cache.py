"""Content-hash verdict cache (concept §6.2: "verdicts are cached by content hash").

Only controls with `cacheable = True` are cached: their verdict must depend solely on the payload
text, the control's config, the policy version and the preset. The key therefore is

    (control id, policy version, preset, inspection point, sha256(field paths + texts))

Entries are bounded (LRU) and expire after `ttl_s`. Cached verdicts are returned as deep copies
with `status=cached` and zero latency.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict

from acl.contracts.common import VerdictStatus
from acl.contracts.decision import Verdict
from acl.contracts.inspection import InspectionContext
from acl.engine.text import iter_texts

CacheKey = tuple[str, str, str, str, str]


def payload_digest(ctx: InspectionContext) -> str:
    """sha256 over the (field, text) pairs the controls actually see (normalised payload if published)."""
    payload = ctx.attributes.get("payload", ctx.payload)
    if not hasattr(payload, "kind"):
        payload = ctx.payload
    h = hashlib.sha256()
    for field, text in iter_texts(payload):
        h.update(field.encode("utf-8"))
        h.update(b"\0")
        h.update(text.encode("utf-8", "surrogatepass"))
        h.update(b"\0")
    return h.hexdigest()


class VerdictCache:
    def __init__(self, max_entries: int = 4096, ttl_s: float = 300.0) -> None:
        self.max_entries = max(1, max_entries)
        self.ttl_s = ttl_s
        self._data: OrderedDict[CacheKey, tuple[float, Verdict]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._data)

    @staticmethod
    def key(control_id: str, policy_version: str, ctx: InspectionContext, digest: str | None = None) -> CacheKey:
        return (control_id, policy_version, str(ctx.preset), str(ctx.point), digest or payload_digest(ctx))

    def get(self, key: CacheKey) -> Verdict | None:
        item = self._data.get(key)
        if item is None:
            self.misses += 1
            return None
        stored_at, verdict = item
        if self.ttl_s and time.monotonic() - stored_at > self.ttl_s:
            del self._data[key]
            self.misses += 1
            return None
        self._data.move_to_end(key)
        self.hits += 1
        hit = verdict.model_copy(deep=True)
        hit.status = VerdictStatus.cached
        hit.latency_ms = 0.0
        return hit

    def put(self, key: CacheKey, verdict: Verdict) -> None:
        if verdict.status != VerdictStatus.ok:  # never cache timeouts / errors
            return
        self._data[key] = (time.monotonic(), verdict.model_copy(deep=True))
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)

    def clear(self) -> None:
        self._data.clear()

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0
