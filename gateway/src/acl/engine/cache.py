"""Content-hash verdict cache (concept §6.2: "verdicts are cached by content hash").

Only controls with `cacheable = True` are cached: their verdict must depend solely on the payload,
the control's config, the policy version and the preset. The key therefore is

    (control id, policy version, preset, inspection point, sha256(canonical JSON of the FULL payload))

The digest covers everything a cacheable control can read about the payload: the original payload
(every field, not only the inspected text: tools, content parts, params, message names, ...), the
normalised payload published by SEC-NORM-01 and its decoded views. Two requests that differ in any byte
never share an entry (CP1 finding: keying on text alone replayed one user's normalised payload, incl.
image parts and tools, into another user's request).

Verdicts that carry `outputs` (data for later phases, e.g. a normalised payload) are never cached and
never replayed: outputs are request-specific by nature. Entries are bounded (LRU) and expire after
`ttl_s`. Cached verdicts are returned as deep copies with `status=cached` and zero latency.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import OrderedDict
from typing import Any

from pydantic import BaseModel

from acl.contracts.canonical import canonical_json
from acl.contracts.common import VerdictStatus
from acl.contracts.decision import Verdict
from acl.contracts.inspection import InspectionContext

CacheKey = tuple[str, str, str, str, str]


def _dump(obj: Any) -> Any:
    return obj.model_dump(mode="json") if isinstance(obj, BaseModel) else None


def payload_digest(ctx: InspectionContext) -> str:
    """sha256 over the canonical JSON of the full original payload, the normalised payload and decoded views."""
    normalised = ctx.attributes.get("payload")
    if getattr(normalised, "kind", None) != ctx.payload.kind:
        normalised = None
    material = {
        "payload": _dump(ctx.payload),
        "normalised": _dump(normalised),
        "views": ctx.attributes.get("decoded_views") or [],
    }
    try:
        blob = canonical_json(material).encode("utf-8", "surrogatepass")
    except (TypeError, ValueError):
        # Not canonically serialisable: never share an entry (a unique digest is a guaranteed miss).
        return f"uncacheable-{uuid.uuid4().hex}"
    return hashlib.sha256(blob).hexdigest()


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
        hit.outputs = {}  # defensive: outputs are never replayed (`put` refuses them anyway)
        return hit

    def put(self, key: CacheKey, verdict: Verdict) -> None:
        if verdict.status != VerdictStatus.ok:  # never cache timeouts / errors
            return
        if verdict.outputs:  # request-specific data for later phases: never cache, never replay
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
