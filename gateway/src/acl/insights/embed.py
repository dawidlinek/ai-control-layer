"""Embeddings for mining: the policy's `routing.targets.embeddings` model through the gateway's own connectors.

Only a **local-tier** model may embed employee prompts (embeddings are outbound data); a cloud target is refused.
In deterministic mode (tests, demo without a model server) `HashingEmbedder` is used instead: a stable hashed
bag of words + bigrams, so structurally similar prompts land close together and test clusters are known.
"""

from __future__ import annotations

import hashlib
import itertools
import math
import re
from collections import OrderedDict
from typing import Any, Protocol

from acl.contracts.common import ConnectorTier

_TOKEN = re.compile(r"<[a-z_]+?(?:_\d+)?>|\[redacted:[a-z_]+\]|[^\W\d_]+|\d+(?:[.,\s]\d+)*", re.I)
_PLACEHOLDER = re.compile(r"^<([a-z_]+?)(?:_\d+)?>$|^\[redacted:([a-z_]+)\]$", re.I)


class InsightsError(RuntimeError):
    """The pipeline cannot run safely (e.g. the embeddings or drafting model is not local)."""


class Embedder(Protocol):
    name: str
    mode: str

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


def tokens(text: str) -> list[str]:
    """Lower-cased word tokens; pseudonyms (`<PERSON_1>`) and masks collapse to their entity type, numbers to `#`."""
    out: list[str] = []
    for raw in _TOKEN.findall(text):
        m = _PLACEHOLDER.match(raw)
        if m:
            out.append(f"<{(m.group(1) or m.group(2)).lower()}>")
        elif raw[0].isdigit():
            out.append("#")
        else:
            out.append(raw.lower())
    return out


def _bucket(feature: str, dim: int) -> tuple[int, float]:
    n = int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest(), "big")
    return n % dim, (1.0 if (n >> 63) & 1 else -1.0)


def normalise(vec: list[float]) -> list[float]:
    norm = math.sqrt(sum(v * v for v in vec))
    return [v / norm for v in vec] if norm else vec


class HashingEmbedder:
    """Deterministic, dependency-free text embedding (feature hashing of unigrams and bigrams).

    The first line usually carries the instruction ("Summarise this loan application…") while the rest is the
    variable material, so first-line features weigh `first_line_weight` times more."""

    mode = "deterministic"

    def __init__(self, dim: int = 512, first_line_weight: float = 3.0) -> None:
        self.dim = dim
        self.first_line_weight = first_line_weight
        self.name = f"hashing-{dim}"

    def vector(self, text: str) -> list[float]:
        counts: dict[str, float] = {}
        for n, line in enumerate(text.strip().splitlines()):
            w = self.first_line_weight if n == 0 else 1.0
            toks = tokens(line)
            for t in toks:
                counts[t] = counts.get(t, 0.0) + w
            for a, b in itertools.pairwise(toks):
                counts[f"{a} {b}"] = counts.get(f"{a} {b}", 0.0) + w
        vec = [0.0] * self.dim
        for feat, c in counts.items():
            i, sign = _bucket(feat, self.dim)
            vec[i] += sign * math.sqrt(c)
        return normalise(vec)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self.vector(t) for t in texts]


class ConnectorEmbedder:
    """Calls the embeddings target through the connector registry (same connectors as user traffic)."""

    mode = "connector"
    batch = 64

    def __init__(self, app: Any) -> None:
        self.app = app
        self.name = "unresolved"

    def _resolve(self) -> tuple[Any, str]:
        engine = self.app.state.engine
        if engine is None:
            raise InsightsError("policy not loaded")
        policy = engine.policy
        ref = policy.routing.targets.embeddings
        if not ref:
            raise InsightsError("routing.targets.embeddings is not set")
        entry = policy.model_by_id().get(ref) or next((m for m in policy.models if ref in m.aliases), None)
        if entry is None:
            raise InsightsError(f"embeddings target {ref!r} is not a model")
        if policy.connectors[entry.connector].tier != ConnectorTier.local:
            raise InsightsError("the embeddings target is not a local model; refusing to embed employee prompts")
        table = self.app.state.connectors.table_for(policy, engine.policy_version)
        problem = table.model_problem(entry.id) or table.connector_problem(entry.connector)
        handle = table.models.get(entry.id)
        connector = table.connector_for(entry.id)
        if problem or connector is None or handle is None or not handle.upstream_model:
            raise InsightsError(f"embeddings model {entry.id} unavailable: {problem or 'no connector'}")
        self.name = entry.id
        return connector, handle.upstream_model

    async def embed(self, texts: list[str]) -> list[list[float]]:
        connector, upstream = self._resolve()
        out: list[list[float]] = []
        for i in range(0, len(texts), self.batch):
            chunk = texts[i : i + self.batch]
            resp = await connector.embeddings(upstream, {"model": upstream, "input": chunk})
            data = sorted(resp.body.get("data") or [], key=lambda d: d.get("index", 0))
            if len(data) != len(chunk):
                raise InsightsError("embeddings response has the wrong number of vectors")
            out.extend(normalise([float(x) for x in d["embedding"]]) for d in data)
        return out


class CachedEmbedder:
    """Bounded LRU in front of an embedder: a recompute only embeds prompts it has not seen."""

    def __init__(self, inner: Embedder, max_entries: int = 20000) -> None:
        self.inner = inner
        self.max_entries = max_entries
        self._cache: OrderedDict[tuple[str, str], list[float]] = OrderedDict()

    @property
    def name(self) -> str:
        return self.inner.name

    @property
    def mode(self) -> str:
        return self.inner.mode

    async def embed(self, texts: list[str]) -> list[list[float]]:
        keys = [hashlib.sha256(t.encode("utf-8")).hexdigest() for t in texts]
        first: dict[str, int] = {}
        for i, k in enumerate(keys):
            first.setdefault(k, i)
        missing = sorted(i for k, i in first.items() if (self.inner.name, k) not in self._cache)
        if missing:
            vectors = await self.inner.embed([texts[i] for i in missing])
            for i, v in zip(missing, vectors, strict=True):
                self._cache[(self.inner.name, keys[i])] = v
        out = []
        for k in keys:
            ck = (self.inner.name, k)
            self._cache.move_to_end(ck)
            out.append(self._cache[ck])
        while len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)
        return out


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


def centroid(vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    acc = [0.0] * len(vectors[0])
    for v in vectors:
        for i, x in enumerate(v):
            acc[i] += x
    return normalise(acc)
