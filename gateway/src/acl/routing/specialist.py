"""Specialist routing for `auto` (strategy `specialist_then_rules`): kNN over a model's `specialist.examples`.

An admin-configurable routing rule is a `specialist` block on a model in `policy/models.yaml`:

    specialist: {task: polish_legal, min_confidence: 0.5, examples: ["...", "..."]}

`auto` compares the latest user message with every example of every enabled specialist and routes to the model of the
nearest example when the similarity reaches the model's `min_confidence` (`SpecialistConfig` defaults it to 0.8).

The similarity is deterministic and dependency-free (no embedding call, so it also works offline, in deterministic test
mode and without leaking the prompt to any model): the text is lower-cased, diacritics are stripped, stop words dropped
and each remaining word is cut to a 4-character stem (a crude stemmer that copes with Polish inflection:
"umowy" / "umowie" / "umowa" → "umow"). Bags of stems are compared with cosine similarity. The latest user message is
scanned in short sliding windows, so a one-line instruction followed by a long pasted contract still matches on the
instruction, and the best window counts. The score is a lexical overlap, not a semantic one: paraphrases that share no
vocabulary with any example do not match (they fall through to the sensitivity × complexity rules).

Only text goes in; nothing is logged or stored, and the audited route reason cites the task and the score only.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from acl.contracts.inspection import ChatPayload, Payload
from acl.policy.models import ModelEntry, Policy

_STEM = 4
_WINDOW = 14
_STRIDE = 7
_MAX_TOKENS = 600
_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "are",
        "was",
        "were",
        "have",
        "has",
        "not",
        "you",
        "your",
        "can",
        "will",
        "what",
        "how",
        "why",
        "who",
        "which",
        "when",
        "where",
        "czy",
        "jak",
        "jest",
        "sie",
        "oraz",
        "dla",
        "pod",
        "nad",
        "przy",
        "tego",
        "tej",
        "ten",
        "ale",
        "lub",
        "albo",
        "ktory",
        "ktora",
        "ktore",
        "tym",
        "tych",
        "jego",
        "jej",
        "ich",
        "nie",
        "tak",
        "juz",
        "byc",
        "moze",
        "mozna",
        "prosze",
        "mnie",
        "mam",
        "chce",
        "potrzebuje",
        "napisz",
        "zrob",
        "podaj",
    }
)


# two-letter abbreviations that carry meaning in legal text (kc, kk, kp, sn, ue)
_SHORT_TERMS = frozenset({"kc", "kk", "kp", "kw", "sn", "ue"})


def _fold(text: str) -> str:
    text = text.lower().replace("ł", "l")
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def stems(text: str) -> list[str]:
    out: list[str] = []
    for tok in _TOKEN.findall(_fold(text)):
        if tok in _STOP or (len(tok) < 3 and tok not in _SHORT_TERMS):
            continue
        out.append(tok[:_STEM])
        if len(out) >= _MAX_TOKENS:
            break
    return out


def _vector(tokens: list[str]) -> tuple[Counter[str], float]:
    c = Counter(tokens)
    return c, math.sqrt(sum(v * v for v in c.values()))


def _cosine(a: tuple[Counter[str], float], b: tuple[Counter[str], float]) -> float:
    (ca, na), (cb, nb) = a, b
    if not na or not nb:
        return 0.0
    if len(ca) > len(cb):
        ca, cb = cb, ca
    return sum(v * cb.get(k, 0) for k, v in ca.items()) / (na * nb)


def last_user_text(payload: Payload) -> str:
    """Text of the latest user message of a chat payload ("" for anything else)."""
    if not isinstance(payload, ChatPayload):
        return ""
    for m in reversed(payload.messages):
        if m.role != "user":
            continue
        c = m.content
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return "\n".join(p["text"] for p in c if isinstance(p, dict) and isinstance(p.get("text"), str))
        return ""
    return ""


@dataclass(frozen=True)
class SpecialistMatch:
    model_id: str
    task: str
    confidence: float
    threshold: float


class SpecialistIndex:
    """Example vectors of every model that declares `specialist.examples` (built once per policy)."""

    def __init__(self, policy: Policy) -> None:
        self._entries: list[tuple[ModelEntry, float, list[tuple[Counter[str], float]]]] = []
        for m in policy.models:
            sp = m.specialist
            if sp is None or not sp.examples:
                continue
            vecs = [_vector(stems(e)) for e in sp.examples]
            self._entries.append((m, sp.min_confidence, [v for v in vecs if v[1]]))

    def __bool__(self) -> bool:
        return bool(self._entries)

    def candidates(self, text: str) -> list[SpecialistMatch]:
        """Every specialist whose best example reaches its threshold, best first (stable for ties)."""
        tokens = stems(text)
        if not tokens or not self._entries:
            return []
        windows = [tokens] if len(tokens) <= _WINDOW else []
        windows += [tokens[i : i + _WINDOW] for i in range(0, max(1, len(tokens) - _WINDOW + _STRIDE), _STRIDE)]
        vecs = [_vector(w) for w in windows]
        found: list[SpecialistMatch] = []
        for m, threshold, examples in self._entries:
            best = max((_cosine(w, e) for w in vecs for e in examples), default=0.0)
            assert m.specialist is not None
            if best >= threshold:
                found.append(SpecialistMatch(m.id, m.specialist.task, round(best, 3), threshold))
        found.sort(key=lambda x: -x.confidence)
        return found
