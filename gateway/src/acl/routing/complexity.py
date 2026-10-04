"""Deterministic request complexity (0..1) for `auto` routing between the fast and the strong cloud model.

No model is involved (HANDOFF §7.8: Flash vs Pro vs local = rules + bands). The score only chooses *which permitted*
model serves a request; sensitivity, org locks, grants and `route_local` obligations are applied by the router before
and after it, so complexity can never send data anywhere it was not already allowed to go.

Signals (each capped, summed, clipped to 1.0), measured on the latest user turn plus a light history term:
  * length of the latest user message (≈ tokens / 2000, up to 0.45)
  * code blocks and multi-file / multi-step structure (up to 0.25)
  * reasoning-heavy wording ("step by step", "prove", "architecture", "trade-offs", ...) (up to 0.25)
  * conversation depth (number of prior turns, up to 0.1)
"""

from __future__ import annotations

import re

from acl.contracts.inspection import ChatPayload, Payload

_HEAVY = re.compile(
    r"\b(step[- ]by[- ]step|prove|proof|derive|architecture|design (?:a|the) system|trade-?offs?|refactor|"
    r"migrat\w+|threat model|root cause|optimi[sz]e|compare (?:and|&) contrast|in depth|detailed analysis|"
    r"multi-?step|algorithm|complexity analysis|formal)\b",
    re.IGNORECASE,
)
_FENCE = re.compile(r"```")
_LIST_ITEM = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s+", re.MULTILINE)


def _text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        return "\n".join(parts)
    return ""


def estimate_complexity(payload: Payload) -> float:
    """0 = trivial, 1 = very complex. Non-chat payloads score 0 (embeddings never go to a chat model)."""
    if not isinstance(payload, ChatPayload) or not payload.messages:
        return 0.0
    user_turns = [m for m in payload.messages if m.role == "user"]
    last = _text(user_turns[-1].content) if user_turns else ""
    score = min(0.45, (len(last) / 4) / 2000 * 0.45)
    fences = len(_FENCE.findall(last)) // 2
    items = len(_LIST_ITEM.findall(last))
    score += min(0.25, 0.08 * fences + 0.02 * items)
    score += min(0.25, 0.1 * len(_HEAVY.findall(last)))
    score += min(0.1, 0.02 * max(0, len(user_turns) - 1))
    return round(min(1.0, score), 3)
