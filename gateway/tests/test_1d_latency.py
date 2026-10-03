"""1D: latency budget — the deterministic layer (normalise, PII, secrets, exfil, signatures, hygiene) ≤ 15 ms p95."""

from __future__ import annotations

import base64
import json
import statistics
import time
from pathlib import Path

import pytest

from acl.contracts.common import Action, InspectionPoint
from acl.contracts.feed import FeedBundle
from acl.controls.base import ControlDeps
from acl.controls.pii.vault import PseudonymVault
from acl.engine.engine import Engine
from acl.feed.store import SignatureStore
from acl.policy.loader import load_policy_dir
from acl.testing import make_context

ROOT = Path(__file__).resolve().parents[2]
BUDGET_MS = 15.0
ITERATIONS = 100
ROUNDS = 3

PARAGRAPH = (
    "Zespół platformy danych przygotował zestawienie zmian w procesie rozliczeń. Analiza obejmuje trzy obszary: "
    "integrację z systemem księgowym, uzgadnianie przelewów oraz raportowanie dla działu ryzyka. Poniżej szczegóły "
    "do omówienia na poniedziałkowym spotkaniu, w tym lista otwartych pytań i zależności między zespołami. "
)


def _engine() -> Engine:
    loaded = load_policy_dir(ROOT / "policy")
    store = SignatureStore()
    seed = json.loads((ROOT / "feed-server" / "bundles" / "0001-seed.json").read_text(encoding="utf-8"))
    store.install(FeedBundle.model_validate(seed), "seed")
    return Engine.build(loaded.policy, loaded.version, deps=ControlDeps(vault=PseudonymVault(), signatures=store))


def _prompt_2kb() -> str:
    attachment = base64.b64encode("Notatka robocza: klient prosi o przesunięcie terminu płatności.".encode()).decode()
    body = (
        PARAGRAPH * 5
        + "\nKontakt: jan.kowalski@example.com, tel. +48 501 234 567, PESEL 44051401359.\n"
        + "Konto: PL61 1090 1014 0000 0712 1981 2874; dokumentacja: https://docs.corp.example/guide?page=2\n"
        + f"Załącznik: {attachment}\n"
        + "```python\nfor row in rows:\n    total += row['amount']\nprint(total)\n```\n"
    )
    assert 1800 <= len(body) <= 2600, len(body)
    return body


async def _bench(engine: Engine, make) -> tuple[float, float, Action]:
    for _ in range(20):  # warm-up (regex caches, imports)
        await engine.evaluate(make())
    # Best of a few rounds: a shared CI/dev machine can stall any one round, but cannot make code faster than it is.
    best: tuple[float, float] | None = None
    action = Action.allow
    for _ in range(ROUNDS):
        samples = []
        for _ in range(ITERATIONS):
            ctx = make()
            t0 = time.perf_counter()
            decision = await engine.evaluate(ctx)
            samples.append((time.perf_counter() - t0) * 1000)
            action = decision.action
        samples.sort()
        round_stats = (statistics.median(samples), samples[int(0.95 * len(samples)) - 1])
        if best is None or round_stats[1] < best[1]:
            best = round_stats
    assert best is not None
    return best[0], best[1], action


@pytest.mark.slow
async def test_ingress_2kb_p95_under_budget() -> None:
    engine = _engine()
    text = _prompt_2kb()
    p50, p95, action = await _bench(engine, lambda: make_context(text))
    print(f"\nlatency ingress 2KB: p50={p50:.2f} ms p95={p95:.2f} ms action={action.value}")
    assert action == Action.pseudonymise  # the work really happened
    assert p95 < BUDGET_MS, f"p95 {p95:.2f} ms over budget"


HOSTILE = {
    "digits-and-spaces": "1 " * 1000,
    "one-long-word": "A" * 2000,
    "percent-escapes": "%41" * 700,
    "long-base64-token": "QUJD" * 500,
    "many-newlines": "x\n" * 1000,
    "email-like": "a@" * 1000,
    "markdown-openers": "![" * 700,
    "link-openers": "[a](" * 500,
    "template-openers": "<|" * 1000,
    "pem-headers": "-----BEGIN PRIVATE KEY----- " * 70,
    "dots-and-dashes": "a.b-" * 500,
    "unicode-soup": "".join(chr(c) for c in (0x200B, 0x202E, 0xE9, 0xE0041)) * 500,
    "slashes": "/" * 2000,
    "quotes-and-plus": '"+\n' * 600,
}


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(HOSTILE))
async def test_hostile_inputs_stay_linear(name: str) -> None:
    engine = _engine()
    text = HOSTILE[name]
    for point in (InspectionPoint.ingress, InspectionPoint.egress, InspectionPoint.tool_result):
        data = {"tool": "x.y", "content": text} if point == InspectionPoint.tool_result else text
        runs = []
        for _ in range(5):
            t0 = time.perf_counter()
            await engine.evaluate(make_context(data, point=point))
            runs.append((time.perf_counter() - t0) * 1000)
        assert min(runs) < 100, f"{name} at {point.value}: {min(runs):.1f} ms"  # linear-time, not catastrophic


@pytest.mark.slow
async def test_egress_2kb_p95_under_budget() -> None:
    engine = _engine()
    text = _prompt_2kb().replace("PESEL 44051401359", "numer w aktach")
    p50, p95, _ = await _bench(engine, lambda: make_context(text, point=InspectionPoint.egress))
    print(f"\nlatency egress 2KB: p50={p50:.2f} ms p95={p95:.2f} ms")
    assert p95 < BUDGET_MS


@pytest.mark.slow
async def test_tool_call_p95_under_budget() -> None:
    engine = _engine()
    payload = {
        "tool": "opencode.bash",
        "arguments": {
            "command": "cd /work/repo && git status --short && pip install requests==2.32.3 && python -m pytest -q"
        },
        "cwd": "/work/repo",
        "workspace_root": "/work/repo",
    }
    p50, p95, action = await _bench(engine, lambda: make_context(payload, point=InspectionPoint.tool_call))
    print(f"\nlatency tool_call: p50={p50:.2f} ms p95={p95:.2f} ms")
    assert action == Action.allow and p95 < BUDGET_MS


@pytest.mark.slow
async def test_tool_result_2kb_p95_under_budget() -> None:
    engine = _engine()
    payload = {"tool": "files.read_file", "content": _prompt_2kb().replace("PESEL 44051401359", "")}
    p50, p95, _ = await _bench(engine, lambda: make_context(payload, point=InspectionPoint.tool_result))
    print(f"\nlatency tool_result 2KB: p50={p50:.2f} ms p95={p95:.2f} ms")
    assert p95 < BUDGET_MS
