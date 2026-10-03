"""1A: verdict cache, replay buffer, streaming guard, repeat detector."""

from __future__ import annotations

import time

import pytest

from acl.contracts.common import Action, CostTier, InspectionPoint, Phase, VerdictStatus
from acl.contracts.decision import Decision, Finding, Verdict
from acl.contracts.inspection import CompletionPayload, ToolCall
from acl.engine.cache import VerdictCache, payload_digest
from acl.engine.replay import ReplayBuffer
from acl.engine.streaming import RepeatDetector, StreamGuard
from acl.testing import make_context

# ------------------------------------------------------------------ cache


def verdict(**kw) -> Verdict:  # type: ignore[no-untyped-def]
    base = {
        "control_id": "SEC-X-01",
        "control_type": "x",
        "phase": Phase.deterministic,
        "cost_tier": CostTier.deterministic,
    }
    return Verdict(**{**base, **kw})


def test_cache_key_covers_control_policy_preset_point_and_content() -> None:
    cache = VerdictCache()
    ctx = make_context("hello")
    key = VerdictCache.key("SEC-X-01", "v1", ctx)
    cache.put(key, verdict(action=Action.redact, outputs={"payload": "n"}))
    assert cache.get(key) is None  # verdicts with request-specific outputs are never cached (CP1 finding)
    cache.put(key, verdict(action=Action.redact))
    hit = cache.get(key)
    assert hit is not None and hit.status == VerdictStatus.cached and hit.latency_ms == 0
    assert hit.outputs == {}
    assert cache.get(VerdictCache.key("SEC-X-02", "v1", ctx)) is None  # other control
    assert cache.get(VerdictCache.key("SEC-X-01", "v2", ctx)) is None  # other policy version
    assert cache.get(VerdictCache.key("SEC-X-01", "v1", make_context("hello", preset="strict"))) is None  # type: ignore[arg-type]
    assert cache.get(VerdictCache.key("SEC-X-01", "v1", make_context("hello", point=InspectionPoint.egress))) is None
    assert cache.get(VerdictCache.key("SEC-X-01", "v1", make_context("hello!"))) is None  # other content
    assert payload_digest(make_context("hello")) == payload_digest(ctx)


def test_cache_is_bounded_lru_and_expires() -> None:
    cache = VerdictCache(max_entries=2, ttl_s=0.05)
    keys = [VerdictCache.key("C-1", "v", make_context(f"t{i}")) for i in range(3)]
    cache.put(keys[0], verdict())
    cache.put(keys[1], verdict())
    assert cache.get(keys[0]) is not None  # touch → keys[1] is now the oldest
    cache.put(keys[2], verdict())
    assert len(cache) == 2 and cache.get(keys[1]) is None and cache.get(keys[0]) is not None
    time.sleep(0.07)
    assert cache.get(keys[0]) is None and len(cache) == 1


def test_cache_never_stores_failed_verdicts_and_returns_copies() -> None:
    cache = VerdictCache()
    key = VerdictCache.key("C-1", "v", make_context("x"))
    cache.put(key, verdict(status=VerdictStatus.timeout))
    assert cache.get(key) is None
    cache.put(key, verdict(reason="orig"))
    first = cache.get(key)
    assert first is not None
    first.reason = "mutated"
    second = cache.get(key)
    assert second is not None and second.reason == "orig"
    assert cache.hit_rate > 0


def test_replay_buffer_is_bounded_newest_first_and_clean() -> None:
    buf = ReplayBuffer(maxlen=3)
    decision = Decision.model_construct()  # content irrelevant for the buffer
    for i in range(5):
        ctx = make_context(f"m{i}", point=InspectionPoint.egress if i % 2 else InspectionPoint.ingress)
        ctx.attributes["scratch"] = i
        buf.add(ctx, decision)
    assert len(buf) == 3
    recent = buf.recent(10)
    assert recent[0][0].payload.messages[0].content == "m4"
    assert all(c.attributes == {} for c, _ in recent)
    assert [c.point for c, _ in buf.recent(10, point=InspectionPoint.egress)] == [InspectionPoint.egress]
    assert len(buf.recent(1)) == 1


# ------------------------------------------------------------------ repeat detector


def test_repeat_detector_flags_loops_not_prose() -> None:
    det = RepeatDetector(n=3, max_repeats=3)
    assert not det.feed(" ".join(f"w{i}" for i in range(200)))
    loop = RepeatDetector(n=3, max_repeats=3)
    assert any(loop.feed("alpha beta gamma delta ") for _ in range(10))


def test_repeat_detector_handles_words_split_across_chunks() -> None:
    det = RepeatDetector(n=2, max_repeats=2)
    chunks = ["ab", " cd ab", " cd", " ab c", "d ab cd"]
    assert any(det.feed(c) for c in chunks)


# ------------------------------------------------------------------ stream guard


class FakeEgress:
    """Egress stand-in: pseudonymises 'secret' (replacement <S_1>) and blocks on 'KILL'."""

    def __init__(self) -> None:
        self.windows: list[CompletionPayload] = []

    async def evaluate(self, payload: CompletionPayload) -> Decision:
        self.windows.append(payload)
        text = payload.content or ""
        verdicts, action = [], Action.allow
        if "KILL" in text:
            action = Action.block
        findings = []
        i = text.find("secret")
        while i != -1:
            findings.append(Finding(entity_type="S", field="content", start=i, end=i + 6, replacement="<S_1>"))
            i = text.find("secret", i + 1)
        if findings and action == Action.allow:
            action = Action.pseudonymise
            verdicts.append(
                Verdict(
                    control_id="C-1",
                    control_type="c",
                    phase=Phase.deterministic,
                    cost_tier=CostTier.deterministic,
                    action=Action.pseudonymise,
                    findings=findings,
                )
            )
        d = Decision.model_construct(
            action=action, verdicts=verdicts, rule_ids=["C-1"] if action == Action.block else []
        )
        return d

    @staticmethod
    def findings_of(d: Decision) -> list[Finding]:
        return [f for v in d.verdicts for f in v.findings]


async def run_guard(guard: StreamGuard, text: str, size: int = 7, **finish) -> tuple[str, list[str], object]:  # type: ignore[no-untyped-def]
    out: list[str] = []
    for i in range(0, len(text), size):
        step = await guard.feed(text[i : i + size])
        if step.blocked is not None:
            return "".join(out), out, step
        if step.text:
            out.append(step.text)
    end = await guard.finish(finish.get("tool_calls", []), "stop")
    if end.text:
        out.append(end.text)
    return "".join(out), out, end


async def test_guard_holds_back_and_redacts_across_chunk_boundaries() -> None:
    fake = FakeEgress()
    guard = StreamGuard(evaluate=fake.evaluate, findings_of=fake.findings_of, holdback_chars=40)
    filler = " ".join(f"f{i}" for i in range(60))
    text = f"one two secret {filler} secret end"
    result, pieces, _ = await run_guard(guard, text, size=5)
    assert result == text.replace("secret", "<S_1>")
    assert len(pieces) > 2  # incremental, not one lump at the end
    assert all("secret" not in p for p in pieces)


async def test_guard_blocks_before_emitting_the_offending_text() -> None:
    fake = FakeEgress()
    guard = StreamGuard(evaluate=fake.evaluate, findings_of=fake.findings_of, holdback_chars=40)
    text = "a" * 100 + " KILL " + "b" * 100
    result, _, outcome = await run_guard(guard, text, size=10)
    assert "KILL" not in result and len(result) < len(text)
    assert getattr(outcome, "blocked", None) is not None


async def test_guard_final_evaluation_can_block_held_back_tail() -> None:
    fake = FakeEgress()
    guard = StreamGuard(evaluate=fake.evaluate, findings_of=fake.findings_of, holdback_chars=500)
    result, _, end = await run_guard(guard, "short text KILL", size=4)
    assert result == "" and end.blocked  # type: ignore[attr-defined]  # nothing left the building


async def test_guard_never_splits_a_placeholder_and_restores_whole_ones() -> None:
    restored: list[str] = []

    async def restore(text: str) -> str:
        restored.append(text)
        return text.replace("<PERSON_1>", "Jan Kowalski")

    guard = StreamGuard(
        evaluate=FakeEgress().evaluate,
        findings_of=FakeEgress.findings_of,
        restore=restore,
        placeholders={"<PERSON_1>"},
        holdback_chars=0,  # restore enforces a minimum hold-back
        inspect=False,
    )
    text = "Dear <PERSON_1>, hello <PERSON_1> and bye <PERSON_1>!"
    result, _, _ = await run_guard(guard, text, size=3)
    assert result == "Dear Jan Kowalski, hello Jan Kowalski and bye Jan Kowalski!"
    assert not any("<" in r and ">" not in r.split("<", 1)[1] for r in restored)  # never a partial placeholder


async def test_guard_without_inspection_or_restore_streams_straight_through() -> None:
    fake = FakeEgress()
    guard = StreamGuard(evaluate=fake.evaluate, findings_of=fake.findings_of, inspect=False)
    step = await guard.feed("immediate")
    assert step.text == "immediate" and fake.windows == []
    end = await guard.finish([], "stop")
    assert end.decision is not None and len(fake.windows) == 1 and fake.windows[0].is_partial is False


async def test_guard_tool_calls_are_inspected_and_transformed_at_finish() -> None:
    async def evaluate(payload: CompletionPayload) -> Decision:
        findings = [
            Finding(entity_type="S", field="tool_calls[0].function.arguments", start=7, end=13, replacement="<S_1>")
        ]
        v = Verdict(
            control_id="C-1",
            control_type="c",
            phase=Phase.deterministic,
            cost_tier=CostTier.deterministic,
            action=Action.redact,
            findings=findings,
        )
        return Decision.model_construct(action=Action.redact, verdicts=[v], rule_ids=[])

    guard = StreamGuard(evaluate=evaluate, findings_of=lambda d: [f for v in d.verdicts for f in v.findings])
    call = ToolCall(id="c1", function={"name": "send", "arguments": '{"a": "secret"}'})  # type: ignore[arg-type]
    await guard.feed("hi")
    end = await guard.finish([call], "tool_calls")
    assert end.tool_calls[0].function.arguments == '{"a": "<S_1>"}'


@pytest.mark.parametrize("holdback", [0, 8, 64, 1000])
async def test_guard_output_is_lossless_for_clean_text(holdback: int) -> None:
    fake = FakeEgress()
    guard = StreamGuard(evaluate=fake.evaluate, findings_of=fake.findings_of, holdback_chars=holdback)
    text = " ".join(f"token{i}" for i in range(80))
    result, _, _ = await run_guard(guard, text, size=11)
    assert result == text
