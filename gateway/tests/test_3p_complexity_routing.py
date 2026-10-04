"""Complexity routing: `estimate_complexity` (deterministic score) and how `auto` uses it (Flash vs Pro vs local).

Complexity only chooses *between permitted models*: Pro is picked only when the principal's usable map contains it
for the request's data class; confidential data and `route_local` obligations are decided before and win.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from acl.contracts.common import DataClass
from acl.contracts.inspection import ChatPayload, EmbeddingsPayload
from acl.policy.loader import load_policy_dir
from acl.routing.complexity import estimate_complexity
from acl.routing.dev_access import PermissiveAccess
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import Router, RouteRequest

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"

LOCAL = "local/qwen3.8-27b"
FLASH = "gemini/flash"
PRO = "gemini/pro"

_CODE = "```python\n" + "def handler(event):\n    return process(event)\n" * 40 + "```\n"
HEAVY_PROMPT = (
    "Refactor this service step by step and explain the architecture trade-offs, then migrate it.\n"
    "1. Analyse the algorithm complexity\n2. Propose a new design\n3. Write the migration plan\n"
    "4. Compare the options\n" + _CODE * 6 + "Please do a detailed analysis of the root cause. " * 20
)


def chat_payload(text: str, prior_turns: int = 0) -> ChatPayload:
    messages: list[dict[str, Any]] = []
    for _ in range(prior_turns):
        messages += [{"role": "user", "content": "question"}, {"role": "assistant", "content": "answer"}]
    messages.append({"role": "user", "content": text})
    return ChatPayload.model_validate({"messages": messages})


# ------------------------------------------------------------------------------------ estimate_complexity


def test_short_prompt_scores_low() -> None:
    assert estimate_complexity(chat_payload("What is the capital of France?")) < 0.05
    assert estimate_complexity(chat_payload("hi")) < 0.05


def test_long_multipart_code_and_architecture_prompt_scores_high() -> None:
    score = estimate_complexity(chat_payload(HEAVY_PROMPT))
    assert score > 0.6 and score <= 1.0  # above the seed `ext_small_max` band


def test_score_is_monotonic_in_each_signal() -> None:
    base = estimate_complexity(chat_payload("Explain how this works."))
    assert estimate_complexity(chat_payload("Explain how this works. " * 300)) > base  # length
    assert estimate_complexity(chat_payload("Explain how this works.\n1. a\n2. b\n3. c")) > base  # structure
    assert estimate_complexity(chat_payload("Prove the algorithm step by step.")) > base  # reasoning wording
    assert estimate_complexity(chat_payload("Explain how this works.", prior_turns=5)) > base  # conversation depth


def test_score_is_clipped_to_unit_interval_and_deterministic() -> None:
    huge = chat_payload(HEAVY_PROMPT * 10, prior_turns=20)
    assert estimate_complexity(huge) == 1.0
    assert estimate_complexity(chat_payload(HEAVY_PROMPT)) == estimate_complexity(chat_payload(HEAVY_PROMPT))


def test_only_the_latest_user_turn_is_measured_for_length() -> None:
    long_then_short = ChatPayload.model_validate(
        {
            "messages": [
                {"role": "user", "content": HEAVY_PROMPT},
                {"role": "assistant", "content": "done"},
                {"role": "user", "content": "thanks"},
            ]
        }
    )
    assert estimate_complexity(long_then_short) < 0.1


def test_content_parts_are_read_and_empty_or_non_chat_payloads_score_zero() -> None:
    parts = ChatPayload.model_validate(
        {"messages": [{"role": "user", "content": [{"type": "text", "text": HEAVY_PROMPT}]}]}
    )
    assert estimate_complexity(parts) > 0.6
    assert estimate_complexity(ChatPayload(messages=[])) == 0.0
    assert (
        estimate_complexity(ChatPayload.model_validate({"messages": [{"role": "system", "content": "be nice"}]})) == 0
    )
    assert estimate_complexity(EmbeddingsPayload(inputs=[HEAVY_PROMPT])) == 0.0


# ------------------------------------------------------------------------------------------- routing


@pytest.fixture
def setup():  # type: ignore[no-untyped-def]
    loaded = load_policy_dir(POLICY_DIR)
    registry = ConnectorRegistry(deterministic=True)
    table = registry.table_for(loaded.policy, loaded.version)
    access = PermissiveAccess(lambda: loaded.policy)

    async def usable():  # type: ignore[no-untyped-def]
        return await access.usable_models(None)  # type: ignore[arg-type]

    return loaded.policy, registry, Router(loaded.policy, table), usable


def test_seed_bands_and_targets() -> None:
    policy = load_policy_dir(POLICY_DIR).policy
    assert policy.routing.complexity_bands.local_max == 0.0
    assert policy.routing.complexity_bands.ext_small_max == 0.6
    assert (policy.routing.targets.ext_small, policy.routing.targets.ext_large) == (FLASH, PRO)


async def route(setup, requested: str = "auto", data_class=DataClass.public, usable=None, **kw):  # type: ignore[no-untyped-def]
    _, _, router, get_usable = setup
    return router.route(
        RouteRequest(
            requested=requested, data_class=data_class, usable=await get_usable() if usable is None else usable, **kw
        )
    )


async def test_auto_low_complexity_picks_flash(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, complexity=estimate_complexity(chat_payload("What is the capital of France?")))
    assert r.info.model == FLASH and not r.info.degraded
    assert r.info.factors["complexity"] < 0.05


async def test_auto_high_complexity_picks_pro_when_the_principal_may_use_it(setup) -> None:  # type: ignore[no-untyped-def]
    cx = estimate_complexity(chat_payload(HEAVY_PROMPT))
    r = await route(setup, complexity=cx)
    assert r.info.model == PRO and r.info.tier.value == "cloud"
    assert r.info.factors["complexity"] == cx and "strong model" in r.info.reason


async def test_auto_high_complexity_falls_back_to_flash_when_pro_is_not_usable(setup) -> None:  # type: ignore[no-untyped-def]
    usable = {k: v for k, v in (await setup[3]()).items() if k != PRO}
    assert FLASH in usable and PRO not in usable
    r = await route(setup, usable=usable, complexity=0.95)
    assert r.info.model == FLASH
    assert r.info.factors["complexity"] == 0.95 and "not usable for this principal" in r.info.reason


async def test_auto_high_complexity_without_any_cloud_model_stays_local(setup) -> None:  # type: ignore[no-untyped-def]
    usable = {k: v for k, v in (await setup[3]()).items() if not k.startswith("gemini")}
    r = await route(setup, usable=usable, complexity=0.95)
    assert r.info.model == LOCAL and r.info.factors["complexity"] == 0.95


async def test_pro_is_bound_by_the_data_classes_the_principal_may_send_to_it(setup) -> None:  # type: ignore[no-untyped-def]
    usable = dict(await setup[3]())
    usable[PRO] = [DataClass.public]  # e.g. a grant constrained to public data
    r = await route(setup, data_class=DataClass.internal, usable=usable, complexity=0.95)
    assert r.info.model == FLASH
    r = await route(setup, data_class=DataClass.public, usable=usable, complexity=0.95)
    assert r.info.model == PRO


async def test_band_boundary_is_exclusive(setup) -> None:  # type: ignore[no-untyped-def]
    assert (await route(setup, complexity=0.6)).info.model == FLASH  # "above ext_small_max" is strict
    assert (await route(setup, complexity=0.61)).info.model == PRO


@pytest.mark.parametrize("cx", [0.0, 0.1, 0.5, 0.7, 0.95, 1.0])
async def test_confidential_data_goes_local_whatever_the_complexity(setup, cx: float) -> None:  # type: ignore[no-untyped-def]
    for dc in (DataClass.confidential, DataClass.restricted):
        r = await route(setup, data_class=dc, complexity=cx)
        assert r.info.model == LOCAL, (dc, cx)
        assert r.info.factors["sensitivity_rule"] == "local_only"


async def test_route_local_obligation_wins_over_complexity(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, complexity=0.95, force_local=True, force_reason="route_local")
    assert r.info.model == LOCAL and r.info.factors["forced_local"] is True
    assert "route_local" in r.info.reason and r.info.factors["complexity"] == 0.95


async def test_complexity_does_not_move_explicit_model_choices(setup) -> None:  # type: ignore[no-untyped-def]
    assert (await route(setup, "smart", complexity=0.95)).info.model == FLASH  # explicit alias is honoured
    assert (await route(setup, "smart-pro", complexity=0.0)).info.model == PRO
    assert (await route(setup, "local", complexity=0.95)).info.model == LOCAL


async def test_org_lock_still_reroutes_the_strong_model(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, "smart-pro", DataClass.restricted, complexity=0.95)
    assert r.info.model == LOCAL and r.info.factors["lock"] == "LOCK-01"


async def test_missing_complexity_means_the_default_cloud_model(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup)  # callers that do not measure complexity keep the pre-band behaviour
    assert r.info.model == FLASH and "complexity" not in r.info.factors


async def test_local_band_sends_trivial_requests_local_when_the_policy_enables_it(setup) -> None:  # type: ignore[no-untyped-def]
    policy, registry, _, usable = setup
    policy = policy.model_copy(deep=True)
    policy.routing.complexity_bands.local_max = 0.3
    router = Router(policy, registry.table_for(policy, "v-bands"))
    low = router.route(RouteRequest(requested="auto", usable=await usable(), complexity=0.1))
    assert low.info.model == LOCAL and "→ local" in low.info.reason
    mid = router.route(RouteRequest(requested="auto", usable=await usable(), complexity=0.3))
    assert mid.info.model == FLASH
    high = router.route(RouteRequest(requested="auto", usable=await usable(), complexity=0.9))
    assert high.info.model == PRO
