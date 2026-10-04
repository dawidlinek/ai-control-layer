"""Bielik (local Polish specialist), user-selectable aliases and the `auto` specialist rule (kNN over examples).

The seed policy gives `local/bielik` a `specialist` block (task polish_legal). `auto` routes there for Polish legal
prompts when the principal may use it; explicit picks go by alias; sensitivity escalation still wins over any pick.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from acl.contracts.common import ConnectorTier, DataClass
from acl.contracts.inspection import ChatPayload
from acl.policy.loader import load_policy_dir
from acl.policy.models import SpecialistConfig
from acl.routing.dev_access import PermissiveAccess
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import Router, RouteRequest
from acl.routing.specialist import SpecialistIndex, last_user_text, stems

sys.path.insert(0, str(Path(__file__).parent))
from test_1a_api import PESEL, audit_records, chat, harness  # noqa: F401  (harness is a fixture)

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
BIELIK = "local/bielik"
QWEN = "local/qwen3.8-27b"
LOAN = "local/loan-memo"
FLASH = "gemini/flash"
PRO = "gemini/pro"

LEGAL = "Czy ta umowa najmu zawiera klauzule niedozwolone?"
LEGAL_KC = "Wyjaśnij mi art. 415 Kodeksu cywilnego o odpowiedzialności deliktowej."
LEGAL_LONG = "Wklejam fragment umowy. " + "Strony zgodnie oświadczają co następuje. " * 30 + LEGAL
NOT_LEGAL = [
    "Napisz funkcję w Pythonie sortującą listę słowników.",
    "Napisz mi plan treningowy na siłownię na 4 dni w tygodniu.",
    "Summarise the quarterly incident report in three bullets.",
    "Explain the contract law concept of consideration.",
    "Podsumuj spotkanie zespołu z poniedziałku.",
]


@pytest.fixture
def setup():  # type: ignore[no-untyped-def]
    loaded = load_policy_dir(POLICY_DIR)
    registry = ConnectorRegistry(deterministic=True)
    table = registry.table_for(loaded.policy, loaded.version)
    access = PermissiveAccess(lambda: loaded.policy)

    async def usable():  # type: ignore[no-untyped-def]
        return await access.usable_models(None)  # type: ignore[arg-type]

    return loaded.policy, registry, Router(loaded.policy, table), usable


async def route(setup, requested: str = "auto", data_class=DataClass.public, usable=None, **kw):  # type: ignore[no-untyped-def]
    _, _, router, get_usable = setup
    return router.route(
        RouteRequest(
            requested=requested, data_class=data_class, usable=await get_usable() if usable is None else usable, **kw
        )
    )


# ------------------------------------------------------------------ the policy


def test_bielik_is_a_local_polish_specialist_with_aliases() -> None:
    policy = load_policy_dir(POLICY_DIR).policy
    m = policy.model_by_id()[BIELIK]
    assert m.connector == "local-pl" and policy.connectors[m.connector].tier == ConnectorTier.local
    assert policy.connectors["local-pl"].base_url == "env:LOCAL_PL_BASE_URL"
    assert policy.connectors["local-pl"].api_key == "env:LOCAL_LLM_API_KEY"
    assert m.upstream_model == "env:LOCAL_BIELIK_MODEL" and m.aliases == ["bielik"]
    assert m.tags["family"] == "bielik" and "Polish" in m.tags["role"]
    assert set(m.data_classes) == set(DataClass) and "chat" in m.capabilities
    assert m.specialist is not None and m.specialist.task == "polish_legal"
    assert 6 <= len(m.specialist.examples) <= 10
    by_alias = {a: x.id for x in policy.models for a in x.aliases}
    assert by_alias["qwen"] == QWEN and by_alias["local"] == QWEN and by_alias["fast"] == QWEN
    assert by_alias["flash"] == FLASH and by_alias["smart"] == FLASH
    assert by_alias["pro"] == PRO and by_alias["smart-pro"] == PRO and by_alias["bielik"] == BIELIK


def test_groups_with_local_may_use_bielik() -> None:
    policy = load_policy_dir(POLICY_DIR).policy
    for name, g in policy.groups.items():
        if str(name).startswith("agents/"):
            assert "bielik" not in g.models
        elif "local" in g.models:
            assert "bielik" in g.models, name


# ------------------------------------------------------------------ the matcher


def test_stems_fold_polish_inflection_and_diacritics() -> None:
    assert stems("Umowy, umowie i umowa")[:3] == ["umow"] * 3
    assert "kode" in stems("Kodeksu cywilnego") and "kc" in stems("art. 5 KC")
    assert stems("a to jest czy") == []  # stop words / tiny tokens only


def test_last_user_text_reads_strings_and_parts() -> None:
    p = ChatPayload.model_validate(
        {
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "a"},
                {"role": "user", "content": [{"type": "text", "text": "second"}, {"type": "text", "text": "third"}]},
            ]
        }
    )
    assert last_user_text(p) == "second\nthird"
    assert last_user_text(ChatPayload(messages=[])) == ""


@pytest.mark.parametrize("prompt", [LEGAL, LEGAL_KC, LEGAL_LONG, "Jakie są skutki prawne odstąpienia od umowy?"])
def test_polish_legal_prompts_match_bielik(prompt: str) -> None:
    idx = SpecialistIndex(load_policy_dir(POLICY_DIR).policy)
    best = idx.candidates(prompt)[0]
    assert (best.model_id, best.task) == (BIELIK, "polish_legal") and best.confidence >= best.threshold


@pytest.mark.parametrize("prompt", NOT_LEGAL)
def test_other_prompts_do_not_match_any_specialist(prompt: str) -> None:
    assert SpecialistIndex(load_policy_dir(POLICY_DIR).policy).candidates(prompt) == []


def test_loan_memo_specialist_still_matches_its_own_task() -> None:
    idx = SpecialistIndex(load_policy_dir(POLICY_DIR).policy)
    assert idx.candidates("Podsumuj wniosek kredytowy klienta i przygotuj notatkę.")[0].model_id == LOAN


def test_min_confidence_is_per_model_and_checked() -> None:
    policy = load_policy_dir(POLICY_DIR).policy.model_copy(deep=True)
    m = policy.model_by_id()[BIELIK]
    assert m.specialist is not None
    m.specialist = SpecialistConfig(task="polish_legal", min_confidence=0.99, examples=m.specialist.examples)
    assert SpecialistIndex(policy).candidates(LEGAL) == []  # a paraphrase is below 0.99


# ------------------------------------------------------------------ the router


async def test_auto_sends_polish_legal_text_to_bielik(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, prompt=LEGAL)
    assert r.info.model == BIELIK and r.info.tier == ConnectorTier.local and not r.info.degraded
    assert "task=polish_legal" in r.info.reason and r.info.factors["specialist"] == BIELIK
    assert LEGAL not in r.info.reason  # the reason cites task and score, never the prompt


async def test_auto_english_general_prompt_is_unchanged(setup) -> None:  # type: ignore[no-untyped-def]
    for text in NOT_LEGAL:
        r = await route(setup, prompt=text, complexity=0.02)
        assert r.info.model == FLASH and "specialist" not in r.info.factors
    r = await route(setup, prompt=NOT_LEGAL[0], complexity=0.9)
    assert r.info.model == PRO


async def test_auto_without_prompt_keeps_the_rules(setup) -> None:  # type: ignore[no-untyped-def]
    assert (await route(setup)).info.model == FLASH


async def test_confidential_legal_text_stays_local_on_bielik(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, prompt=LEGAL, data_class=DataClass.confidential)
    assert r.info.model == BIELIK and r.info.tier == ConnectorTier.local


async def test_auto_skips_a_specialist_the_principal_may_not_use(setup) -> None:  # type: ignore[no-untyped-def]
    _, _, _, get_usable = setup
    usable = {k: v for k, v in (await get_usable()).items() if k != BIELIK}
    r = await route(setup, prompt=LEGAL, usable=usable, complexity=0.02)
    assert r.info.model == FLASH
    r = await route(setup, prompt=LEGAL, usable=usable, data_class=DataClass.confidential)
    assert r.info.model == QWEN


async def test_auto_skips_a_specialist_that_is_not_usable_for_the_data_class(setup) -> None:  # type: ignore[no-untyped-def]
    _, _, _, get_usable = setup
    usable = dict(await get_usable())
    usable[BIELIK] = [DataClass.public]
    r = await route(setup, prompt=LEGAL, usable=usable, data_class=DataClass.confidential)
    assert r.info.model == QWEN


async def test_auto_skips_a_specialist_that_is_unavailable(setup) -> None:  # type: ignore[no-untyped-def]
    policy, _, _, get_usable = setup
    # real (non-deterministic) registry, LOCAL_PL_BASE_URL / LOCAL_BIELIK_MODEL unset: unavailable, auto uses the rules
    reg = ConnectorRegistry(
        environ={
            "LOCAL_LLM_BASE_URL": "http://gpu:8000/v1",
            "LOCAL_GENERAL_MODEL": "qwen3:8b",
            "GEMINI_API_KEY": "k",
            "GEMINI_MODEL": "g",
        }
    )
    router = Router(policy, reg.table_for(policy, "no-bielik"))
    assert "LOCAL_BIELIK_MODEL" in (router.table.model_problem(BIELIK) or "")
    usable = await get_usable()
    r = router.route(RouteRequest(requested="auto", usable=usable, prompt=LEGAL, complexity=0.02))
    assert r.info.model == FLASH
    # an explicit pick degrades to the local Qwen instead of crashing, and says so
    r = router.route(RouteRequest(requested="bielik", usable=usable))
    assert r.info.model == QWEN and r.info.degraded and "LOCAL_BIELIK_MODEL" in r.info.reason
    # with the variable set the specialist is live
    reg = ConnectorRegistry(
        environ={
            "LOCAL_LLM_BASE_URL": "http://gpu:8000/v1",
            "LOCAL_GENERAL_MODEL": "qwen3:8b",
            "LOCAL_PL_BASE_URL": "http://gpu:8002/v1",
            "LOCAL_BIELIK_MODEL": "bielik:11b",
            "GEMINI_API_KEY": "k",
            "GEMINI_MODEL": "g",
        }
    )
    router = Router(policy, reg.table_for(policy, "with-bielik"))
    r = router.route(RouteRequest(requested="auto", usable=usable, prompt=LEGAL))
    assert r.info.model == BIELIK and r.upstream_model == "bielik:11b" and r.info.connector == "local-pl"
    # server URL unset while the model name is set (and the other way round): still unavailable, each with its reason
    reg = ConnectorRegistry(environ={"LOCAL_LLM_BASE_URL": "http://gpu:8000/v1", "LOCAL_BIELIK_MODEL": "bielik:11b"})
    assert "LOCAL_PL_BASE_URL" in (reg.table_for(policy, "no-url").model_problem(BIELIK) or "")
    reg = ConnectorRegistry(
        environ={"LOCAL_LLM_BASE_URL": "http://gpu:8000/v1", "LOCAL_PL_BASE_URL": "http://gpu:8002/v1"}
    )
    assert "LOCAL_BIELIK_MODEL" in (reg.table_for(policy, "no-model").model_problem(BIELIK) or "")


async def test_specialist_rule_can_be_disabled_in_routing_settings(setup) -> None:  # type: ignore[no-untyped-def]
    policy, registry, _, get_usable = setup
    policy = policy.model_copy(deep=True)
    policy.routing.specialist.enabled = False
    router = Router(policy, registry.table_for(policy, "no-specialists"))
    r = router.route(RouteRequest(requested="auto", usable=await get_usable(), prompt=LEGAL, complexity=0.02))
    assert r.info.model == FLASH


@pytest.mark.parametrize(
    ("alias", "model"),
    [
        ("bielik", BIELIK),
        ("qwen", QWEN),
        ("local", QWEN),
        ("fast", QWEN),
        ("flash", FLASH),
        ("smart", FLASH),
        ("pro", PRO),
        ("smart-pro", PRO),
    ],
)
async def test_explicit_alias_picks(setup, alias: str, model: str) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, alias, prompt=LEGAL)  # an explicit pick is never second-guessed by the specialist rule
    assert r.info.model == model and r.info.model_requested == alias


@pytest.mark.parametrize("alias", ["flash", "pro", "smart", "smart-pro"])
async def test_sensitivity_escalation_overrides_an_explicit_cloud_pick(setup, alias: str) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, alias, data_class=DataClass.confidential)
    assert r.info.model == QWEN and "LOCK-01" in r.info.reason


async def test_route_local_obligation_overrides_an_explicit_cloud_pick(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, "pro", force_local=True, force_reason="route_local")
    assert r.info.model == QWEN and r.info.factors["forced_local"] is True


async def test_explicit_bielik_stays_on_bielik_for_confidential_data(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, "bielik", data_class=DataClass.restricted, force_local=True)
    assert r.info.model == BIELIK


# ------------------------------------------------------------------ end to end (chat flow, mock connectors)


def test_chat_auto_routes_polish_legal_prompt_to_bielik(harness) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    client, _, settings = harness
    r = chat(client, LEGAL, model="auto")
    assert r.status_code == 200 and r.headers["x-acl-model"] == BIELIK
    assert chat(client, "plain question", model="auto").headers["x-acl-model"] == FLASH
    route = next(x["route"] for x in audit_records(settings.audit_path) if x["point"] == "ingress")
    assert route["model"] == BIELIK and route["tier"] == "local" and "polish_legal" in route["reason"]


def test_chat_explicit_picks_and_escalation(harness) -> None:  # type: ignore[no-untyped-def]  # noqa: F811
    client, _, _ = harness
    assert chat(client, "hello", model="bielik").headers["x-acl-model"] == BIELIK
    assert chat(client, "hello", model="qwen").headers["x-acl-model"] == QWEN
    assert chat(client, "hello", model="pro").headers["x-acl-model"] == PRO
    r = chat(client, f"pesel {PESEL}", model="pro")  # escalation: confidential data never reaches the cloud pick
    assert r.status_code == 200 and r.headers["x-acl-model"] == QWEN
    assert chat(client, f"pesel {PESEL}", model="bielik").headers["x-acl-model"] == BIELIK
