"""Deterministic Polish-legal detector (`acl.routing.polish_legal`) and its use by `auto` (specialist routing).

Invariants: Polish legal text → local/bielik; Polish non-legal text, English legal text → the normal rules;
confidential Polish legal text → Bielik, never the cloud; Bielik unavailable → the normal rules (local Qwen for
confidential data); a principal without the `bielik` grant → `auto` skips it. Reasons never carry prompt text.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

import pytest

from acl.contracts.common import ConnectorTier, DataClass
from acl.policy.loader import load_policy_dir
from acl.routing.dev_access import PermissiveAccess
from acl.routing.polish_legal import detect
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import Router, RouteRequest
from acl.routing.specialist import SpecialistIndex


def _load_1a_api():  # type: ignore[no-untyped-def]
    """Same trick as test_bielik_routing: one registration of test_1a_api's controls per process."""
    name = "gateway.tests.test_1a_api"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("test_1a_api.py"))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


_api = _load_1a_api()
PESEL, audit_records, chat, harness = _api.PESEL, _api.audit_records, _api.chat, _api.harness

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
BIELIK = "local/bielik"
QWEN = "local/qwen3.8-27b"
FLASH = "gemini/flash"
DEMO = "Czy umowa najmu zawarta ustnie jest ważna według kodeksu cywilnego?"

POLISH_LEGAL = [
    DEMO,
    "Czy ta umowa najmu zawiera klauzule niedozwolone?",
    "Wyjaśnij mi art. 415 Kodeksu cywilnego o odpowiedzialności deliktowej.",
    "Jakie są skutki prawne odstąpienia od umowy sprzedaży?",
    "Jaki jest okres wypowiedzenia umowy o pracę według Kodeksu pracy?",
    "Czy mogę dochodzić zadośćuczynienia przed sądem po przedawnieniu roszczenia?",
    "Sporządź pozew o zapłatę wraz z pełnomocnictwem dla adwokata.",
    "Czy RODO wymaga zgody na przetwarzanie danych osobowych w tym regulaminie?",
    "Ile wynosi zachowek dla dziecka spadkodawcy według k.c.?",
    "Czy wyrok sądu można zaskarżyć apelacją?",
    "Jak liczyć terminy z art. 118 k.c. oraz art. 123 § 1 k.c.?",
    "Czy czynsz i kaucja wynikające z umowy najmu podlegają zwrotowi po wypowiedzeniu?",
    "Czy umowa najmu zawarta ustnie jest wazna wedlug kodeksu cywilnego?",  # no diacritics
    "Jakie są przesłanki odpowiedzialności z art. 471 KC?",  # live regression: uppercase abbreviation
    "Wyjaśnij krótko, czym jest art. 415 Kodeksu cywilnego.",
    "Czy art. 3 KPC dotyczy pozwu?",
    "Jakie są przesłanki z art. 471 k.c.?",
    "Jakie są przesłanki z art. 471 k.p.c.?",
    "Co mówi art. 22 KP o stosunku pracy?",
    "Jaka kara grozi z art. 148 KK?",
]
NOT_POLISH_LEGAL = [
    "Podaj przepis na szarlotkę z jabłkami i cynamonem.",
    "Napisz funkcję w Pythonie sortującą listę słowników według klucza.",
    "Jak zmienić ustawienia drukarki w systemie Windows?",
    "Cześć, co słychać? Jak minął weekend?",
    "Podpisaliśmy umowę z dostawcą kawy, a potem poszliśmy na obiad.",  # one incidental legal word
    "Umówmy się na spotkanie jutro, najmniej na godzinę.",
    "Podsumuj spotkanie zespołu z poniedziałku i wypisz zadania.",
    "Jak skonfigurować serwer administratora w naszej sieci firmowej?",
    "Explain the contract law concept of consideration.",
    "Is an oral lease agreement valid under civil law?",
    "What does article 415 of the Polish civil code say about tort liability?",
    "Summarise the GDPR obligations of a data controller in three bullets.",
    "",
    "   ",
    "12345 !!! ???",
]


# ------------------------------------------------------------------ the detector


@pytest.mark.parametrize("text", POLISH_LEGAL)
def test_polish_legal_text_is_detected(text: str) -> None:
    d = detect(text)
    assert d.confidence >= 0.5 and d.lang >= 0.5 and d.legal >= 0.5, d.reason


@pytest.mark.parametrize("text", NOT_POLISH_LEGAL)
def test_other_text_is_not_detected(text: str) -> None:
    d = detect(text)
    assert d.confidence < 0.5, d.reason


def test_confidence_is_language_times_legal_and_bounded() -> None:
    for text in [*POLISH_LEGAL, *NOT_POLISH_LEGAL]:
        d = detect(text)
        assert 0.0 <= d.confidence <= 1.0
        assert d.confidence == pytest.approx(d.lang * d.legal, abs=0.002)


def test_english_never_scores_even_with_polish_legal_words() -> None:
    d = detect("In English only: the umowa najmu under the kodeks cywilny and art. 415 k.c. is a lease.")
    assert d.lang < 0.3 and d.confidence < 0.5


def test_article_citation_and_code_abbreviations_count_as_legal() -> None:
    d = detect("Proszę o wyjaśnienie, jak należy rozumieć art. 415 k.c. w tym przypadku.")
    assert d.confidence >= 0.5 and "legal citation" in d.reason


def test_repeated_term_in_a_long_document_wins_one_mention_does_not() -> None:
    one = "Wczoraj rozmawialiśmy o tym, że umowa jest gotowa i że wszystko idzie zgodnie z planem."
    assert detect(one).confidence < 0.5
    doc = "Strony oświadczają, że umowa jest ważna, a umowa wiąże strony i każda umowa wymaga formy pisemnej. " * 5
    assert detect(doc).confidence >= 0.5


def test_reason_has_scores_counts_and_categories_but_no_prompt_text() -> None:
    d = detect(DEMO)
    assert d.reason.startswith("lang=pl ") and "legal=" in d.reason and "legal terms=" in d.reason
    for word in ("umowa", "najmu", "kodeksu", "cywilnego", "ustnie"):
        assert word not in d.reason


def test_detector_is_fast_on_2kb() -> None:
    text = ("Strony zgodnie oświadczają, że umowa najmu jest zawarta na czas oznaczony. Najemca płaci czynsz. " * 30)[
        :2048
    ]
    detect(text)
    t0 = time.perf_counter()
    for _ in range(50):
        detect(text)
    assert (time.perf_counter() - t0) / 50 < 0.005  # ~0.5 ms measured; 5 ms leaves room for a loaded CI box


def test_huge_input_is_bounded() -> None:
    text = "Czy umowa najmu jest zgodna z kodeksem cywilnym według sądu? " * 20000
    t0 = time.perf_counter()
    assert detect(text).confidence >= 0.5
    assert time.perf_counter() - t0 < 0.5


# ------------------------------------------------------------------ specialist index


@pytest.fixture
def policy():  # type: ignore[no-untyped-def]
    return load_policy_dir(POLICY_DIR).policy


def test_index_reports_the_detector_and_why(policy) -> None:  # type: ignore[no-untyped-def]
    best = SpecialistIndex(policy).candidates(DEMO)[0]
    assert (best.model_id, best.task, best.method) == (BIELIK, "polish_legal", "detector")
    assert best.confidence >= best.threshold and best.detail.startswith("lang=pl ")
    assert DEMO not in best.reason and "umowa" not in best.reason


@pytest.mark.parametrize("text", POLISH_LEGAL)
def test_index_matches_every_polish_legal_text(policy, text: str) -> None:  # type: ignore[no-untyped-def]
    assert SpecialistIndex(policy).candidates(text)[0].model_id == BIELIK


@pytest.mark.parametrize("text", NOT_POLISH_LEGAL)
def test_index_matches_nothing_else(policy, text: str) -> None:  # type: ignore[no-untyped-def]
    assert [m for m in SpecialistIndex(policy).candidates(text) if m.model_id == BIELIK] == []


def test_knn_alone_cannot_send_english_text_to_bielik(policy) -> None:  # type: ignore[no-untyped-def]
    # an English sentence stuffed with words from the Polish examples: lexical overlap, but not Polish
    text = "umowa najmu klauzule niedozwolone Kodeksu cywilnego art. 471 pozew apelacji"
    assert [m for m in SpecialistIndex(policy).candidates(text) if m.model_id == BIELIK] == []


# ------------------------------------------------------------------ the router


@pytest.fixture
def setup(policy):  # type: ignore[no-untyped-def]
    table = ConnectorRegistry(deterministic=True).table_for(policy, "v")
    access = PermissiveAccess(lambda: policy)

    async def usable():  # type: ignore[no-untyped-def]
        return await access.usable_models(None)  # type: ignore[arg-type]

    return Router(policy, table), usable


async def test_demo_question_routes_to_bielik_with_an_explaining_reason(setup) -> None:  # type: ignore[no-untyped-def]
    router, usable = setup
    r = router.route(RouteRequest(requested="auto", usable=await usable(), prompt=DEMO))
    assert r.info.model == BIELIK and r.info.tier == ConnectorTier.local and not r.info.degraded
    reason = r.info.reason
    assert reason.startswith(f"auto → {BIELIK}: task=polish_legal (") and "detector: lang=pl" in reason
    assert "legal=" in reason and "legal terms=" in reason and "data=public" in reason
    assert r.info.factors["specialist_method"] == "detector" and r.info.factors["specialist_confidence"] >= 0.5
    for word in ("umowa", "najmu", "kodeksu", "ustnie"):
        assert word not in reason


async def test_polish_non_legal_and_english_legal_follow_the_normal_rules(setup) -> None:  # type: ignore[no-untyped-def]
    router, usable = setup
    for text in NOT_POLISH_LEGAL[:11]:
        r = router.route(RouteRequest(requested="auto", usable=await usable(), prompt=text, complexity=0.02))
        assert r.info.model == FLASH and "specialist" not in r.info.factors, text


async def test_confidential_polish_legal_goes_to_bielik_never_the_cloud(setup) -> None:  # type: ignore[no-untyped-def]
    router, usable = setup
    for dc in (DataClass.confidential, DataClass.restricted):
        r = router.route(RouteRequest(requested="auto", data_class=dc, usable=await usable(), prompt=DEMO))
        assert r.info.model == BIELIK and r.info.tier == ConnectorTier.local


async def test_principal_without_the_bielik_grant_never_gets_bielik_from_auto(setup) -> None:  # type: ignore[no-untyped-def]
    router, usable = setup
    granted = {k: v for k, v in (await usable()).items() if k != BIELIK}
    r = router.route(RouteRequest(requested="auto", usable=granted, prompt=DEMO, complexity=0.02))
    assert r.info.model == FLASH and "specialist" not in r.info.factors
    r = router.route(RouteRequest(requested="auto", data_class=DataClass.confidential, usable=granted, prompt=DEMO))
    assert r.info.model == QWEN and r.info.tier == ConnectorTier.local


async def test_bielik_unavailable_keeps_confidential_text_on_local_qwen(policy) -> None:  # type: ignore[no-untyped-def]
    reg = ConnectorRegistry(
        environ={
            "LOCAL_LLM_BASE_URL": "http://gpu:8000/v1",
            "LOCAL_GENERAL_MODEL": "qwen3:8b",
            "GEMINI_API_KEY": "k",
            "GEMINI_MODEL": "g",
        }
    )
    router = Router(policy, reg.table_for(policy, "no-bielik"))
    usable = await PermissiveAccess(lambda: policy).usable_models(None)  # type: ignore[arg-type]
    for dc in (DataClass.confidential, DataClass.restricted):
        r = router.route(RouteRequest(requested="auto", data_class=dc, usable=usable, prompt=DEMO))
        assert r.info.model == QWEN and r.info.tier == ConnectorTier.local and "specialist" not in r.info.factors
    # an explicit pick of an unavailable Bielik degrades to local Qwen, also for confidential data
    r = router.route(RouteRequest(requested="bielik", data_class=DataClass.confidential, usable=usable))
    assert r.info.model == QWEN and r.info.degraded and r.info.tier == ConnectorTier.local


async def test_detector_rule_is_off_when_specialist_routing_is_disabled(policy) -> None:  # type: ignore[no-untyped-def]
    policy = policy.model_copy(deep=True)
    policy.routing.specialist.enabled = False
    table = ConnectorRegistry(deterministic=True).table_for(policy, "off")
    usable = await PermissiveAccess(lambda: policy).usable_models(None)  # type: ignore[arg-type]
    r = Router(policy, table).route(RouteRequest(requested="auto", usable=usable, prompt=DEMO, complexity=0.02))
    assert r.info.model == FLASH


# ------------------------------------------------------------------ end to end (chat flow, mock connectors)


def test_chat_demo_question_routes_to_bielik_and_the_audit_trace_explains_it(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, DEMO, model="auto")
    assert r.status_code == 200 and r.headers["x-acl-model"] == BIELIK
    route = next(x["route"] for x in audit_records(settings.audit_path) if x["point"] == "ingress")
    assert route["model"] == BIELIK and route["tier"] == "local"
    assert "task=polish_legal" in route["reason"] and "detector: lang=pl" in route["reason"]
    assert "umowa" not in route["reason"] and "najmu" not in route["reason"]


def test_chat_confidential_polish_legal_text_with_a_pesel_stays_on_bielik(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    text = f"Klient o numerze PESEL {PESEL} pyta: {DEMO}"
    r = chat(client, text, model="auto")
    assert r.status_code == 200 and r.headers["x-acl-model"] == BIELIK
    records = audit_records(settings.audit_path)
    route = next(x["route"] for x in records if x["point"] == "ingress")
    assert route["tier"] == "local" and PESEL not in route["reason"]
    assert PESEL not in settings.audit_path.read_text(encoding="utf-8")


def test_chat_article_citation_with_uppercase_code_abbreviation_routes_to_bielik(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    for text in (
        "Jakie są przesłanki odpowiedzialności z art. 471 KC?",
        "Wyjaśnij krótko, czym jest art. 415 Kodeksu cywilnego.",
    ):
        assert chat(client, text, model="auto").headers["x-acl-model"] == BIELIK, text


def test_chat_polish_non_legal_and_english_legal_do_not_reach_bielik(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    for text in (NOT_POLISH_LEGAL[0], NOT_POLISH_LEGAL[4], NOT_POLISH_LEGAL[8]):
        assert chat(client, text, model="auto").headers["x-acl-model"] == FLASH, text
    # confidential but not legal: local Qwen, as before
    assert (
        chat(client, f"Mój PESEL to {PESEL}, napisz mi przepis na szarlotkę", model="auto").headers["x-acl-model"]
        == QWEN
    )
