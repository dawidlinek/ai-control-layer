"""1D: PII validators, detection, pseudonymisation vault and the SEC-PII-01 control."""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

import pytest

from acl.contracts.common import Action, DataClass, InspectionPoint, Preset
from acl.controls.base import ControlDeps
from acl.controls.pii.detect import canonical, detect
from acl.controls.pii.validators import (
    luhn_ok,
    valid_card,
    valid_iban,
    valid_nip,
    valid_pesel,
    valid_pl_id_card,
    valid_regon,
)
from acl.controls.pii.vault import PseudonymVault
from acl.engine.engine import Engine
from acl.policy.loader import load_policy_dir
from acl.testing import make_context

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"

PESEL = "44051401359"  # synthetic, checksum-valid
NIP = "123-456-32-18"
REGON9 = "123456785"
REGON14 = "12345678512347"
ID_CARD = "ABA300000"
IBAN_PL = "PL61 1090 1014 0000 0712 1981 2874"
CARD = "4111 1111 1111 1111"


@lru_cache(maxsize=1)
def _loaded():
    return load_policy_dir(POLICY_DIR)


def _engine(**services) -> Engine:
    return Engine.build(_loaded().policy, _loaded().version, deps=ControlDeps(**services))


def _pesel(first10: str) -> str:
    total = sum(w * int(c) for w, c in zip((1, 3, 7, 9, 1, 3, 7, 9, 1, 3), first10, strict=True))
    return first10 + str((10 - total % 10) % 10)


# --------------------------------------------------------------------------- validators


def test_pesel_validator() -> None:
    assert valid_pesel(PESEL)
    assert not valid_pesel("44051401358")  # wrong checksum
    assert not valid_pesel(_pesel("4413140135"))  # checksum ok, month 13
    assert not valid_pesel(_pesel("4402300135"))  # checksum ok, 30 February
    assert valid_pesel(_pesel("0222140135"))  # month 22 → 2002
    assert not valid_pesel("4405140135")  # length
    assert not valid_pesel("4405140135a")


def test_nip_validator() -> None:
    assert valid_nip("1234563218")
    assert not valid_nip("1234563219")
    assert not valid_nip("123456321")  # length
    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    # a prefix whose weighted sum is 10 (mod 11) has no valid check digit at all
    prefix = next(
        f"{n:09d}"
        for n in range(100000000, 100001000)
        if sum(w * int(c) for w, c in zip(weights, f"{n:09d}", strict=True)) % 11 == 10
    )
    assert not any(valid_nip(prefix + d) for d in "0123456789")


def test_regon_validator() -> None:
    assert valid_regon(REGON9)
    assert not valid_regon("123456786")
    assert valid_regon(REGON14)
    assert not valid_regon("12345678512348")
    assert not valid_regon("12345678")


def test_pl_id_card_validator() -> None:
    assert valid_pl_id_card(ID_CARD)
    assert not valid_pl_id_card("ABA400000")
    assert not valid_pl_id_card("aba300000")  # must be capitals
    assert not valid_pl_id_card("AB3000000")


def test_iban_validator() -> None:
    assert valid_iban("PL61109010140000071219812874")
    assert valid_iban("DE89370400440532013000")
    assert valid_iban("GB82WEST12345698765432")
    assert not valid_iban("PL61109010140000071219812875")  # mod-97
    assert not valid_iban("PL6110901014000007121981287")  # length
    assert not valid_iban("XX00123456789012345678")  # unknown country


def test_luhn_and_cards() -> None:
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
    assert valid_card("4111111111111111")  # visa
    assert valid_card("5555555555554444")  # mastercard
    assert valid_card("378282246310005")  # amex (15)
    assert not valid_card("4111111111111112")  # Luhn
    assert not valid_card("411111111111")  # too short for visa


def test_luhn_valid_but_unknown_issuer_is_not_a_card() -> None:
    # 16 digits with a valid Luhn sum but a prefix no scheme owns
    digits = "9" + "0" * 14
    check = next(d for d in "0123456789" if luhn_ok(digits + d))
    assert not valid_card(digits + check)


# --------------------------------------------------------------------------- detection


def _types(text: str) -> list[str]:
    return [h.entity for h in detect(text)]


def test_detect_all_entities() -> None:
    assert _types(f"pesel {PESEL}") == ["PESEL"]
    assert _types(f"NIP: {NIP}") == ["NIP"]
    assert _types("NIP 1234563218") == ["NIP"]  # bare, keyword context
    assert _types("1234563218") == []  # bare 10 digits without context
    assert _types(f"REGON {REGON9}") == ["REGON"]
    assert _types(REGON9) == []
    assert _types(f"dowód {ID_CARD}") == ["PL_ID_CARD"]
    assert _types(f"konto {IBAN_PL}") == ["IBAN"]
    assert _types("konto 61 1090 1014 0000 0712 1981 2874") == ["IBAN"]  # bare Polish NRB
    assert _types(f"karta {CARD}") == ["CREDIT_CARD"]
    assert _types("write to jan.kowalski@example.com please") == ["EMAIL"]
    assert _types("tel. 501 234 567") == ["PHONE"]
    assert _types("zadzwoń +48 501 234 567") == ["PHONE"]
    assert _types("telefon 501234567") == ["PHONE"]
    assert _types("501234567") == []  # bare 9 digits without a phone keyword


def test_detect_near_misses() -> None:
    assert _types("Order 4111 1111 1111 1112") == []  # Luhn-invalid
    assert _types("PESEL 44051401358") == []  # bad checksum
    assert _types("IBAN PL61 1090 1014 0000 0712 1981 2875") == []
    assert _types("git clone git@github.com:org/repo.git") == []  # ssh remote is not a mailbox
    assert _types("version 1.2.3 build 20240131") == []


def test_iban_over_capture_is_trimmed() -> None:
    hits = detect(f"{IBAN_PL} ORAZ coś")
    assert [h.entity for h in hits] == ["IBAN"]
    assert hits[0].value == IBAN_PL


def test_overlap_priority_prefers_checksummed_entity() -> None:
    # a spaced IBAN contains digit groups that could also look like a card/phone; only the IBAN is reported
    assert _types(f"IBAN: {IBAN_PL} tel 501 234 567") == ["IBAN", "PHONE"]


def test_canonical_identity() -> None:
    assert canonical("IBAN", "61 1090 1014 0000 0712 1981 2874") == "PL61109010140000071219812874"
    assert canonical("IBAN", IBAN_PL) == "PL61109010140000071219812874"
    assert canonical("PHONE", "+48 501 234 567") == canonical("PHONE", "501-234-567")
    assert canonical("EMAIL", "Jan@Example.COM") == "jan@example.com"


# --------------------------------------------------------------------------- vault


def test_vault_consistent_placeholders_and_restore_allowlist() -> None:
    v = PseudonymVault()
    a = v.placeholder_for("s1", "PESEL", PESEL)
    assert a == "<PESEL_1>"
    assert v.placeholder_for("s1", "PESEL", PESEL) == a
    assert v.placeholder_for("s1", "PESEL", _pesel("0222140135")) == "<PESEL_2>"
    assert v.placeholder_for("s1", "IBAN", IBAN_PL) == "<IBAN_1>"
    text = "a <PESEL_1> b <IBAN_1> c <PESEL_9>"
    assert (
        v.restore("s1", text, allowed_entity_types={"PESEL"}) == f"a {PESEL} b <IBAN_1> c <PESEL_9>"
    )  # IBAN not allowed
    assert v.restore("s1", text, allowed_entity_types=set()) == text
    assert v.placeholders("s1") == {"<PESEL_1>", "<PESEL_2>", "<IBAN_1>"}


def test_vault_restore_is_session_scoped_and_never_invents() -> None:
    v = PseudonymVault()
    v.placeholder_for("s1", "PESEL", PESEL)
    assert v.restore("other", "<PESEL_1>", allowed_entity_types={"PESEL"}) == "<PESEL_1>"
    assert v.restore("s1", "<PESEL_2> <NIP_1>", allowed_entity_types={"PESEL", "NIP"}) == "<PESEL_2> <NIP_1>"
    assert v.placeholders("other") == set()


def test_vault_plan_is_pure_and_register_is_explicit() -> None:
    v = PseudonymVault()
    plan1 = v.plan("s", [("PESEL", PESEL, PESEL), ("PESEL", "x2", "x2")])
    plan2 = v.plan("s", [("PESEL", PESEL, PESEL), ("PESEL", "x2", "x2")])
    assert [p.placeholder for p in plan1] == [p.placeholder for p in plan2] == ["<PESEL_1>", "<PESEL_2>"]
    assert v.placeholders("s") == set()  # planning stored nothing
    v.register("s", plan1)
    assert v.placeholders("s") == {"<PESEL_1>", "<PESEL_2>"}
    # a new payload continues the numbering
    assert v.plan("s", [("PESEL", "x3", "x3")])[0].placeholder == "<PESEL_3>"


def test_vault_ttl_and_capacity() -> None:
    now = [0.0]
    v = PseudonymVault(ttl_s=10, max_sessions=2, clock=lambda: now[0])
    v.placeholder_for("a", "PESEL", PESEL)
    now[0] = 11
    assert v.placeholders("a") == set()  # expired
    assert v.restore("a", "<PESEL_1>", allowed_entity_types={"PESEL"}) == "<PESEL_1>"
    v.placeholder_for("x", "PESEL", PESEL)
    v.placeholder_for("y", "PESEL", PESEL)
    v.placeholder_for("z", "PESEL", PESEL)  # evicts the oldest
    assert v.placeholders("x") == set() and v.placeholders("z")


def test_vault_contested_placeholder_is_ambiguous_not_guessed() -> None:
    v = PseudonymVault()
    p1 = v.plan("s", [("PESEL", "k1", "val-one")])
    p2 = v.plan("s", [("PESEL", "k2", "val-two")])  # concurrent request planned the same number
    v.register("s", p1)
    v.register("s", p2)
    assert v.restore("s", "<PESEL_1>", allowed_entity_types={"PESEL"}) == "<PESEL_1>"  # contested → untouched
    assert v.restore("s", "<PESEL_2>", allowed_entity_types={"PESEL"}) == "val-two"


def test_vault_repr_has_no_values() -> None:
    v = PseudonymVault()
    v.placeholder_for("s", "PESEL", PESEL)
    assert PESEL not in repr(v)


# --------------------------------------------------------------------------- control


async def _run(engine: Engine, text, point=InspectionPoint.ingress, preset=Preset.balanced, **kw):
    ctx = make_context(text, point=point, preset=preset, **kw)
    return ctx, await engine.evaluate(ctx)


def _pii_verdict(decision):
    return next(v for v in decision.verdicts if v.control_id == "SEC-PII-01")


async def test_presets_map_to_actions() -> None:
    eng = _engine(vault=PseudonymVault())
    expected = {
        Preset.monitor: Action.monitor,
        Preset.balanced: Action.pseudonymise,
        Preset.strict: Action.pseudonymise,
        Preset.paranoid: Action.pseudonymise,
    }
    for preset, action in expected.items():
        _, d = await _run(eng, f"PESEL {PESEL}", preset=preset)
        assert d.action == action, preset
    v = _pii_verdict(d)
    assert v.data_class == DataClass.confidential


async def test_pseudonymise_placeholders_and_commit() -> None:
    vault = PseudonymVault()
    eng = _engine(vault=vault)
    ctx, d = await _run(eng, f"PESEL {PESEL}, again {PESEL}, IBAN {IBAN_PL}", session_id="sess-a")
    v = _pii_verdict(d)
    assert [f.replacement for f in v.findings] == ["<PESEL_1>", "<PESEL_1>", "<IBAN_1>"]
    assert vault.placeholders("sess-a") == set()  # inspect is side-effect free (dry-run safe)
    await eng.commit(ctx, d)
    assert vault.placeholders("sess-a") == {"<PESEL_1>", "<IBAN_1>"}
    assert vault.restore("sess-a", "<PESEL_1>", allowed_entity_types={"PESEL"}) == PESEL
    # next request in the same session: same value → same placeholder, new value → next number
    _, d2 = await _run(eng, f"{PESEL} and {_pesel('0222140135')}", session_id="sess-a")
    assert [f.replacement for f in _pii_verdict(d2).findings] == ["<PESEL_1>", "<PESEL_2>"]


async def test_dry_run_does_not_touch_the_vault() -> None:
    vault = PseudonymVault()
    eng = _engine(vault=vault)
    for _ in range(3):
        await _run(eng, f"PESEL {PESEL}", session_id="replay")
    assert vault.placeholders("replay") == set()


async def test_blocked_decision_registers_nothing() -> None:
    vault = PseudonymVault()
    eng = _engine(vault=vault)
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    ctx, d = await _run(eng, f"PESEL {PESEL} and {key}", session_id="blocked")
    assert d.action == Action.block
    await eng.commit(ctx, d)
    assert vault.placeholders("blocked") == set()


async def test_without_vault_degrades_to_typed_masks() -> None:
    eng = _engine()
    _, d = await _run(eng, f"PESEL {PESEL}")
    v = _pii_verdict(d)
    assert d.action == Action.pseudonymise
    assert v.findings[0].replacement == "[REDACTED:PESEL]"
    assert "typed masks" in (v.reason or "")


async def test_findings_never_contain_raw_values() -> None:
    eng = _engine(vault=PseudonymVault())
    text = f"PESEL {PESEL} IBAN {IBAN_PL} card {CARD} mail jan.kowalski@example.com tel. 501 234 567"
    _, d = await _run(eng, text)
    dumped = d.model_dump_json()
    for raw in (PESEL, IBAN_PL, CARD, "jan.kowalski@example.com", "501 234 567"):
        assert raw not in dumped
    assert all(f.value_hash and len(f.value_hash) == 16 for f in _pii_verdict(d).findings)


async def test_value_hash_is_stable_per_value_and_uses_the_salt() -> None:
    class S:
        value_hash_salt = "salt-one"

    class S2:
        value_hash_salt = "salt-two"

    h = []
    for settings in (S(), S(), S2()):
        _, d = await _run(_engine(settings=settings), f"PESEL {PESEL}")
        h.append(_pii_verdict(d).findings[0].value_hash)
    assert h[0] == h[1] != h[2]


def test_value_salt_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import SecretStr

    from acl.controls.normalise.scan import DEV_SALT, value_salt
    from acl.settings import Settings

    monkeypatch.delenv("ACL_VALUE_HASH_SALT", raising=False)
    assert value_salt(ControlDeps(settings=Settings(value_hash_salt=SecretStr("from-settings")))) == "from-settings"
    assert value_salt(ControlDeps()) == DEV_SALT
    monkeypatch.setenv("ACL_VALUE_HASH_SALT", "from-env")
    assert value_salt(ControlDeps()) == "from-env"
    assert value_salt(ControlDeps(settings=Settings(value_hash_salt=SecretStr("")))) == "from-env"


async def test_hit_inside_base64_replaces_the_whole_token() -> None:
    eng = _engine(vault=PseudonymVault())
    token = base64.b64encode(f"PESEL {PESEL}".encode()).decode()
    text = f"decode: {token} thanks"
    _, d = await _run(eng, text)
    f = _pii_verdict(d).findings[0]
    assert f.entity_type == "PESEL"
    assert text[f.start : f.end] == token  # the encoded token, not the decoded offsets


async def test_line_split_values_are_found() -> None:
    eng = _engine(vault=PseudonymVault())
    _, d = await _run(eng, "PESEL 440514\n01359")
    f = _pii_verdict(d).findings[0]
    assert f.entity_type == "PESEL"
    _, d2 = await _run(eng, "card 4111 1111\n1111 1111")
    assert _pii_verdict(d2).findings[0].entity_type == "CREDIT_CARD"
    # two ordinary lines of numbers are not glued into a phantom identifier
    _, d3 = await _run(eng, "ids:\n12345\n67890")
    assert d3.action == Action.allow


async def test_egress_and_tool_call_are_scanned() -> None:
    eng = _engine(vault=PseudonymVault())
    _, d = await _run(eng, f"Twój PESEL: {PESEL}", point=InspectionPoint.egress)
    assert d.action == Action.pseudonymise
    _, d = await _run(
        eng,
        {"tool": "mail.send", "arguments": {"to": "x@y.pl", "body": f"PESEL {PESEL}"}},
        point=InspectionPoint.tool_call,
    )
    assert d.action == Action.pseudonymise
    assert {f.field for f in _pii_verdict(d).findings} >= {"arguments.body"}


async def test_config_action_override_and_block_is_final() -> None:
    loaded = _loaded()
    policy = loaded.policy.model_copy(deep=True)
    policy.presets[Preset.balanced] = policy.presets[Preset.balanced].model_copy(update={"pii_action": Action.block})
    eng = Engine.build(policy, "t", deps=ControlDeps())
    _, d = await _run(eng, f"PESEL {PESEL}")
    assert d.action == Action.block and d.final
    assert "SEC-PII-01" in d.rule_ids


@pytest.mark.parametrize("entity", ["PESEL", "IBAN", "CREDIT_CARD", "EMAIL"])
def test_unknown_entity_param_rejected(entity: str) -> None:
    from acl.controls.base import registry
    from acl.policy.models import ControlConfig

    cfg = ControlConfig(
        id="SEC-PII-99",
        type="pii",
        stages=[InspectionPoint.ingress],
        cost_tier="deterministic",
        timeout_ms=20,
        params={"entities": [entity, "SHOE_SIZE"]},
    )
    with pytest.raises(ValueError):
        registry.build(cfg, ControlDeps())
