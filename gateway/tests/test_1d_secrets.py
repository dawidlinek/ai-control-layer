"""1D: SEC-SECRET-01 rules, entropy heuristic and control behaviour (synthetic secrets, built at runtime)."""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

import pytest

from acl.contracts.common import Action, DataClass, InspectionPoint, Preset
from acl.controls.base import ControlDeps
from acl.controls.secrets.rules import find_secrets
from acl.engine.engine import Engine
from acl.policy.loader import load_policy_dir
from acl.testing import make_context

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"


def _rep(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB = "gh" + "p_" + _rep("A1b2C3d4", 36)
GITHUB_PAT = "github" + "_pat_" + _rep("A1b2C3d4", 40)
GITLAB = "gl" + "pat-" + _rep("x9", 20)
SLACK = "xo" + "xb-" + "123456789012-abcdefghijkl"
STRIPE = "sk_" + "live_" + _rep("a1", 24)
OPENAI = "sk-" + "proj-" + _rep("Ab3d", 48)
ANTHROPIC = "sk-ant-" + "api03-" + _rep("Zy9x", 64)
GEMINI = "AI" + "za" + _rep("Qw3r", 35)
HF = "hf" + "_" + _rep("Kj8m", 34)
JWT = ".".join(
    base64.urlsafe_b64encode(p).decode().rstrip("=")
    for p in (b'{"alg":"HS256","typ":"JWT"}', b'{"sub":"1234567890","name":"Synthetic"}', b"signature-bytes-synthetic")
)
PEM = (
    "-----BEGIN RSA PRIVATE" + " KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "-----END RSA PRIVATE KEY-----"
)
ENTROPY = "q8Zr3KpV7mXw2LdN9sTb5YhC1gJf4AuE6oRi0PxM"


@lru_cache(maxsize=1)
def _loaded():
    return load_policy_dir(POLICY_DIR)


def _engine() -> Engine:
    return Engine.build(_loaded().policy, _loaded().version, deps=ControlDeps())


def _entities(text: str, **kw) -> list[str]:
    return [h.entity for h in find_secrets(text, **kw)]


@pytest.mark.parametrize(
    ("secret", "entity"),
    [
        (AWS, "AWS_ACCESS_KEY"),
        (GITHUB, "GITHUB_TOKEN"),
        (GITHUB_PAT, "GITHUB_PAT"),
        (GITLAB, "GITLAB_TOKEN"),
        (SLACK, "SLACK_TOKEN"),
        (STRIPE, "STRIPE_KEY"),
        (OPENAI, "OPENAI_KEY"),
        (ANTHROPIC, "ANTHROPIC_KEY"),
        (GEMINI, "GCP_API_KEY"),
        (HF, "HUGGINGFACE_TOKEN"),
        (JWT, "JWT"),
        (PEM, "PRIVATE_KEY"),
        ("aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS_SECRET_KEY"),
        ("DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + _rep("Ab+/", 64) + "==", "AZURE_STORAGE_KEY"),
        ("postgres://app:" + "s3cretPw99" + "@db.internal:5432/x", "BASIC_AUTH_URL"),
        ("password=" + "Tr0ub4dor&3x", "PASSWORD_ASSIGNMENT"),
        ('{"api_key": "' + "q8Zr3KpV7mXw2LdN9sTb5YhC" + '"}', "PASSWORD_ASSIGNMENT"),
    ],
)
def test_rules_detect(secret: str, entity: str) -> None:
    hits = find_secrets(f"config:\n{secret}\nend", entropy=False)
    assert entity in {h.entity for h in hits}, [h.entity for h in hits]


@pytest.mark.parametrize(
    "text",
    [
        "AKIA1234",  # truncated
        "the key is AKIAlowercasenotakey",
        "sk-learn is a library, sk-ant-short",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",  # JWT without a signature segment
        "password=<your-password>",
        "password = os.environ['DB_PASSWORD']",
        "password: ${DB_PASSWORD}",
        "password=changeme",
        "token: {{ secrets.token }}",
        "max_tokens=4096, tokens: 12",
        "commit e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "id 123e4567-e89b-12d3-a456-426614174000",
        "https://user@example.com/path",
        "secret = settings.SECRET_NAME",
    ],
)
def test_near_misses_are_not_secrets(text: str) -> None:
    assert _entities(text) == [], text


def test_entropy_heuristic() -> None:
    assert _entities(f"here: {ENTROPY}") == ["HIGH_ENTROPY_TOKEN"]
    assert _entities(f"here: {ENTROPY}", entropy=False) == []
    assert _entities("a" * 40) == []  # low entropy
    assert _entities("getUserAccountBalanceFromDatabaseForTheCurrentSession2024") == []  # identifier
    assert _entities("sha512-" + _rep("Ab3d9Zq+", 86)) == []  # SRI hash
    assert _entities("data:image/png;base64," + ENTROPY) == []
    cert = "-----BEGIN CERTIFICATE-----\n" + ENTROPY + "\n-----END CERTIFICATE-----"
    assert _entities(cert) == []  # public material in PEM armour


def test_spans_cover_the_secret_value() -> None:
    text = f"x password={'Tr0ub4dor&3x'} y {AWS} z"
    spans = {h.entity: text[h.start : h.end] for h in find_secrets(text, entropy=False)}
    assert spans["AWS_ACCESS_KEY"] == AWS
    assert spans["PASSWORD_ASSIGNMENT"] == "Tr0ub4dor&3x"


# --------------------------------------------------------------------------- control


async def _run(text, point=InspectionPoint.ingress, preset=Preset.balanced):
    return await _engine().evaluate(make_context(text, point=point, preset=preset))


async def test_block_is_final_and_restricted() -> None:
    d = await _run(f"my key {AWS}")
    assert d.action == Action.block and d.final and d.rule_ids == ["SEC-SECRET-01"]
    v = next(v for v in d.verdicts if v.control_id == "SEC-SECRET-01")
    assert v.data_class == DataClass.restricted
    assert AWS not in d.model_dump_json()
    assert v.findings[0].value_hash and v.findings[0].replacement == "[REDACTED:AWS_ACCESS_KEY]"


async def test_preset_secret_action() -> None:
    assert (await _run(f"k {AWS}", preset=Preset.monitor)).action == Action.monitor
    for p in (Preset.balanced, Preset.strict, Preset.paranoid):
        assert (await _run(f"k {AWS}", preset=p)).action == Action.block


async def test_every_inspection_point_is_covered() -> None:
    assert (await _run(f"out: {AWS}", InspectionPoint.egress)).action == Action.block
    d = await _run({"tool": "files.read", "content": f"export KEY={AWS}"}, InspectionPoint.tool_result)
    assert d.action == Action.block
    d = await _run({"tool": "mail.send", "arguments": {"body": f"key {AWS}"}}, InspectionPoint.tool_call)
    assert d.action == Action.block


@pytest.mark.parametrize(
    "variant",
    [
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: s.encode().hex(),
        lambda s: "".join(f"%{b:02X}" for b in s.encode()),
        lambda s: s[:8] + "\n" + s[8:],
        lambda s: s[:6] + "\U0000200b" + s[6:],
        lambda s: base64.b64encode(base64.b64encode(s.encode())).decode(),
    ],
    ids=["base64", "hex", "percent", "line-split", "zero-width", "double-base64"],
)
async def test_obfuscated_secrets_are_caught(variant) -> None:
    d = await _run(f"please use this: {variant(AWS)} thanks")
    assert d.action == Action.block and "SEC-SECRET-01" in d.rule_ids


async def test_secret_split_with_string_concatenation() -> None:
    code = f'key = "{AWS[:10]}" +\n  "{AWS[10:]}"'
    d = await _run(code)
    assert d.action == Action.block


async def test_pem_block_is_one_finding() -> None:
    d = await _run(f"here\n{PEM}\nthanks")
    v = next(v for v in d.verdicts if v.control_id == "SEC-SECRET-01")
    assert [f.entity_type for f in v.findings] == ["PRIVATE_KEY"]


async def test_benign_text_passes() -> None:
    d = await _run("Napisz funkcję w Pythonie, która czyta plik .env.example i zwraca słownik.")
    assert d.action == Action.allow
