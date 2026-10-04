"""CP1 security review: regression tests for the gateway request flow.

1. verdict cache leaked one request's normalised payload (image parts, tools, tool intent) into another's;
2. client-controlled session ids let one principal restore another principal's pseudonyms;
3. uninspected request fields (unknown keys, non-text parts, tools, names, params) reached the upstream;
4. the degraded fallback ignored local-only obligations;
5. lone UTF-16 surrogates were accepted in `/v1` bodies.

Every test runs against the real seed policy and controls (deterministic mode, mock connectors).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from acl.contracts.common import ConnectorTier, CostTier, DataClass, InspectionPoint, Phase
from acl.contracts.decision import Verdict
from acl.contracts.inspection import ChatPayload
from acl.controls.base import ControlDeps
from acl.engine.cache import VerdictCache, payload_digest
from acl.engine.engine import Engine
from acl.main import create_app
from acl.policy.loader import load_policy_dir
from acl.routing.dev_access import PermissiveAccess
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import RouteError, Router, RouteRequest
from acl.settings import Settings
from acl.testing import make_context, make_principal

REPO = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO / "policy"
PESEL = "44051401359"
EMAIL = "jan.kowalski@corp.example"
AWS = "AKIA" + "IOSFODNN7EXAMPLE"


@lru_cache(maxsize=1)
def _loaded():  # type: ignore[no-untyped-def]
    return load_policy_dir(POLICY_DIR)


def _headers(user: str, **extra: str) -> dict[str, str]:
    return {"X-ACL-Dev-User": user, "X-ACL-Dev-Groups": "operations", **extra}


@pytest.fixture
def app(tmp_path: Path) -> Iterator[Any]:
    settings = Settings(
        policy_dir=POLICY_DIR,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    application = create_app(settings, allow_anonymous_dev=True)
    with TestClient(application) as client:
        application.state.test_client = client
        yield application


def _client(app: Any) -> TestClient:
    return app.state.test_client


def _grant_all_models(app: Any) -> None:
    """The seed groups grant no embedding model: use the dev resolver (model grants are not under test here)."""
    access = PermissiveAccess(lambda: app.state.engine.policy)
    app.state.access = access
    app.state.control_deps.register("access", access)
    engine = app.state.engine
    app.state.engine = app.state.build_engine(engine.policy, engine.policy_version)


def _calls(app: Any, connector: str) -> list[dict[str, Any]]:
    conn = app.state.connectors.get(connector)
    return conn.calls if conn is not None else []


def _upstream_blob(app: Any) -> str:
    return json.dumps([c["request"] for cid in ("local", "gemini") for c in _calls(app, cid)], ensure_ascii=False)


def _audit(app: Any) -> list[dict[str, Any]]:
    path: Path = app.state.settings.audit_path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _chat(app: Any, body: dict[str, Any], user: str = "anna", **headers: str):  # type: ignore[no-untyped-def]
    return _client(app).post("/v1/chat/completions", json=body, headers=_headers(user, **headers))


def _tool(description: str = "Look up a customer", param_description: str = "customer query") -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": "lookup_customer",
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {"q": {"type": "string", "description": param_description}},
                "required": ["q"],
            },
        },
    }


# =============================================================================== 1. verdict cache


async def test_cache_exact_repro_text_plus_image_and_tools_never_leaks_into_text_only_request() -> None:
    """User A: text + image part + tools; user B: the same text alone. B must see only B's own payload."""
    loaded = _loaded()
    engine = Engine.build(loaded.policy, loaded.version, deps=ControlDeps())
    text = "please summarise the quarterly report"
    ctx_a = make_context(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": text},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,QUFBQQ=="}},
                    ],
                }
            ],
            "tools": [_tool()],
        },
        principal=make_principal("alice"),
    )
    ctx_b = make_context(
        {"messages": [{"role": "user", "content": [{"type": "text", "text": text}]}]},
        principal=make_principal("bob"),
    )
    await engine.evaluate(ctx_a)
    await engine.evaluate(ctx_b)
    seen_by_b = ctx_b.attributes["payload"]
    assert isinstance(seen_by_b, ChatPayload)
    assert seen_by_b.tools is None
    assert seen_by_b.messages[0].content == [{"type": "text", "text": text}]
    assert seen_by_b == ctx_b.payload


async def test_cache_separates_tool_call_intents_by_tool_and_cwd() -> None:
    loaded = _loaded()
    engine = Engine.build(loaded.policy, loaded.version, deps=ControlDeps())
    args = {"package": "leftpad", "version": "1.0.0"}
    npm = make_context({"tool": "npm.install", "arguments": args}, point=InspectionPoint.tool_call)
    pip = make_context({"tool": "pip.install", "arguments": args}, point=InspectionPoint.tool_call)
    await engine.evaluate(npm)
    await engine.evaluate(pip)
    assert pip.attributes["payload"].tool == "pip.install"
    assert {p.ecosystem for p in pip.attributes["intent"].packages} == {"pypi"}
    assert {p.ecosystem for p in npm.attributes["intent"].packages} == {"npm"}

    read = {"tool": "opencode.read", "arguments": {"path": "id_rsa"}}
    home = make_context({**read, "cwd": "/home/anna/project"}, point=InspectionPoint.tool_call)
    ssh = make_context({**read, "cwd": "/home/anna/.ssh"}, point=InspectionPoint.tool_call)
    await engine.evaluate(home)
    await engine.evaluate(ssh)
    assert ssh.attributes["intent"].paths == ["/home/anna/.ssh/id_rsa"]


def test_cache_key_is_the_full_canonical_payload() -> None:
    text_only = make_context({"messages": [{"role": "user", "content": "hi"}]})
    with_tools = make_context({"messages": [{"role": "user", "content": "hi"}], "tools": [_tool()]})
    with_name = make_context({"messages": [{"role": "user", "content": "hi", "name": "x"}]})
    with_params = make_context({"messages": [{"role": "user", "content": "hi"}], "params": {"seed": 1}})
    digests = {payload_digest(c) for c in (text_only, with_tools, with_name, with_params)}
    assert len(digests) == 4
    assert payload_digest(make_context({"messages": [{"role": "user", "content": "hi"}]})) == payload_digest(text_only)
    a = make_context({"tool": "a.read", "arguments": {"path": "x"}}, point=InspectionPoint.tool_call)
    b = make_context({"tool": "b.read", "arguments": {"path": "x"}}, point=InspectionPoint.tool_call)
    assert VerdictCache.key("C", "v", a) != VerdictCache.key("C", "v", b)


def test_cached_verdicts_never_replay_outputs() -> None:
    cache = VerdictCache()
    key = VerdictCache.key("SEC-X-01", "v", make_context("x"))
    base = {
        "control_id": "SEC-X-01",
        "control_type": "x",
        "phase": Phase.normalise,
        "cost_tier": CostTier.deterministic,
    }
    cache.put(key, Verdict(**base, outputs={"payload": "someone else's"}))
    assert cache.get(key) is None and len(cache) == 0


def test_flow_text_only_request_never_receives_another_users_tools(app: Any) -> None:
    text = "hello from the cache test"
    r = _chat(app, {"model": "local", "messages": [{"role": "user", "content": text}], "tools": [_tool()]}, "anna")
    assert r.status_code == 200, r.text
    r = _chat(app, {"model": "local", "messages": [{"role": "user", "content": text}]}, "bob")
    assert r.status_code == 200, r.text
    last = _calls(app, "local")[-1]["request"]
    assert "tools" not in last
    assert last["messages"] == [{"role": "user", "content": text}]


# =============================================================================== 2. session isolation


def test_same_client_session_id_never_restores_another_principals_pseudonyms(app: Any) -> None:
    sid = {"X-Session-Id": "shared-session"}
    r = _chat(app, {"model": "local", "messages": [{"role": "user", "content": f"write to {EMAIL}"}]}, "anna", **sid)
    assert r.status_code == 200, r.text
    assert EMAIL not in _upstream_blob(app)  # pseudonymised on the way out

    probe = {"model": "local", "messages": [{"role": "user", "content": "[[mock:reply contact <EMAIL_1> now]]"}]}
    own = _chat(app, probe, "anna", **sid)  # positive control: the owner's own session restores
    assert own.status_code == 200, own.text
    assert own.json()["choices"][0]["message"]["content"] == f"contact {EMAIL} now"

    other = _chat(app, probe, "bob", **sid)  # same client session id, different principal
    assert EMAIL not in other.text

    vault = app.state.control_deps.get("vault")
    anna = hashlib.sha256(b"dev-anna").hexdigest()[:16]  # namespace of the dev-header principal `dev-anna`
    assert vault.placeholders(f"{anna}:shared-session") == {"<EMAIL_1>"}
    assert vault.placeholders("shared-session") == set()  # the raw client value keys nothing


def test_session_ids_are_namespaced_by_principal_in_chat_and_embeddings(app: Any) -> None:
    _grant_all_models(app)
    r = _chat(
        app, {"model": "local", "messages": [{"role": "user", "content": "hi"}]}, "anna", **{"X-Session-Id": "s1"}
    )
    assert r.status_code == 200, r.text
    r = _client(app).post(
        "/v1/embeddings",
        json={"model": "local/embed", "input": "hello"},
        headers=_headers("anna", **{"X-Session-Id": "s1"}),
    )
    assert r.status_code == 200, r.text
    r = _chat(app, {"model": "local", "messages": [{"role": "user", "content": "hi"}], "user": "s1"}, "bob")
    assert r.status_code == 200, r.text

    anna = hashlib.sha256(b"dev-anna").hexdigest()[:16]
    bob = hashlib.sha256(b"dev-bob").hexdigest()[:16]
    sessions = {rec.get("session_id") for rec in _audit(app) if rec.get("session_id")}
    assert f"{anna}:s1" in sessions and f"{bob}:s1" in sessions
    assert "s1" not in sessions
    points = {rec.get("point") for rec in _audit(app) if rec.get("session_id") == f"{anna}:s1"}
    assert {"ingress", "egress", "embeddings"} <= points


# =============================================================================== 3. uninspected fields


@pytest.mark.parametrize(
    "key,value",
    [
        ("prediction", {"type": "content", "content": "x"}),
        ("logprobs", True),
        ("top_logprobs", 5),
        ("modalities", ["text", "audio"]),
        ("audio", {"voice": "alloy", "format": "wav"}),
        ("functions", [{"name": "f"}]),
        ("function_call", "auto"),
        ("metadata", {"k": "v"}),
        ("store", True),
    ],
)
def test_unknown_chat_keys_are_rejected(app: Any, key: str, value: Any) -> None:
    body = {"model": "smart", "messages": [{"role": "user", "content": "hi"}], key: value}
    r = _chat(app, body)
    assert r.status_code == 400, r.text
    err = r.json()["error"]
    assert err["type"] == "invalid_request_error" and err["code"] == "unsupported_parameter" and err["param"] == key
    assert not _calls(app, "gemini") and not _calls(app, "local")


def test_verified_repro_prediction_with_pesel_and_aws_key_is_rejected(app: Any) -> None:
    body = {
        "model": "smart",
        "messages": [{"role": "user", "content": "hi"}],
        "prediction": {"type": "content", "content": f"PESEL {PESEL} key {AWS}"},
        "tools": [_tool(description=f"mail {EMAIL}")],
    }
    r = _chat(app, body)
    assert r.status_code == 400 and r.json()["error"]["param"] == "prediction"
    assert not _calls(app, "gemini") and not _calls(app, "local")


@pytest.mark.parametrize(
    "part",
    [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,QUFBQQ=="}},
        {"type": "input_audio", "input_audio": {"data": "QUFBQQ==", "format": "wav"}},
        {"type": "file", "file": {"file_data": "QUFBQQ==", "filename": "a.pdf"}},
    ],
)
def test_non_text_content_parts_are_rejected(app: Any, part: dict[str, Any]) -> None:
    body = {"model": "smart", "messages": [{"role": "user", "content": [{"type": "text", "text": "see"}, part]}]}
    r = _chat(app, body)
    assert r.status_code == 400, r.text
    err = r.json()["error"]
    assert err["code"] == "unsupported_content_part" and err["param"] == "messages[0].content[1].type"
    assert not _calls(app, "gemini") and not _calls(app, "local")


@pytest.mark.parametrize(
    "message,param",
    [
        ({"role": "user", "content": "hi", "metadata": {"pesel": PESEL}}, "messages[0].metadata"),
        ({"role": "user", "content": [{"type": "text", "text": "hi", "extra": PESEL}]}, "messages[0].content[0].extra"),
        (
            {
                "role": "assistant",
                "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f", "arguments": "{}", "x": 1}}],
            },
            "messages[0].tool_calls[0].function.x",
        ),
    ],
)
def test_unknown_message_keys_are_rejected(app: Any, message: dict[str, Any], param: str) -> None:
    r = _chat(app, {"model": "smart", "messages": [message]})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "unsupported_parameter" and r.json()["error"]["param"] == param


def test_email_in_tool_description_is_inspected_and_kept_local(app: Any) -> None:
    body = {"model": "smart", "messages": [{"role": "user", "content": "hi"}], "tools": [_tool(f"mail {EMAIL}")]}
    r = _chat(app, body)
    assert r.status_code == 200, r.text
    assert r.headers["x-acl-model"] == "local/qwen3.8-27b"  # confidential data never goes to the cloud (LOCK-01)
    assert not _calls(app, "gemini")
    sent = _calls(app, "local")[-1]["request"]
    assert EMAIL not in json.dumps(sent) and "<EMAIL_1>" in sent["tools"][0]["function"]["description"]


def test_pesel_in_tool_parameter_description_is_inspected_and_kept_local(app: Any) -> None:
    body = {
        "model": "smart",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [_tool(param_description=f"customer PESEL, e.g. {PESEL}")],
    }
    r = _chat(app, body)
    assert r.status_code == 200, r.text
    assert r.headers["x-acl-model"] == "local/qwen3.8-27b"
    assert not _calls(app, "gemini") and PESEL not in _upstream_blob(app)
    assert PESEL not in app.state.settings.audit_path.read_text(encoding="utf-8")
    records = [rec for rec in _audit(app) if rec.get("point") == "ingress"]
    assert records and records[-1]["route"]["factors"]["data_class"] in ("confidential", "restricted")


def test_secret_in_tool_description_is_blocked(app: Any) -> None:
    body = {"model": "smart", "messages": [{"role": "user", "content": "hi"}], "tools": [_tool(f"use key {AWS}")]}
    r = _chat(app, body)
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "SEC-SECRET-01"
    assert not _calls(app, "gemini") and not _calls(app, "local")


@pytest.mark.parametrize(
    "body_extra,message_extra",
    [({"stop": [f"key {AWS}"]}, {}), ({}, {"name": AWS})],
)
def test_secret_in_params_or_message_name_is_blocked(app: Any, body_extra: dict, message_extra: dict) -> None:
    body = {"model": "smart", "messages": [{"role": "user", "content": "hi", **message_extra}], **body_extra}
    r = _chat(app, body)
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "SEC-SECRET-01"  # blocked by the secret control, not by model access
    assert not _calls(app, "gemini") and not _calls(app, "local")


@pytest.mark.parametrize(
    "properties",
    [
        # `a-b` parses like `a.b`: a mask aimed at it would land on the decoy and the raw value would leave
        {"a-b": {"type": "string", "description": f"mail {EMAIL}"}, "a": {"b": {"description": "decoy"}}},
        # `my-field` resolves to nothing: the mask would be skipped
        {"my-field": {"type": "string", "description": f"mail {EMAIL}"}},
    ],
)
def test_unaddressable_tool_schema_key_fails_closed(app: Any, properties: dict[str, Any]) -> None:
    tool = _tool()
    tool["function"]["parameters"]["properties"] = properties
    r = _chat(app, {"model": "local", "messages": [{"role": "user", "content": "hi"}], "tools": [tool]})
    assert r.status_code == 403, r.text
    record = _audit(app)[-1]
    assert "ENG-REDACT-01" in json.dumps(record["decision"])
    assert not _calls(app, "local") and EMAIL not in _upstream_blob(app)
    assert EMAIL not in app.state.settings.audit_path.read_text(encoding="utf-8")  # nor in the audit log


def test_allowed_params_are_forwarded_and_inspected(app: Any) -> None:
    body = {
        "model": "smart",
        "messages": [{"role": "user", "content": "hi"}],
        "temperature": 0.2,
        "max_tokens": 50,
        "seed": 7,
        "stop": ["END"],
        "tool_choice": "auto",
        "response_format": {"type": "json_object"},
        "user": "client-session",
    }
    r = _chat(app, body)
    assert r.status_code == 200, r.text
    sent = _calls(app, "gemini")[-1]["request"]
    assert sent["temperature"] == 0.2 and sent["max_tokens"] == 50 and sent["stop"] == ["END"]
    assert "user" not in sent and "stream" not in sent


def test_embeddings_allowlist(app: Any) -> None:
    _grant_all_models(app)
    client = _client(app)
    r = client.post(
        "/v1/embeddings", json={"model": "local/embed", "input": "x", "extra": PESEL}, headers=_headers("anna")
    )
    assert r.status_code == 400 and r.json()["error"]["param"] == "extra"
    r = client.post(
        "/v1/embeddings",
        json={"model": "local/embed", "input": "x", "encoding_format": "base64"},
        headers=_headers("anna"),
    )
    assert r.status_code == 400 and r.json()["error"]["param"] == "encoding_format"
    r = client.post(
        "/v1/embeddings",
        json={"model": "local/embed", "input": "x", "encoding_format": "float", "dimensions": 8, "user": "u"},
        headers=_headers("anna"),
    )
    assert r.status_code == 200, r.text


# =============================================================================== 4. degraded fallback


def _router(policy: Any, version: str) -> tuple[Router, ConnectorRegistry]:
    registry = ConnectorRegistry(deterministic=True)
    return Router(policy, registry.table_for(policy, version)), registry


async def _usable(policy: Any) -> dict[str, list[DataClass]]:
    return await PermissiveAccess(lambda: policy).usable_models(None)  # type: ignore[arg-type]


async def test_degraded_cloud_target_never_serves_a_force_local_request() -> None:
    policy = _loaded().policy.model_copy(deep=True)
    policy.routing.targets.degraded = "gemini/flash"  # misconfiguration
    router, registry = _router(policy, "v-degraded-cloud")
    registry.set_kill_switch("local", True, "down")
    req = RouteRequest(requested="smart", data_class=DataClass.public, usable=await _usable(policy), force_local=True)
    with pytest.raises(RouteError) as exc:
        router.route(req)
    assert exc.value.status == 503


async def test_degraded_cloud_target_never_serves_confidential_data_even_if_usable() -> None:
    policy = _loaded().policy.model_copy(deep=True)
    policy.routing.targets.degraded = "gemini/flash"
    router, registry = _router(policy, "v-degraded-cloud-2")
    usable = await _usable(policy)
    usable["gemini/flash"] = list(DataClass)  # grants misconfigured too
    registry.set_kill_switch("local", True, "down")
    with pytest.raises(RouteError) as exc:
        router.route(RouteRequest(requested="local", data_class=DataClass.confidential, usable=usable))
    assert exc.value.status == 503
    with pytest.raises(RouteError):  # explicitly local public request: no silent move to the cloud either
        router.route(RouteRequest(requested="local", data_class=DataClass.public, usable=usable))


async def test_runtime_failover_honours_force_local() -> None:
    policy = _loaded().policy.model_copy(deep=True)
    policy.routing.targets.degraded = "gemini/flash"
    router, _ = _router(policy, "v-degraded-cloud-3")
    usable = await _usable(policy)
    primary = router.route(RouteRequest(requested="smart", usable=usable, force_local=True))
    assert primary.info.tier == ConnectorTier.local
    req = RouteRequest(requested="smart", usable=usable, force_local=True, force_reason="route_local")
    assert router.degraded_route(primary, req, "HTTP 503") is None
    # a cloud primary may still fail over to a (local) degraded target
    policy.routing.targets.degraded = "local/qwen3.8-27b"
    router, _ = _router(policy, "v-degraded-local")
    cloud = router.route(RouteRequest(requested="smart", usable=usable))
    fb = router.degraded_route(cloud, RouteRequest(requested="smart", usable=usable), "HTTP 503")
    assert fb is not None and fb.info.model == "local/qwen3.8-27b" and fb.info.degraded


def test_flow_degraded_cloud_target_returns_503_for_local_only_data(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policy"
    shutil.copytree(POLICY_DIR, policy_dir)
    routing = policy_dir / "routing.yaml"
    routing.write_text(
        routing.read_text(encoding="utf-8").replace("degraded: local/qwen3.8-27b", "degraded: gemini/flash"),
        encoding="utf-8",
        newline="\n",
    )
    settings = Settings(
        policy_dir=policy_dir,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
    )
    application = create_app(settings, allow_anonymous_dev=True)
    with TestClient(application) as client:
        application.state.connectors.set_kill_switch("local", True, "down")
        for text in (f"PESEL {PESEL}", "plain public text"):  # confidential, and explicitly-local public data
            body = {"model": "local", "messages": [{"role": "user", "content": text}]}
            r = client.post("/v1/chat/completions", json=body, headers=_headers("anna"))
            assert r.status_code == 503, r.text
        gemini = application.state.connectors.get("gemini")
        assert gemini is None or not gemini.calls


# =============================================================================== 5. unicode hygiene


@pytest.mark.parametrize(
    "path,raw",
    [
        ("/v1/chat/completions", b'{"model":"local","messages":[{"role":"user","content":"hi \\ud800 there"}]}'),
        ("/v1/chat/completions", b'{"model":"local","messages":[{"role":"user","content":"hi","name":"\\udfff"}]}'),
        ("/v1/chat/completions", b'{"model":"local","messages":[{"role":"user","content":"hi"}],"\\ud83d":1}'),
        ("/v1/embeddings", b'{"model":"local/embed","input":["ok","\\udc00"]}'),
    ],
)
def test_lone_surrogates_are_rejected_before_processing(app: Any, path: str, raw: bytes) -> None:
    before = len(_audit(app))
    r = _client(app).post(path, content=raw, headers={**_headers("anna"), "content-type": "application/json"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "invalid_unicode"
    assert len(_audit(app)) == before  # rejected before the pipeline / audit
    assert not _calls(app, "local") and not _calls(app, "gemini")


def test_valid_surrogate_pairs_are_accepted(app: Any) -> None:
    raw = b'{"model":"local","messages":[{"role":"user","content":"hi \\ud83d\\ude00"}]}'
    r = _client(app).post(
        "/v1/chat/completions", content=raw, headers={**_headers("anna"), "content-type": "application/json"}
    )
    assert r.status_code == 200, r.text
