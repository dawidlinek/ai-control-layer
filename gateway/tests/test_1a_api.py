"""1A: the OpenAI-compatible request path end to end (mock connectors, fake access/vault/controls)."""

from __future__ import annotations

import json
import re
import shutil
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import httpx
import jsonschema
import pytest
import uvicorn
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from acl.audit.chain import verify_chain
from acl.contracts.canonical import value_hash
from acl.contracts.common import Action
from acl.contracts.decision import Finding
from acl.controls.base import Control, register_control
from acl.controls.pii.vault import Planned, PseudonymVault
from acl.engine.text import iter_texts
from acl.main import create_app
from acl.routing.dev_access import DevAccessCheck, PermissiveAccess
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
EVENT_SCHEMA = json.loads((REPO / "contracts" / "event.schema.json").read_text(encoding="utf-8"))
INSTALLERS_1A = ["acl.audit.wiring:install", "acl.api.wiring:install"]
PESEL = "44051401359"
PERSON = "Jan Kowalski"

# ------------------------------------------------------------------ fake controls (registered once)


class _AnyParams(BaseModel):
    model_config = ConfigDict(extra="allow")


@register_control
class T1aPseudo(Control):
    """Pseudonymises PESEL and a fixed person name; raises the data class when a PESEL is present."""

    type = "t1a_pseudo"
    Params = _AnyParams
    commits: ClassVar[list[str]] = []

    async def inspect(self, ctx):  # type: ignore[no-untyped-def]
        findings = []
        data_class = None
        vault = self.deps.get("vault")
        for field, text in iter_texts(ctx.attributes.get("payload", ctx.payload)):
            for entity, pattern, placeholder in (
                ("PESEL", re.escape(PESEL), "<PESEL_1>"),
                ("PERSON", re.escape(PERSON), "<PERSON_1>"),
            ):
                for m in re.finditer(pattern, text):
                    findings.append(
                        Finding(
                            entity_type=entity,
                            field=field,
                            start=m.start(),
                            end=m.end(),
                            replacement=placeholder,
                            value_hash=value_hash(m.group(), "test-salt"),
                            rule_id="T1A-PSEUDO-01",
                        )
                    )
                    if vault is not None:
                        vault.add(ctx.session_id, placeholder, entity, m.group())
                    if entity == "PESEL":
                        data_class = "confidential"
        if not findings:
            return self.verdict()
        return self.verdict(
            action=Action.pseudonymise, rule_ids=["T1A-PSEUDO-01"], findings=findings, data_class=data_class
        )

    async def commit(self, ctx, decision):  # type: ignore[no-untyped-def]
        self.commits.append(f"{ctx.point}:{decision.action}")


@register_control
class T1aKeyword(Control):
    """Blocks (final) when `params.keyword` appears in the text; configurable action."""

    type = "t1a_keyword"
    Params = _AnyParams
    cacheable = True
    calls: ClassVar[int] = 0

    async def inspect(self, ctx):  # type: ignore[no-untyped-def]
        type(self).calls += 1
        kw = self.config.params["keyword"]
        for field, text in iter_texts(ctx.payload):
            idx = text.find(kw)
            if idx >= 0:
                return self.verdict(
                    action=Action(self.config.params.get("action", "block")),
                    final=True,
                    rule_ids=[self.id],
                    reason=f"keyword rule {self.id} matched",
                    findings=[Finding(entity_type="KEYWORD", field=field, start=idx, end=idx + len(kw))],
                )
        return self.verdict()


class FakeVault(PseudonymVault):
    """The real vault plus test helpers: `add()` seeds a mapping, `restored` records restore calls."""

    def __init__(self) -> None:
        super().__init__()
        self.restored: list[tuple[str, set[str]]] = []

    def add(self, session_id: str, placeholder: str, entity_type: str, value: str) -> None:
        self.register(session_id, [Planned(entity_type, value, value, placeholder)])

    def restore(self, session_id: str, text: str, *, allowed_entity_types: set[str]) -> str:
        self.restored.append((session_id, set(allowed_entity_types)))
        return super().restore(session_id, text, allowed_entity_types=allowed_entity_types)


class FakeAccess(PermissiveAccess):
    def __init__(self, policy_getter: Callable[[], Any], deny: set[str] | None = None) -> None:
        super().__init__(policy_getter)
        self.deny = deny or set()

    async def check_model(self, principal, name):  # type: ignore[no-untyped-def]
        if name in self.deny:
            return DevAccessCheck(False, "SEC-MODEL-01", f"model {name} is not granted", "fake")
        return DevAccessCheck(True)


# ------------------------------------------------------------------ harness

CONTROLS = """  - id: T1A-PSEUDO-01
    type: t1a_pseudo
    stages: [ingress, embeddings]
    cost_tier: deterministic
    timeout_ms: 200
    params: {restore_entity_types: [PERSON, PESEL]}
  - id: T1A-BLOCKIN-01
    type: t1a_keyword
    stages: [ingress]
    cost_tier: deterministic
    timeout_ms: 200
    params: {keyword: BLOCKME}
  - id: T1A-BLOCKOUT-01
    type: t1a_keyword
    stages: [egress]
    cost_tier: deterministic
    timeout_ms: 200
    params: {keyword: FORBIDDEN-OUT}
"""


def make_policy(tmp: Path, budgets_stream: str | None = None) -> Path:
    dst = tmp / "policy"
    shutil.copytree(REPO / "policy", dst)
    seed = (dst / "controls.yaml").read_text(encoding="utf-8")
    # append the test controls to the (disabled) seed controls, which org locks reference
    before, sep, after = seed.rpartition("\nsignatures:\n")
    assert sep
    (dst / "controls.yaml").write_text(before + "\n" + CONTROLS + sep + after, encoding="utf-8", newline="\n")
    if budgets_stream:
        text = (dst / "budgets.yaml").read_text(encoding="utf-8")
        text = re.sub(r"  stream:\n(?:    .*\n)+", budgets_stream, text)
        (dst / "budgets.yaml").write_text(text, encoding="utf-8", newline="\n")
    return dst


def build_app(tmp: Path, *, budgets_stream: str | None = None, deny: set[str] | None = None):  # type: ignore[no-untyped-def]
    settings = Settings(
        policy_dir=make_policy(tmp, budgets_stream),
        database_url=f"sqlite+aiosqlite:///{tmp / 'test.db'}",
        audit_path=tmp / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    # 1A in isolation: only the audit + gateway installers, with fake access / vault / controls
    app = create_app(settings, allow_anonymous_dev=True, installers=INSTALLERS_1A)
    app.state.access = FakeAccess(lambda: app.state.engine.policy if app.state.engine else None, deny)
    app.state.vault = FakeVault()
    app.state.control_deps.register("vault", app.state.vault)
    app.state.control_deps.register("access", app.state.access)  # SEC-MODEL-01 (enabled in the seed policy)
    return app, settings


def audit_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def assert_audit_valid(path: Path) -> list[dict[str, Any]]:
    records = audit_records(path)
    for rec in records:
        jsonschema.validate(rec, EVENT_SCHEMA)
    result = verify_chain(path)
    assert result.ok, result.message
    assert result.records == len(records)
    return records


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[tuple[TestClient, Any, Settings]]:
    T1aPseudo.commits.clear()
    app, settings = build_app(tmp_path)
    with TestClient(app) as client:
        yield client, app, settings
    # every decision path emits schema-valid records and the chain verifies
    assert_audit_valid(settings.audit_path)


def chat(client: TestClient, content: str, model: str = "local/qwen3.8-27b", **extra: Any) -> httpx.Response:
    headers = extra.pop("headers", None)
    body = {"model": model, "messages": [{"role": "user", "content": content}], **extra}
    return client.post("/v1/chat/completions", json=body, headers=headers)


def sse_events(text: str) -> list[Any]:
    out: list[Any] = []
    for block in text.split("\n\n"):
        block = block.strip()
        if block.startswith("data:"):
            data = block[5:].strip()
            out.append("[DONE]" if data == "[DONE]" else json.loads(data))
    return out


def stream_text(events: list[Any]) -> str:
    return "".join(c["choices"][0]["delta"].get("content") or "" for c in events if c != "[DONE]" and c.get("choices"))


# ------------------------------------------------------------------ basic path


def test_chat_roundtrip_headers_and_audit(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, "hello world", headers={"X-Session-Id": "sess-abc", "X-Client-App": "librechat"})
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == "MOCK[local/qwen3.8-27b]: hello world"
    assert r.headers["x-acl-decision"] == "allow"
    assert r.headers["x-acl-model"] == "local/qwen3.8-27b"
    assert r.headers["x-acl-degraded"] == "false"
    trace = r.headers["x-acl-trace-id"]
    records = assert_audit_valid(settings.audit_path)
    assert [x["point"] for x in records] == ["ingress", "egress"]
    assert {x["trace_id"] for x in records} == {trace}
    # the client session id is namespaced by the principal (CP1: sessions never cross principals)
    ns, _, client_sid = records[0]["session_id"].partition(":")
    assert client_sid == "sess-abc" and re.fullmatch(r"[0-9a-f]{16}", ns)
    assert records[0]["client"]["app"] == "librechat"
    assert records[1]["usage"]["input_tokens"] > 0 and records[1]["usage"]["output_tokens"] > 0
    assert records[1]["route"]["model"] == "local/qwen3.8-27b" and records[1]["latency"]["upstream_ms"] > 0
    assert records[0]["redacted_payload"] == "hello world"
    ev = client.get(f"/admin/v1/events/{records[0]['event_id']}")
    assert ev.status_code == 200 and ev.json()["trace_id"] == trace


def test_validation_errors(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    assert client.post("/v1/chat/completions", json={"messages": []}).status_code == 400
    assert client.post("/v1/chat/completions", json={"model": "x", "messages": []}).status_code == 400
    assert client.post("/v1/chat/completions", content=b"{nope").status_code == 400
    r = chat(client, "hi", model="no-such-model")
    assert r.status_code == 404 and r.json()["error"]["code"] == "model_not_found"
    assert chat(client, "hi", n=2).status_code == 400


def test_models_listing(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    ids = {m["id"] for m in client.get("/v1/models").json()["data"]}
    assert {"auto", "local/qwen3.8-27b", "gemini/flash", "smart"} <= ids


def test_hygiene_strips_reasoning_and_logprobs(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    r = chat(client, "[[mock:reasoning my secret plan]]")
    msg, choice = r.json()["choices"][0]["message"], r.json()["choices"][0]
    assert "reasoning_content" not in msg and "logprobs" not in choice
    assert "secret plan" not in r.text


def test_replay_buffer_and_commit(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, _ = harness
    chat(client, f"my pesel {PESEL}")
    recent = app.state.replay_buffer.recent(10)
    assert [c.point.value for c, _ in recent] == ["egress", "ingress"]  # newest first
    assert app.state.replay_buffer.recent(10, point=recent[1][0].point)[0][0].point.value == "ingress"
    assert recent[1][0].attributes == {}  # clean slate for replay
    assert "ingress:pseudonymise" in T1aPseudo.commits  # engine.commit called for the enforced decision


# ------------------------------------------------------------------ routing


def test_auto_routes_by_data_class(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, "plain question", model="auto")
    assert r.headers["x-acl-model"] == "gemini/flash"  # public → ext_small
    r = chat(client, f"customer pesel {PESEL}", model="auto")
    assert r.headers["x-acl-model"] == "local/qwen3.8-27b"  # confidential → local_only
    routes = [x["route"] for x in audit_records(settings.audit_path) if x["point"] == "ingress"]
    assert "local_only" in routes[1]["reason"] and routes[1]["factors"]["data_class"] == "confidential"
    assert routes[0]["tier"] == "cloud" and routes[1]["tier"] == "local"


def test_org_lock_reroutes_explicit_cloud_model(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, f"pesel {PESEL}", model="gemini/flash")
    assert r.status_code == 200 and r.headers["x-acl-model"] == "local/qwen3.8-27b"
    route = next(x["route"] for x in audit_records(settings.audit_path) if x["point"] == "ingress")
    assert "LOCK-01" in route["reason"] and route["degraded"] is False


def test_kill_switch_degrades_and_survives_policy_reload(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, settings = harness
    r = client.post("/admin/v1/connectors/gemini/kill-switch", json={"engaged": True, "reason": "provider incident"})
    assert r.status_code == 200 and r.json()["kill_switch"] is True
    r = chat(client, "hello", model="smart")
    assert r.headers["x-acl-model"] == "local/qwen3.8-27b" and r.headers["x-acl-degraded"] == "true"
    # a new policy version builds a new routing table; the kill switch is held by the registry
    engine = app.state.engine
    app.state.engine = app.state.build_engine(engine.policy, "reloaded-v2")
    r = chat(client, "hello again", model="smart")
    assert r.headers["x-acl-degraded"] == "true"
    listing = {c["id"]: c for c in client.get("/admin/v1/connectors").json()}
    assert listing["gemini"]["kill_switch"] is True and listing["local"]["kill_switch"] is False
    client.post("/admin/v1/connectors/gemini/kill-switch", json={"engaged": False, "reason": "resolved"})
    assert chat(client, "hello", model="smart").headers["x-acl-degraded"] == "false"
    events = client.get("/admin/v1/events", params={"event_type": "system_alert"}).json()
    assert len(events) == 2  # engage + release are audited
    assert any(x["route"] and x["route"]["degraded"] for x in audit_records(settings.audit_path) if x.get("route"))


def test_model_system_prompt_is_prepended(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, _ = harness
    chat(client, "podsumuj", model="local/loan-memo")
    sent = app.state.connectors.get("local").calls[-1]["request"]["messages"]
    assert sent[0]["role"] == "system" and "credit analyst" in sent[0]["content"]
    assert sent[-1]["content"] == "podsumuj"


# ------------------------------------------------------------------ enforcement


def test_pseudonymise_roundtrip_restores_for_client(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, settings = harness
    r = chat(client, f"Napisz notatkę o {PERSON}, PESEL {PESEL}", headers={"X-Session-Id": "sess-1"})
    assert r.status_code == 200
    upstream = app.state.connectors.get("local").calls[-1]["request"]["messages"][-1]["content"]
    assert "<PERSON_1>" in upstream and "<PESEL_1>" in upstream
    assert PESEL not in upstream and PERSON not in upstream  # the model never sees raw values
    content = r.json()["choices"][0]["message"]["content"]
    assert PERSON in content and PESEL in content  # restored for the client (both allow-listed by policy)
    assert r.headers["x-acl-decision"] == "pseudonymise"
    raw = settings.audit_path.read_text(encoding="utf-8")
    assert PESEL not in raw and PERSON not in raw  # nothing raw in the audit log
    ingress = audit_records(settings.audit_path)[0]
    assert "<PESEL_1>" in ingress["redacted_payload"] and ingress["decision"]["action"] == "pseudonymise"
    pseudo = next(v for v in ingress["verdicts"] if v["control_id"] == "T1A-PSEUDO-01")
    assert pseudo["findings"][0]["value_hash"]


def test_restore_is_limited_to_allow_listed_types_and_text(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, _ = harness
    app.state.vault.restored.clear()
    # tool_call arguments never get restored, even for an allow-listed type
    r = chat(client, f'[[mock:tool mail.send {{"to": "{PERSON}"}}]]', headers={"X-Session-Id": "sess-2"})
    msg = r.json()["choices"][0]["message"]
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"to": "<PERSON_1>"}
    # the vault is only asked for the policy allow-list
    r = chat(client, f"about {PERSON}", headers={"X-Session-Id": "sess-3"})
    assert PERSON in r.json()["choices"][0]["message"]["content"]
    assert app.state.vault.restored[-1][1] == {"PERSON", "PESEL"}


def test_restore_default_allow_list_when_policy_has_none(tmp_path: Path) -> None:
    app, settings = build_app(tmp_path)
    policy_file = settings.policy_dir / "controls.yaml"
    policy_file.write_text(
        policy_file.read_text(encoding="utf-8").replace(
            "params: {restore_entity_types: [PERSON, PESEL]}", "params: {}"
        ),
        encoding="utf-8",
        newline="\n",
    )
    with TestClient(app) as client:
        r = chat(client, f"about {PERSON} pesel {PESEL}")
        content = r.json()["choices"][0]["message"]["content"]
        assert PERSON in content  # PERSON is in the default allow-list
        assert "<PESEL_1>" in content and PESEL not in content  # PESEL is not
    assert_audit_valid(settings.audit_path)


def test_ingress_block_is_403_with_rule(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, "please BLOCKME now")
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "policy_violation" and err["code"] == "T1A-BLOCKIN-01"
    assert err["trace_id"] == r.headers["x-acl-trace-id"]
    records = assert_audit_valid(settings.audit_path)
    assert len(records) == 1 and records[0]["decision"]["action"] == "block"
    incidents = client.get("/admin/v1/incidents").json()
    assert incidents[0]["category"] == "blocked_request" and "T1A-BLOCKIN-01" in incidents[0]["rule_ids"]


def test_egress_block_non_stream(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, "[[mock:reply here is FORBIDDEN-OUT text]]")
    assert r.status_code == 403 and r.json()["error"]["code"] == "T1A-BLOCKOUT-01"
    assert "FORBIDDEN-OUT" not in r.text
    records = assert_audit_valid(settings.audit_path)
    assert [x["point"] for x in records] == ["ingress", "egress"]
    assert records[1]["decision"]["action"] == "block" and records[1]["usage"]["output_tokens"] > 0
    assert client.get("/admin/v1/incidents").json()[0]["category"] == "blocked_response"


def test_forbidden_model_is_403_with_incident(tmp_path: Path) -> None:
    app, settings = build_app(tmp_path, deny={"local/qwen3.8-27b"})
    with TestClient(app) as client:
        r = chat(client, "write code", model="local/qwen3.8-27b")
        assert r.status_code == 403
        err = r.json()["error"]
        assert err["type"] == "forbidden_model" and err["code"] == "SEC-MODEL-01" and err["trace_id"]
        assert app.state.connectors.get("local").calls == []  # never reached the upstream
        incidents = client.get("/admin/v1/incidents").json()
        assert len(incidents) == 1 and incidents[0]["category"] == "forbidden_model"
        assert incidents[0]["subject"] == "dev" and len(incidents[0]["event_ids"]) == 2
        # a second attempt within 10 minutes is grouped into the same incident
        chat(client, "again", model="local/qwen3.8-27b")
        grouped = client.get("/admin/v1/incidents").json()
        assert len(grouped) == 1 and len(grouped[0]["event_ids"]) == 4
        # the panel can triage it
        patched = client.patch(
            f"/admin/v1/incidents/{grouped[0]['id']}", json={"status": "triaged", "assignee": "anna", "note": "looking"}
        )
        assert patched.json()["status"] == "triaged" and patched.json()["notes"][0]["text"] == "looking"
        assert client.get(f"/admin/v1/incidents/{grouped[0]['id']}").json()["assignee"] == "anna"
        assert client.get("/admin/v1/incidents", params={"status": "open"}).json() == []
    records = assert_audit_valid(settings.audit_path)
    assert records[0]["decision"]["action"] == "block" and records[0]["decision"]["rule_ids"] == ["SEC-MODEL-01"]
    assert {x["event_type"] for x in records} == {"decision", "incident"}


def test_access_fails_closed_without_resolver(tmp_path: Path) -> None:
    app, _ = build_app(tmp_path)
    app.state.access = None
    app.state.allow_anonymous_dev = False  # production mode: no resolver installed → deny
    app.state.authenticator = None
    from acl.contracts.inspection import Principal

    async def auth(request, creds):  # type: ignore[no-untyped-def]
        return Principal(subject="u1", username="u1", roles=["acl-admin"])

    app.state.authenticator = auth
    with TestClient(app) as client:
        r = chat(client, "hi")
        assert r.status_code == 403 and r.json()["error"]["type"] == "forbidden"


# ------------------------------------------------------------------ streaming


def test_stream_reassembles_and_audits(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    text = " ".join(f"word{i}" for i in range(120))  # not repetitive: the n-gram guard stays quiet
    r = chat(client, f"[[mock:reply {text}]]", stream=True, stream_options={"include_usage": True})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["x-acl-model"] == "local/qwen3.8-27b" and r.headers["x-acl-trace-id"]
    events = sse_events(r.text)
    assert events[-1] == "[DONE]"
    assert stream_text(events) == text.strip()
    assert all(e["object"] == "chat.completion.chunk" for e in events[:-1])
    finish = [e for e in events[:-1] if e["choices"] and e["choices"][0]["finish_reason"]]
    assert finish[-1]["choices"][0]["finish_reason"] == "stop"
    assert events[-2]["choices"] == [] and events[-2]["usage"]["completion_tokens"] > 0  # include_usage
    records = assert_audit_valid(settings.audit_path)
    assert [x["point"] for x in records] == ["ingress", "egress"]
    assert records[1]["usage"]["output_tokens"] > 0 and records[1]["response_hash"]


def test_stream_pseudonyms_restored_across_chunk_boundaries(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, settings = harness
    # 16-char mock chunks split the placeholder; the guard must hold it back until whole
    prefix = "x" * 11
    r = chat(
        client, f"[[mock:reply {prefix}<PERSON_1> and <PESEL_1> done]]", stream=True, headers={"X-Session-Id": "s4"}
    )
    sid = audit_records(settings.audit_path)[-1]["session_id"]  # principal-namespaced "s4"
    assert sid.endswith(":s4")
    app.state.vault.add(sid, "<PERSON_1>", "PERSON", PERSON)
    app.state.vault.add(sid, "<PESEL_1>", "PESEL", PESEL)
    r = chat(
        client, f"[[mock:reply {prefix}<PERSON_1> and <PESEL_1> done]]", stream=True, headers={"X-Session-Id": "s4"}
    )
    events = sse_events(r.text)
    deltas = [e["choices"][0]["delta"].get("content") for e in events[:-1] if e["choices"]]
    assert stream_text(events) == f"{prefix}{PERSON} and {PESEL} done"
    assert not any(d and "<" in d and ">" not in d for d in deltas)  # never a partial placeholder on the wire


def test_stream_egress_block_terminates(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    body = " ".join(f"ok{i}" for i in range(120)) + " FORBIDDEN-OUT " + " ".join(f"tail{i}" for i in range(80))
    r = chat(client, f"[[mock:reply {body}]]", stream=True)
    assert r.status_code == 200
    events = sse_events(r.text)
    assert events[-1] == "[DONE]"
    err = next(e for e in events[:-1] if "error" in e)
    assert err["error"]["code"] == "T1A-BLOCKOUT-01" and err["error"]["type"] == "policy_violation"
    assert "FORBIDDEN-OUT" not in r.text and "tail" not in stream_text(events)
    assert len(stream_text(events)) < len(body) // 2
    assert not any(e["choices"][0]["finish_reason"] for e in events[:-1] if e.get("choices"))
    records = assert_audit_valid(settings.audit_path)
    assert records[-1]["point"] == "egress" and records[-1]["decision"]["action"] == "block"


def test_stream_tool_calls_are_emitted_whole_after_inspection(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    r = chat(client, f'[[mock:tool mail.send {{"to": "{PERSON}"}}]]', stream=True, headers={"X-Session-Id": "s5"})
    events = sse_events(r.text)
    calls = [e for e in events[:-1] if e["choices"] and e["choices"][0]["delta"].get("tool_calls")]
    assert len(calls) == 1
    fn = calls[0]["choices"][0]["delta"]["tool_calls"][0]["function"]
    assert fn["name"] == "mail.send" and json.loads(fn["arguments"]) == {"to": "<PERSON_1>"}
    assert [e for e in events[:-1] if e["choices"] and e["choices"][0]["finish_reason"]][-1]["choices"][0][
        "finish_reason"
    ] == "tool_calls"


def test_stream_output_cap(tmp_path: Path) -> None:
    caps = "  stream:\n    max_output_tokens: 8\n    max_reasoning_tokens: 2048\n    holdback_chars: 16\n"
    app, settings = build_app(tmp_path, budgets_stream=caps)
    with TestClient(app) as client:
        r = chat(client, "[[mock:repeat 100 abcd]]", stream=True)
        events = sse_events(r.text)
        content = stream_text(events)
        assert 0 < len(content) < 100 * 4 and len(content) <= 80
        finish = [e for e in events[:-1] if e["choices"] and e["choices"][0]["finish_reason"]]
        assert finish[-1]["choices"][0]["finish_reason"] == "length"
        alerts = client.get("/admin/v1/events", params={"event_type": "system_alert"}).json()
        assert len(alerts) == 1
    assert_audit_valid(settings.audit_path)


def test_stream_upstream_error_before_first_byte(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    r = chat(client, "[[mock:error 503]]", stream=True)
    # retryable → degraded fallback is the same mock error (target == local/qwen3.8-27b == current) → 502
    assert r.status_code == 502 and r.json()["error"]["type"] == "upstream_error"
    records = assert_audit_valid(settings.audit_path)
    assert [x["event_type"] for x in records] == ["decision", "system_alert"]


def test_upstream_failure_fails_over_to_degraded_target(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, settings = harness
    engine = app.state.engine
    app.state.connectors.table_for(engine.policy, engine.policy_version)  # instantiate the connectors
    cloud = app.state.connectors.get("gemini")
    original = cloud.chat

    async def failing(model, request):  # type: ignore[no-untyped-def]
        from acl.routing.connectors.base import ConnectorError

        raise ConnectorError("boom", status=503, retryable=True)

    cloud.chat = failing
    r = chat(client, "hello", model="smart")
    cloud.chat = original
    assert (
        r.status_code == 200
        and r.headers["x-acl-model"] == "local/qwen3.8-27b"
        and r.headers["x-acl-degraded"] == "true"
    )
    alerts = client.get("/admin/v1/events", params={"event_type": "system_alert"}).json()
    assert len(alerts) == 1
    egress = next(x for x in audit_records(settings.audit_path) if x["point"] == "egress")
    assert egress["route"]["degraded"] is True and "failed" in egress["route"]["reason"]


# ------------------------------------------------------------------ embeddings


def test_embeddings_inspected_and_audited(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, settings = harness
    engine = app.state.engine
    app.state.connectors.table_for(engine.policy, engine.policy_version)
    local = app.state.connectors.get("local")
    sent: list[dict[str, Any]] = []
    original = local.embeddings

    async def spy(model, request):  # type: ignore[no-untyped-def]
        sent.append(request)
        return await original(model, request)

    local.embeddings = spy
    r = client.post("/v1/embeddings", json={"model": "local/embed", "input": [f"pesel {PESEL}", "other"]})
    assert r.status_code == 200
    data = r.json()
    assert len(data["data"]) == 2 and data["model"] == "local/embed"
    assert sent[0]["input"][0] == "pesel <PESEL_1>"  # outbound data is pseudonymised
    records = assert_audit_valid(settings.audit_path)
    assert records[0]["point"] == "embeddings" and records[0]["usage"]["input_tokens"] > 0
    # default model from routing.targets.embeddings
    assert client.post("/v1/embeddings", json={"input": "x"}).json()["model"] == "local/embed"
    assert (
        client.post("/v1/embeddings", json={"model": "local/qwen3.8-27b", "input": "x"}).status_code == 400
    )  # not an embedder


# ------------------------------------------------------------------ cache (engine level, via the app's engine)


async def test_verdict_cache_hits_on_identical_content(tmp_path: Path) -> None:
    from acl.testing import make_context

    app, _ = build_app(tmp_path)
    with TestClient(app):
        engine = app.state.engine
        T1aKeyword.calls = 0
        d1 = await engine.evaluate(make_context("same text"))
        first = T1aKeyword.calls
        d2 = await engine.evaluate(make_context("same text"))
        assert T1aKeyword.calls == first  # served from the cache
        status = {v.control_id: v.status.value for v in d2.verdicts}
        assert status["T1A-BLOCKIN-01"] == "cached" and status["T1A-PSEUDO-01"] == "ok"  # only cacheable ones
        assert {v.status.value for v in d1.verdicts} == {"ok"}
        await engine.evaluate(make_context("different text"))
        assert T1aKeyword.calls > first


# ------------------------------------------------------------------ admin API


def test_admin_events_filters_export_and_metrics(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    chat(client, "hello")
    chat(client, "BLOCKME")
    chat(client, f"pesel {PESEL}", model="auto")
    events = client.get("/admin/v1/events").json()
    assert [e["seq"] for e in events] == sorted((e["seq"] for e in events), reverse=True)
    blocks = client.get("/admin/v1/events", params={"action": "block"}).json()
    assert len(blocks) == 1 and blocks[0]["rule_ids"] == ["T1A-BLOCKIN-01"]
    assert len(client.get("/admin/v1/events", params={"rule_id": "T1A-PSEUDO-01"}).json()) >= 1
    assert len(client.get("/admin/v1/events", params={"control": "T1A-BLOCKIN-01"}).json()) == 1
    assert client.get("/admin/v1/events", params={"subject": "nobody"}).json() == []
    assert len(client.get("/admin/v1/events", params={"point": "egress"}).json()) == 2
    page = client.get("/admin/v1/events", params={"limit": 2, "before_seq": events[0]["seq"]}).json()
    assert len(page) == 2 and page[0]["seq"] < events[0]["seq"]
    assert client.get("/admin/v1/events/does-not-exist").status_code == 404

    # exports
    jsonl = client.get("/admin/v1/audit/export", params={"format": "jsonl"})
    assert jsonl.text == settings.audit_path.read_text(encoding="utf-8")
    ocsf = [json.loads(x) for x in client.get("/admin/v1/audit/export", params={"format": "ocsf"}).text.splitlines()]
    assert all(o["class_uid"] == 2004 and o["class_name"] == "Detection Finding" for o in ocsf)
    assert any(o["disposition"] == "block" and o["disposition_id"] == 2 for o in ocsf)
    csv_lines = client.get("/admin/v1/audit/export", params={"format": "csv"}).text.splitlines()
    assert csv_lines[0].startswith("timestamp,seq,event_id") and len(csv_lines) == len(ocsf) + 1
    future = client.get("/admin/v1/audit/export", params={"since": "2999-01-01T00:00:00Z"}).text
    assert future == ""

    ov = client.get("/admin/v1/metrics/overview", params={"window": "1h"}).json()
    assert ov["decisions_by_action"]["block"] == 1 and ov["decisions_by_action"]["allow"] >= 2
    assert "T1A-BLOCKIN-01" in ov["top_rules"] and ov["spend_usd"] > 0 and ov["open_incidents"] == 1
    assert 0 < ov["posture_score"] < 100 and 0 <= ov["external_routing_rate"] <= 1
    perf = client.get("/admin/v1/metrics/performance").json()
    assert any(s["control_id"] == "T1A-BLOCKIN-01" for s in perf["stages"])

    prom = client.get("/metrics").text
    assert 'acl_decisions_total{action="block",point="ingress"} 1.0' in prom
    assert 'acl_control_latency_seconds_count{control="T1A-BLOCKIN-01"}' in prom
    assert "acl_upstream_latency_seconds_bucket" in prom and "acl_tokens_total" in prom
    assert client.get("/admin/v1/audit/verify").json()["ok"] is True


def test_admin_models_and_connectors(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, _ = harness
    models = {m["id"]: m for m in client.get("/admin/v1/models").json()}
    assert models["gemini/flash"]["tier"] == "cloud" and "smart" in models["gemini/flash"]["aliases"]
    assert (
        models["local/qwen3.8-27b"]["available"] is True
        and models["local/qwen3.8-27b"]["pricing"]["usd_per_gpu_second"]
    )
    assert (
        client.post("/admin/v1/connectors/nope/kill-switch", json={"engaged": True, "reason": "test"}).status_code
        == 404
    )


def test_audit_verify_detects_tampering_and_truncation(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, settings = harness
    for i in range(4):
        chat(client, f"msg {i}")
    original = settings.audit_path.read_text(encoding="utf-8")
    lines = original.splitlines()
    assert client.get("/admin/v1/audit/verify").json()["ok"] is True
    try:
        settings.audit_path.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8", newline="\n")  # truncated tail
        res = client.get("/admin/v1/audit/verify").json()
        assert res["ok"] is False and "truncated" in res["message"]
        tampered = lines.copy()
        tampered[2] = tampered[2].replace('"allow"', '"block"', 1)
        settings.audit_path.write_text("\n".join(tampered) + "\n", encoding="utf-8", newline="\n")
        res = client.get("/admin/v1/audit/verify").json()
        assert res["ok"] is False and res["first_bad_seq"] == 2
    finally:
        settings.audit_path.write_text(original, encoding="utf-8", newline="\n")


# ------------------------------------------------------------------ live SSE


def test_sse_stream_pushes_events_within_a_second(tmp_path: Path) -> None:
    app, settings = build_app(tmp_path)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    port = server.servers[0].sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        with httpx.Client(timeout=10) as http, http.stream("GET", f"{base}/admin/v1/events/stream") as stream:
            assert stream.status_code == 200 and stream.headers["content-type"].startswith("text/event-stream")
            hub = app.state.event_stream
            deadline = time.time() + 5
            while hub.subscribers < 1 and time.time() < deadline:
                time.sleep(0.02)
            assert hub.subscribers == 1
            sent = time.time()
            threading.Thread(
                target=lambda: httpx.post(
                    f"{base}/v1/chat/completions",
                    json={"model": "local/qwen3.8-27b", "messages": [{"role": "user", "content": "live"}]},
                    timeout=10,
                ),
                daemon=True,
            ).start()
            got = None
            for line in stream.iter_lines():
                if line.startswith("data:"):
                    got = json.loads(line[5:])
                    break
            latency = time.time() - sent
            assert got is not None and got["event_type"] == "decision" and got["point"] == "ingress"
            assert latency < 1.0
    finally:
        server.should_exit = True
        thread.join(timeout=10)
    assert_audit_valid(settings.audit_path)
