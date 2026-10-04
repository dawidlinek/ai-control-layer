"""Phase 1B: policy service (hot reload, writer, locks, versions, rollback, dry-run). Temp dirs only."""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import shutil
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.contracts.common import Action, InspectionPoint
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, ControlRegistry
from acl.engine.engine import Engine
from acl.engine.text import iter_texts
from acl.main import create_app
from acl.policy.loader import load_policy_dir
from acl.policy.yamledit import PathOp
from acl.settings import Settings
from acl.testing import make_context

REAL_POLICY = Path(__file__).resolve().parents[2] / "policy"
P = "/admin/v1/policy"

NEW_CONTROL = """  - id: TEST-KW-01
    type: keyword
    stages: [ingress]
    cost_tier: deterministic
    timeout_ms: 50
    params: {needle: forbidden}
"""


# ---------------------------------------------------------------- fake controls


class KeywordParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    needle: str
    action: Action = Action.block


class Keyword(Control):
    type = "keyword"
    Params = KeywordParams
    closed: ClassVar[list[str]] = []

    async def inspect(self, ctx: InspectionContext):  # type: ignore[override]
        text = " ".join(t for _, t in iter_texts(ctx.payload))
        if self.params.needle in text:  # type: ignore[attr-defined]
            return self.verdict(action=self.params.action, rule_ids=[self.id])  # type: ignore[attr-defined]
        return self.verdict()

    async def aclose(self) -> None:
        Keyword.closed.append(self.id)


class Secrets(Control):
    type = "secrets"

    async def inspect(self, ctx: InspectionContext):  # type: ignore[override]
        return self.verdict()


def make_registry() -> ControlRegistry:
    """Real built-in control types (so the real policy compiles) with test doubles on top."""
    from acl.controls.base import load_builtin_controls
    from acl.controls.base import registry as builtin_registry

    load_builtin_controls()
    reg = ControlRegistry()
    for name in builtin_registry.types():
        if name not in (Keyword.type, Secrets.type):
            reg.register(builtin_registry.get(name))
    reg.register(Keyword)
    reg.register(Secrets)
    return reg


# ---------------------------------------------------------------- harness


@dataclass
class Stack:
    app: FastAPI
    client: httpx.AsyncClient
    sink: RecordingSink
    dir: Path

    @property
    def engine(self) -> Engine:
        return self.app.state.engine

    def read(self, name: str) -> str:
        return (self.dir / name).read_text(encoding="utf-8")

    def write(self, name: str, text: str) -> None:
        (self.dir / name).write_text(text, encoding="utf-8", newline="\n")

    async def status(self) -> dict:
        r = await self.client.get(P)
        assert r.status_code == 200, r.text
        return r.json()

    async def file(self, name: str) -> dict:
        r = await self.client.get(f"{P}/files/{name}")
        assert r.status_code == 200, r.text
        return r.json()

    async def put(self, name: str, content: str, base: str | None = None, message: str = "") -> httpx.Response:
        if base is None:
            base = (await self.file(name))["version"]
        return await self.client.put(
            f"{P}/files/{name}", json={"content": content, "base_version": base, "message": message}
        )

    def events(self, kind: EventType) -> list[dict]:
        return [kw["detail"] for t, kw in self.sink.events if t == kind]


def make_policy_dir(tmp_path: Path, mutate: Callable[[dict[str, str]], None] | None = None) -> Path:
    dest = tmp_path / "policy"
    dest.mkdir()
    texts = {p.name: p.read_text(encoding="utf-8") for p in REAL_POLICY.glob("*.yaml")}
    if mutate:
        mutate(texts)
    for name, text in texts.items():
        (dest / name).write_text(text, encoding="utf-8", newline="\n")
    return dest


@asynccontextmanager
async def running(policy_dir: Path, tmp_path: Path, buffer: object | None = None) -> AsyncIterator[Stack]:
    settings = Settings(policy_dir=policy_dir, database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}")
    app = create_app(settings, allow_anonymous_dev=True)
    sink = RecordingSink()
    app.state.audit = sink
    if buffer is not None:
        app.state.replay_buffer = buffer
    reg = make_registry()
    app.state.build_engine = lambda policy, version: Engine.build(
        policy, version, deps=app.state.control_deps, control_registry=reg, load_builtins=False
    )
    app.state.policy_service.registry = reg
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app), httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        yield Stack(app, client, sink, policy_dir)


async def wait_for(cond: Callable[[], object], timeout: float = 2.0) -> float:  # noqa: ASYNC109
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if cond():
            return time.monotonic() - start
        await asyncio.sleep(0.02)
    raise AssertionError(f"condition not met within {timeout}s")


@pytest.fixture(autouse=True)
def _fast_options(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_POLICY_RETIRE_GRACE_S", "0.1")
    monkeypatch.setenv("ACL_POLICY_SETTLE_MS", "50")
    Keyword.closed.clear()


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    async with running(make_policy_dir(tmp_path), tmp_path) as s:
        yield s


def _enable_secret_control(texts: dict[str, str]) -> None:
    old = "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: false\n"
    if old not in texts["controls.yaml"]:  # already enabled in the shipped policy
        assert "id: SEC-SECRET-01" in texts["controls.yaml"]
        return
    texts["controls.yaml"] = texts["controls.yaml"].replace(old, old.replace("enabled: false", "enabled: true"))


# ---------------------------------------------------------------- startup & read side


async def test_startup_loads_policy_and_serves_status(stack: Stack) -> None:
    assert stack.engine is not None
    st = await stack.status()
    assert st["version"] == stack.engine.policy_version
    assert st["source"] == "startup"
    assert "SEC-SECRET-01" in st["locked_controls"]
    names = {f["name"] for f in st["files"]}
    assert names == {p.name for p in REAL_POLICY.glob("*.yaml")}
    f = await stack.file("routing.yaml")
    assert f["version"] == hashlib.sha256(f["content"].encode()).hexdigest()
    assert [x["name"] for x in (await stack.client.get(f"{P}/files")).json()] == sorted(names)
    schema = (await stack.client.get(f"{P}/schema")).json()
    assert "properties" in schema and "controls" in schema["properties"]
    versions = (await stack.client.get(f"{P}/versions")).json()
    assert len(versions) == 1 and versions[0]["source"] == "startup"
    assert any(t == EventType.policy_change for t, _ in stack.sink.events)


async def test_crlf_does_not_change_file_version(stack: Stack) -> None:
    before = await stack.file("routing.yaml")
    text = stack.read("routing.yaml")
    (stack.dir / "routing.yaml").write_bytes(text.replace("\n", "\r\n").encode())
    after = await stack.file("routing.yaml")
    assert after["version"] == before["version"] and "\r" not in after["content"]


async def test_not_ready_and_recovery_when_startup_policy_is_invalid(tmp_path: Path) -> None:
    d = make_policy_dir(tmp_path, lambda t: t.update({"budgets.yaml": "budgets: [unclosed\n"}))
    async with running(d, tmp_path) as s:
        assert s.app.state.engine is None
        st = await s.status()
        assert st["last_error"] and st["last_error"][0]["file"] == "budgets.yaml"
        assert len(s.events(EventType.policy_reload_failed)) == 1
        shutil.copy(REAL_POLICY / "budgets.yaml", d / "budgets.yaml")
        await wait_for(lambda: s.app.state.engine is not None)
        assert (await s.status())["last_error"] == []


# ---------------------------------------------------------------- hot reload


@pytest.mark.parametrize("polling", [False, True])
async def test_hot_reload_swaps_engine_within_two_seconds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, polling: bool
) -> None:
    monkeypatch.setenv("ACL_POLICY_FORCE_POLLING", "true" if polling else "false")
    async with running(make_policy_dir(tmp_path), tmp_path) as s:
        old = s.engine
        assert old.policy.global_.default_preset.value == "balanced"
        # Let the watcher arm (a poller takes its first snapshot one poll cycle after start); edits made
        # before that are only caught by the periodic rescan, which is outside this test's 2 s budget.
        await asyncio.sleep(1.5)
        s.write(
            "controls.yaml", s.read("controls.yaml").replace("default_preset: balanced", "default_preset: strict", 1)
        )
        took = await wait_for(lambda: s.engine is not old, timeout=2.0)
        assert took < 2.0
        assert s.engine.policy_version != old.policy_version
        assert s.engine.policy.global_.default_preset.value == "strict"
        st = await s.status()
        assert st["version"] == s.engine.policy_version and st["source"] == "file"
        # group preset change is picked up the same way
        v1 = s.engine.policy_version
        s.write("groups.yaml", s.read("groups.yaml").replace("preset: balanced", "preset: strict", 1))
        await wait_for(lambda: s.engine.policy_version != v1)
        assert s.engine.policy.groups["admins"].preset.value == "strict"
        # the replaced engine is still usable by in-flight requests, and gets closed after the grace period
        d_old = await old.evaluate(make_context("hello"))
        assert d_old.action == Action.allow, [(v.control_id, v.status, v.reason, v.latency_ms) for v in d_old.verdicts]


async def test_invalid_edit_keeps_last_good_alerts_once_and_recovers(stack: Stack) -> None:
    good = stack.engine
    original = stack.read("groups.yaml")
    stack.write("groups.yaml", original.replace("preset: balanced", "preset: nonsense", 1))
    await wait_for(lambda: stack.events(EventType.policy_reload_failed))
    assert stack.engine is good  # last good kept
    st = await stack.status()
    assert st["last_error"] and st["last_error"][0]["file"] == "groups.yaml"
    assert st["last_error"][0]["line"] is not None
    (ev,) = stack.events(EventType.policy_reload_failed)
    assert ev["errors"][0]["file"] == "groups.yaml" and ev["kept_version"] == good.policy_version
    assert [kw["severity"] for t, kw in stack.sink.events if t == EventType.policy_reload_failed] == ["high"]
    assert "nonsense" not in str(ev)  # no file content in events
    # syntax error as well
    stack.write("groups.yaml", "groups: [1\n")
    await wait_for(lambda: len(stack.events(EventType.policy_reload_failed)) == 2)
    assert stack.engine is good
    # fix it (different content) -> reload succeeds and the error is cleared
    stack.write("groups.yaml", original.replace("preset: balanced", "preset: strict", 1))
    await wait_for(lambda: stack.engine is not good)
    assert (await stack.status())["last_error"] == []
    await wait_for(lambda: any(d["source"] == "file" for d in stack.events(EventType.policy_change)))
    # reverting to exactly the loaded content after a broken edit clears the error without a new version
    keep, loaded_text = stack.engine, stack.read("groups.yaml")
    stack.write("groups.yaml", "groups: [2\n")
    await wait_for(lambda: len(stack.events(EventType.policy_reload_failed)) == 3)
    stack.write("groups.yaml", loaded_text)
    svc = stack.app.state.policy_service
    await wait_for(lambda: not svc._last_error)
    assert stack.engine is keep and len(stack.events(EventType.policy_reload_failed)) == 3


async def test_unknown_control_type_and_bad_params_block_reload(stack: Stack) -> None:
    good = stack.engine
    text = stack.read("controls.yaml")
    stack.write(
        "controls.yaml",
        text.replace("\nsignatures:\n", "\n" + NEW_CONTROL.replace("keyword", "nope") + "\nsignatures:\n", 1),
    )
    await wait_for(lambda: stack.events(EventType.policy_reload_failed))
    err = (await stack.status())["last_error"][0]
    assert "unknown type" in err["message"] and err["file"] == "controls.yaml" and err["line"]
    stack.write(
        "controls.yaml",
        text.replace(
            "\nsignatures:\n",
            "\n" + NEW_CONTROL.replace("{needle: forbidden}", "{needle: x, bogus: 1}") + "\nsignatures:\n",
            1,
        ),
    )
    await wait_for(lambda: len(stack.events(EventType.policy_reload_failed)) == 2)
    assert "params" in (await stack.status())["last_error"][0]["message"]
    assert stack.engine is good


async def test_retired_engine_is_closed_after_grace(tmp_path: Path) -> None:
    d = make_policy_dir(
        tmp_path,
        lambda t: t.update(
            {"controls.yaml": t["controls.yaml"].replace("\nsignatures:\n", "\n" + NEW_CONTROL + "\nsignatures:\n", 1)}
        ),
    )
    async with running(d, tmp_path) as s:
        assert Keyword.closed == []
        s.write("routing.yaml", s.read("routing.yaml") + "\n# touch\n")
        await wait_for(lambda: Keyword.closed == ["TEST-KW-01"], timeout=3.0)


# ---------------------------------------------------------------- versions


async def test_file_edit_creates_version_with_diff_and_locked_edit_is_reported(tmp_path: Path) -> None:
    async with running(make_policy_dir(tmp_path, _enable_secret_control), tmp_path) as s:
        text = s.read("controls.yaml")
        # a judge disables the locked control on disk: not blocked, but flagged
        s.write(
            "controls.yaml",
            text.replace(
                "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: true",
                "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: false",
                1,
            ),
        )
        await wait_for(lambda: len(s.events(EventType.policy_change)) == 2)
        ev = s.events(EventType.policy_change)[-1]
        assert ev["source"] == "file" and ev["files_changed"] == ["controls.yaml"]
        assert ev["locked_control_modified"] == [{"control_id": "SEC-SECRET-01", "changes": ["disabled"]}]
        assert "enabled" not in str(ev["files_changed"])
        assert [kw["severity"] for t, kw in s.sink.events if t == EventType.policy_change][-1] == "high"
        versions = (await s.client.get(f"{P}/versions")).json()
        assert [v["source"] for v in versions] == ["file", "startup"]
        assert versions[0]["files_changed"] == ["controls.yaml"]
        detail = (await s.client.get(f"{P}/versions/{versions[0]['id']}")).json()
        assert "--- a/controls.yaml" in detail["diff"] and "-    enabled: true" in detail["diff"]
        assert "+    enabled: false" in detail["diff"]
        assert detail["files"]["controls.yaml"].count("enabled: false") > text.count("enabled: false")
        assert (await s.client.get(f"{P}/versions/9999")).status_code == 404


# ---------------------------------------------------------------- panel writer


async def test_panel_write_preserves_comments_and_attributes_author(stack: Stack) -> None:
    f = await stack.file("controls.yaml")
    new = f["content"].replace("default_preset: balanced       #", "default_preset: strict         #", 1)
    assert new != f["content"]
    r = await stack.put("controls.yaml", new, f["version"], message="tighten default")
    assert r.status_code == 200, r.text
    on_disk = stack.read("controls.yaml")
    assert on_disk == new and b"\r" not in (stack.dir / "controls.yaml").read_bytes()
    assert "# Controls, presets and global settings (concept §6, §11)." in on_disk
    assert "# ---- stage 0: normalise" in on_disk
    assert stack.engine.policy.global_.default_preset.value == "strict"
    st = r.json()
    assert st["source"] == "panel" and st["version"] == stack.engine.policy_version
    ev = stack.events(EventType.policy_change)[-1]
    assert ev["source"] == "panel" and ev["author"] == "dev" and ev["message"] == "tighten default"
    # the watcher's echo of our own write must not create another version or event
    n_events = len(stack.events(EventType.policy_change))
    await asyncio.sleep(0.8)
    assert len(stack.events(EventType.policy_change)) == n_events
    assert [v["source"] for v in (await stack.client.get(f"{P}/versions")).json()] == ["panel", "startup"]


async def test_patch_file_preserves_comments_and_layout(stack: Stack) -> None:
    before = stack.read("controls.yaml")
    status = await stack.app.state.policy_writer.patch_file(
        "controls.yaml",
        [
            PathOp("set", ["global", "default_preset"], "strict"),
            PathOp("set", ["controls", {"id": "SEC-NORM-01"}, "description"], "edited from the panel"),
            PathOp("set", ["controls", {"id": "SEC-NORM-01"}, "timeout_ms"], 25),
        ],
        principal=None,
        base_version=(await stack.file("controls.yaml"))["version"],
        message="forms edit",
    )
    after = stack.read("controls.yaml")
    assert status.source == "panel"
    changed = [ln for ln in difflib.ndiff(before.splitlines(), after.splitlines()) if ln[:2] in ("- ", "+ ")]
    assert len(changed) == 6, changed  # exactly three lines replaced
    assert "# monitor | balanced | strict | paranoid" in after  # trailing comment on a changed line survives
    assert (
        "# ---- stage 0: normalise" in after
        and "fail_mode: {deterministic: closed, semantic: open_with_alert}" in after
    )
    assert stack.engine.policy.controls[0].description == "edited from the panel"
    assert stack.engine.policy.global_.default_preset.value == "strict"


async def test_stale_base_version_is_409(stack: Stack) -> None:
    f = await stack.file("routing.yaml")
    ok = await stack.put("routing.yaml", f["content"] + "# first\n", f["version"])
    assert ok.status_code == 200
    stale = await stack.put("routing.yaml", f["content"] + "# second\n", f["version"])
    assert stale.status_code == 409
    body = stale.json()
    assert body["error"] == "stale_version" and body["details"]["file"] == "routing.yaml"
    assert "# second" not in stack.read("routing.yaml")
    # an edit made on disk makes a panel base stale too
    cur = await stack.file("routing.yaml")
    stack.write("routing.yaml", stack.read("routing.yaml") + "# from disk\n")
    assert (await stack.put("routing.yaml", "x: 1\n", cur["version"])).status_code == 409


async def test_invalid_content_is_422_and_nothing_is_written(stack: Stack) -> None:
    f = await stack.file("routing.yaml")
    bad = f["content"].replace("local_max: 0.0", "local_max: 5", 1)
    r = await stack.put("routing.yaml", bad, f["version"])
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "validation_failed"
    err = body["details"]["errors"][0]
    assert err["file"] == "routing.yaml" and err["line"] and "complexity_bands" in err["path"]
    assert stack.read("routing.yaml") == f["content"]
    # whole candidate set is validated: breaking a cross reference in another file's section is caught too
    g = await stack.file("groups.yaml")
    r = await stack.put(
        "groups.yaml",
        g["content"].replace("models: [auto, local, bielik, smart]", "models: [auto, nope/model]", 1),
        g["version"],
    )
    assert r.status_code == 422
    assert any(e["file"] == "groups.yaml" and e["line"] for e in r.json()["details"]["errors"])


async def test_locked_control_cannot_be_weakened_from_the_panel(tmp_path: Path) -> None:
    async with running(make_policy_dir(tmp_path, _enable_secret_control), tmp_path) as s:
        f = await s.file("controls.yaml")
        base = f["content"]
        block = "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: true\n"
        variants = {
            "disabled": base.replace(block, block.replace("enabled: true", "enabled: false")),
            "action": base.replace(
                '    action: block\n    taxonomy: {owasp_llm: ["LLM02:2025"]}\n\n  - id: SEC-EXFIL',
                '    action: monitor\n    taxonomy: {owasp_llm: ["LLM02:2025"]}\n\n  - id: SEC-EXFIL',
                1,
            ),
            "stages": base.replace(
                "    stages: [ingress, egress, tool_call, tool_result, embeddings]\n"
                "    cost_tier: deterministic\n    timeout_ms: 20\n    action: block",
                "    stages: [ingress]\n    cost_tier: deterministic\n    timeout_ms: 20\n    action: block",
                1,
            ),
            "unlocked": base.replace(
                "    locked: true\n    description: Secrets and credentials",
                "    description: Secrets and credentials",
                1,
            ),
        }
        for change, text in variants.items():
            assert text != base, change
            r = await s.put("controls.yaml", text, f["version"])
            assert r.status_code == 422, (change, r.text)
            body = r.json()
            assert body["error"] == "locked_control", (change, body)
            assert body["details"]["violations"][0]["control_id"] == "SEC-SECRET-01"
            assert s.read("controls.yaml") == base
        # removing the control entirely
        start = base.index("  - id: SEC-SECRET-01")
        end = base.index("  - id: SEC-EXFIL-01")
        removed = base[:start] + base[end:]
        # the org lock that names it makes the candidate invalid (422) ...
        assert (await s.put("controls.yaml", removed, f["version"])).status_code == 422
        # ... and even with the org lock gone, the control's own `locked: true` keeps it from being removed
        g = await s.file("groups.yaml")
        no_lock = g["content"].replace("    controls: [SEC-SECRET-01]\n", "    controls: [SEC-NORM-01]\n", 1)
        # (changing an org lock is itself refused from the panel, so the judge does it on disk)
        assert (await s.put("groups.yaml", no_lock, g["version"])).status_code == 422
        n = len(s.events(EventType.policy_change))
        s.write("groups.yaml", no_lock)
        await wait_for(lambda: len(s.events(EventType.policy_change)) == n + 1)
        assert s.events(EventType.policy_change)[-1]["org_lock_modified"] == [
            {"lock_id": "LOCK-02", "changes": ["controls"]}
        ]
        r = await s.put("controls.yaml", removed, f["version"])
        assert r.status_code == 422 and r.json()["error"] == "locked_control"
        assert r.json()["details"]["violations"] == [{"control_id": "SEC-SECRET-01", "changes": ["removed"]}]
        # unrelated edits still work, and validate reports the same problem without writing
        v = (await s.client.post(f"{P}/validate", json={"files": {"controls.yaml": variants["disabled"]}})).json()
        assert v["valid"] is False and "locked control SEC-SECRET-01" in v["errors"][0]["message"]
        ok = await s.put(
            "controls.yaml",
            base.replace("description: Secrets and credentials", "description: Edited - secrets and credentials", 1),
            f["version"],
        )
        assert ok.status_code == 200, ok.text


@pytest.mark.parametrize(
    "name",
    [
        "..\\evil.yaml",
        "../evil.yaml",
        "..%2Fevil.yaml",
        "Controls.yaml",
        "a b.yaml",
        "evil.txt",
        ".hidden.yaml",
        "x.yaml.bak",
    ],
)
async def test_path_traversal_and_bad_names_rejected(stack: Stack, tmp_path: Path, name: str) -> None:
    r = await stack.client.put(f"{P}/files/{name}", json={"content": "x: 1\n", "base_version": "new"})
    assert r.status_code in (404, 422), (name, r.status_code)
    assert not (tmp_path / "evil.yaml").exists() and not (stack.dir.parent / "evil.yaml").exists()
    assert sorted(p.name for p in stack.dir.iterdir()) == sorted(p.name for p in REAL_POLICY.glob("*.yaml"))
    assert (await stack.client.get(f"{P}/files/{name}")).status_code == 404


async def test_create_new_file_requires_new_base_version(stack: Stack) -> None:
    content = "mcp_servers:\n  demo:\n    transport: streamable_http\n    url: http://demo:9000/mcp\n"
    # `mcp_servers` already lives in tools.yaml: a section may appear in one file only
    r = await stack.put("extra.yaml", content, "new")
    assert r.status_code == 422 and "already defined" in str(r.json())
    assert not (stack.dir / "extra.yaml").exists()
    assert (await stack.put("extra.yaml", "# comment only\n", "abc")).status_code == 404
    r = await stack.put("extra.yaml", "# comment only\n", "new")
    assert r.status_code == 200 and (stack.dir / "extra.yaml").exists()


async def test_rollback_restores_content(stack: Stack) -> None:
    original = {p.name: stack.read(p.name) for p in stack.dir.glob("*.yaml")}
    f = await stack.file("controls.yaml")
    assert (
        await stack.put(
            "controls.yaml",
            f["content"].replace("default_preset: balanced", "default_preset: paranoid", 1),
            f["version"],
        )
    ).status_code == 200
    g = await stack.file("routing.yaml")
    assert (await stack.put("routing.yaml", g["content"] + "# edited\n", g["version"])).status_code == 200
    versions = (await stack.client.get(f"{P}/versions")).json()
    assert [v["source"] for v in versions] == ["panel", "panel", "startup"]
    first = versions[-1]
    r = await stack.client.post(f"{P}/versions/{first['id']}/rollback")
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "rollback"
    assert {p.name: stack.read(p.name) for p in stack.dir.glob("*.yaml")} == original
    assert stack.engine.policy.global_.default_preset.value == "balanced"
    assert stack.engine.policy_version == first["version"]
    versions = (await stack.client.get(f"{P}/versions")).json()
    assert versions[0]["source"] == "rollback" and versions[0]["author"] == "dev"
    assert set(versions[0]["files_changed"]) == {"controls.yaml", "routing.yaml"}
    assert (await stack.client.post(f"{P}/versions/9999/rollback")).status_code == 404
    assert [v for v in stack.events(EventType.policy_change)][-1]["source"] == "rollback"


async def _two_versions(stack: Stack) -> dict:
    f = await stack.file("controls.yaml")
    assert (await stack.put("controls.yaml", f["content"] + "# edited" + chr(10), f["version"])).status_code == 200
    versions = (await stack.client.get(f"{P}/versions")).json()
    return versions[-1]  # the startup version


async def test_rollback_without_a_body_still_works_and_has_no_reason(stack: Stack) -> None:
    first = await _two_versions(stack)
    r = await stack.client.post(f"{P}/versions/{first['id']}/rollback")
    assert r.status_code == 200, r.text
    top = (await stack.client.get(f"{P}/versions")).json()[0]
    assert top["source"] == "rollback" and top["reason"] is None
    assert stack.events(EventType.policy_change)[-1]["reason"] is None


async def test_rollback_reason_is_stored_in_history_and_audit(stack: Stack) -> None:
    first = await _two_versions(stack)
    r = await stack.client.post(f"{P}/versions/{first['id']}/rollback", json={"reason": "  bad edit, see INC-7  "})
    assert r.status_code == 200, r.text
    top = (await stack.client.get(f"{P}/versions")).json()[0]
    assert top["source"] == "rollback" and top["reason"] == "bad edit, see INC-7"
    assert "bad edit, see INC-7" in top["message"]  # also readable in the existing message field
    detail = (await stack.client.get(f"{P}/versions/{top['id']}")).json()
    assert detail["reason"] == "bad edit, see INC-7"
    event = stack.events(EventType.policy_change)[-1]
    assert event["source"] == "rollback" and event["reason"] == "bad edit, see INC-7"
    # versions that are not rollbacks carry no reason
    assert all(v["reason"] is None for v in (await stack.client.get(f"{P}/versions")).json()[1:])


@pytest.mark.parametrize("body", [{"reason": "ab"}, {"reason": "   "}, {}, {"reason": "x" * 501}, {"why": "because"}])
async def test_rollback_rejects_an_invalid_body(stack: Stack, body: dict) -> None:
    first = await _two_versions(stack)
    before = await stack.status()
    r = await stack.client.post(f"{P}/versions/{first['id']}/rollback", json=body)
    assert r.status_code == 422, r.text
    assert (await stack.status())["version"] == before["version"]  # nothing was rolled back


# ---------------------------------------------------------------- validate & dry-run


async def test_validate_endpoint(stack: Stack) -> None:
    ok = (await stack.client.post(f"{P}/validate", json={"files": {}})).json()
    assert ok["valid"] is True and ok["candidate_version"] == stack.engine.policy_version
    controls = stack.read("controls.yaml")
    bad_type = controls.replace("\nsignatures:\n", "\n" + NEW_CONTROL.replace("keyword", "nope") + "\nsignatures:\n", 1)
    bad = (await stack.client.post(f"{P}/validate", json={"files": {"controls.yaml": bad_type}})).json()
    assert bad["valid"] is False and bad["errors"][0]["line"] and "nope" in bad["errors"][0]["message"]
    syntax = (await stack.client.post(f"{P}/validate", json={"files": {"budgets.yaml": "budgets: [x\n"}})).json()
    assert (
        syntax["valid"] is False and syntax["errors"][0]["file"] == "budgets.yaml" and syntax["errors"][0]["line"] == 2
    )
    name = (await stack.client.post(f"{P}/validate", json={"files": {"../x.yaml": "a: 1"}})).json()
    assert name["valid"] is False
    assert stack.engine.policy_version == ok["candidate_version"]  # validate never swaps


class FakeBuffer:
    def __init__(self, items: list[tuple[InspectionContext, Decision]]) -> None:
        self.items = items
        self.calls: list[tuple[int, InspectionPoint | None]] = []

    def recent(self, n: int, point: InspectionPoint | None = None) -> list[tuple[InspectionContext, Decision]]:
        self.calls.append((n, point))
        return [i for i in self.items if point is None or i[0].point == point][:n]


async def test_dry_run_reports_transitions_against_candidate(tmp_path: Path) -> None:
    baseline = Engine.build(
        load_policy_dir(REAL_POLICY).policy, "base", control_registry=make_registry(), load_builtins=False
    )
    items = []
    for i in range(30):
        ctx = make_context("this is forbidden stuff" if i % 3 == 0 else f"hello {i}")
        items.append((ctx, await baseline.evaluate(ctx.model_copy(deep=True))))
    assert all(d.action == Action.allow for _, d in items)
    buffer = FakeBuffer(items)
    async with running(make_policy_dir(tmp_path), tmp_path, buffer=buffer) as s:
        before_version = s.engine.policy_version
        controls = s.read("controls.yaml")
        candidate = controls.replace("\nsignatures:\n", "\n" + NEW_CONTROL + "\nsignatures:\n", 1)
        r = await s.client.post(f"{P}/dry-run", json={"files": {"controls.yaml": candidate}, "last_n": 100})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["errors"] == [] and body["evaluated"] == 30
        assert body["changed"] == 10 and body["transitions"] == {"allow->block": 10}
        assert len(body["samples"]) == 10
        sample = body["samples"][0]
        assert sample["before_action"] == "allow" and sample["after_action"] == "block"
        assert sample["after_rule_ids"] == ["TEST-KW-01"] and sample["subject"] == "anna"
        assert body["candidate_version"] != before_version
        assert buffer.calls == [(100, None)]
        # filter by point is forwarded; nothing was swapped or written
        await s.client.post(f"{P}/dry-run", json={"files": {"controls.yaml": candidate}, "point": "egress"})
        assert buffer.calls[-1][1] == InspectionPoint.egress
        assert s.engine.policy_version == before_version and s.read("controls.yaml") == controls
        # the stored contexts were not mutated
        assert all(c.attributes == {} for c, _ in items)
        # no-op candidate: nothing changes
        same = (await s.client.post(f"{P}/dry-run", json={"files": {}})).json()
        assert same["changed"] == 0 and same["transitions"] == {} and same["evaluated"] == 30
        # invalid candidate: errors, no evaluation
        bad = (await s.client.post(f"{P}/dry-run", json={"files": {"budgets.yaml": "budgets: [x\n"}})).json()
        assert bad["evaluated"] == 0 and bad["errors"][0]["file"] == "budgets.yaml"


async def test_dry_run_follows_candidate_preset_and_samples_are_capped(tmp_path: Path) -> None:
    # a keyword control only active under `strict`; the candidate moves developers to strict
    def mutate(t: dict[str, str]) -> None:
        kw = NEW_CONTROL.replace("timeout_ms: 50", "timeout_ms: 50\n    presets: [strict]")
        t["controls.yaml"] = t["controls.yaml"].replace("\nsignatures:\n", "\n" + kw + "\nsignatures:\n", 1)

    d = make_policy_dir(tmp_path, mutate)
    engine = Engine.build(load_policy_dir(d).policy, "base", control_registry=make_registry(), load_builtins=False)
    items = []
    for _ in range(60):
        ctx = make_context("forbidden", preset=engine.policy.groups["developers"].preset)
        items.append((ctx, await engine.evaluate(ctx.model_copy(deep=True))))
    assert all(dec.action == Action.allow for _, dec in items)  # developers are `balanced`: control inactive
    async with running(d, tmp_path, buffer=FakeBuffer(items)) as s:
        groups = s.read("groups.yaml")
        i = groups.index("  developers:")
        edited = groups[:i] + groups[i:].replace("preset: balanced", "preset: strict", 1)
        body = (await s.client.post(f"{P}/dry-run", json={"files": {"groups.yaml": edited}})).json()
        assert body["errors"] == []
        assert body["changed"] == 60 and body["transitions"] == {"allow->block": 60}
        assert len(body["samples"]) == 50


async def test_dry_run_without_buffer_reports_error(stack: Stack) -> None:
    body = (await stack.client.post(f"{P}/dry-run", json={"files": {}})).json()
    assert body["evaluated"] == 0 and "replay buffer" in body["errors"][0]["message"]


async def test_org_lock_membership_cannot_be_dropped_from_the_panel(tmp_path: Path) -> None:
    def mutate(t: dict[str, str]) -> None:
        _enable_secret_control(t)
        t["controls.yaml"] = t["controls.yaml"].replace("    locked: true\n", "", 1)  # locked only via the org lock

    async with running(make_policy_dir(tmp_path, mutate), tmp_path) as s:
        assert (await s.status())["locked_controls"] == ["SEC-SECRET-01"]
        g = await s.file("groups.yaml")
        edited = g["content"].replace("controls: [SEC-SECRET-01]", "controls: [SEC-NORM-01]", 1)
        r = await s.put("groups.yaml", edited, g["version"])
        assert r.status_code == 422 and r.json()["error"] == "locked_control"
        assert r.json()["details"]["violations"][0]["changes"] == ["unlocked"]
        assert s.read("groups.yaml") == g["content"]
