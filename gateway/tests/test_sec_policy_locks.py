"""CP1 review: panel writes may not weaken locked controls, org locks, or switch enforcement off (concept §11.1).

Regression tests for: a locked control could get `mode: monitor`, `presets: [paranoid]`, `fail_mode: open` (and
any other field) from the panel, and `data_class_tier` org locks could be loosened / removed.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.main import create_app
from acl.policy.errors import LockedControl
from acl.policy.loader import parse_documents, read_policy_dir
from acl.policy.locks import lock_report
from acl.policy.yamledit import PathOp
from acl.settings import Settings

REAL_POLICY = Path(__file__).resolve().parents[2] / "policy"
P = "/admin/v1/policy"

SECRET_HEAD = "  - id: SEC-SECRET-01\n    type: secrets\n    enabled: true\n    locked: true\n"
LOCK01_TIERS = "    data_classes: [confidential, restricted]\n    allowed_tiers: [local]\n"


@dataclass
class Stack:
    app: FastAPI
    client: httpx.AsyncClient
    sink: RecordingSink
    dir: Path

    def read(self, name: str) -> str:
        return (self.dir / name).read_text(encoding="utf-8")

    def write(self, name: str, text: str) -> None:
        (self.dir / name).write_text(text, encoding="utf-8", newline="\n")

    async def file(self, name: str) -> dict:
        r = await self.client.get(f"{P}/files/{name}")
        assert r.status_code == 200, r.text
        return r.json()

    async def put(self, name: str, content: str) -> httpx.Response:
        base = (await self.file(name))["version"]
        return await self.client.put(f"{P}/files/{name}", json={"content": content, "base_version": base})

    def events(self) -> list[dict]:
        return [kw["detail"] for t, kw in self.sink.events if t == EventType.policy_change]


@asynccontextmanager
async def running(tmp_path: Path) -> AsyncIterator[Stack]:
    dest = tmp_path / "policy"
    dest.mkdir()
    for p in REAL_POLICY.glob("*.yaml"):
        (dest / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    settings = Settings(policy_dir=dest, database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}")
    app = create_app(settings, allow_anonymous_dev=True)
    sink = RecordingSink()
    app.state.audit = sink
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app), httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        yield Stack(app, client, sink, dest)


async def wait_for(cond: Callable[[], object], timeout: float = 3.0) -> None:  # noqa: ASYNC109
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"condition not met within {timeout}s")


@pytest.fixture(autouse=True)
def _fast_options(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACL_POLICY_RETIRE_GRACE_S", "0.1")
    monkeypatch.setenv("ACL_POLICY_SETTLE_MS", "50")


@pytest.fixture
async def stack(tmp_path: Path) -> AsyncIterator[Stack]:
    async with running(tmp_path) as s:
        assert SECRET_HEAD in s.read("controls.yaml"), "fixture assumes SEC-SECRET-01 is enabled and locked"
        assert LOCK01_TIERS in s.read("groups.yaml"), "fixture assumes LOCK-01 allows only local"
        yield s


def _secret(extra: str) -> Callable[[str], str]:
    """Insert `extra` (YAML lines) into the SEC-SECRET-01 block."""
    return lambda text: text.replace(SECRET_HEAD, SECRET_HEAD + extra, 1)


LOCKED_CONTROL_EDITS: dict[str, tuple[Callable[[str], str], str]] = {
    "mode_monitor": (_secret("    mode: monitor\n"), "mode"),
    "presets_paranoid_only": (_secret("    presets: [paranoid]\n"), "presets"),
    "fail_mode_open": (_secret("    fail_mode: open\n"), "fail_mode"),
    "timeout_ms": (
        lambda t: t.replace("    timeout_ms: 20\n    action: block", "    timeout_ms: 30\n    action: block", 1),
        "timeout_ms",
    ),
    "cost_tier": (
        lambda t: t.replace(
            "    cost_tier: deterministic\n    timeout_ms: 20\n    action: block",
            "    cost_tier: similarity\n    timeout_ms: 20\n    action: block",
            1,
        ),
        "cost_tier",
    ),
    "taxonomy": (
        lambda t: t.replace('    taxonomy: {owasp_llm: ["LLM02:2025"]}\n\n  - id: SEC-EXFIL', "\n  - id: SEC-EXFIL", 1),
        "taxonomy",
    ),
}


@pytest.mark.parametrize("case", list(LOCKED_CONTROL_EDITS))
async def test_panel_cannot_change_any_field_of_a_locked_control(stack: Stack, case: str) -> None:
    edit, field = LOCKED_CONTROL_EDITS[case]
    before = stack.read("controls.yaml")
    edited = edit(before)
    assert edited != before, case
    r = await stack.put("controls.yaml", edited)
    assert r.status_code == 422, (case, r.text)
    body = r.json()
    assert body["error"] == "locked_control"
    assert body["details"]["violations"] == [{"control_id": "SEC-SECRET-01", "changes": [field]}]
    assert stack.read("controls.yaml") == before


async def test_panel_cannot_change_locked_control_params_or_rename_it(stack: Stack) -> None:
    before = stack.read("controls.yaml")
    with pytest.raises(LockedControl) as exc:
        await stack.app.state.policy_writer.patch_file(
            "controls.yaml",
            [PathOp("set", ["controls", {"id": "SEC-SECRET-01"}, "params"], {"entropy_enabled": False})],
            None,
        )
    changes = exc.value.report.controls[0].changes
    assert exc.value.report.controls[0].control_id == "SEC-SECRET-01" and "params" in changes
    # renaming the id = removing the locked control
    renamed = before.replace("  - id: SEC-SECRET-01\n", "  - id: SEC-SECRET-99\n", 1)
    groups = stack.read("groups.yaml")
    r = await stack.put("controls.yaml", renamed)
    assert r.status_code == 422  # LOCK-02 names a now unknown control -> invalid anyway
    assert groups == stack.read("groups.yaml") and stack.read("controls.yaml") == before


async def test_panel_may_still_edit_a_locked_controls_description(stack: Stack) -> None:
    text = stack.read("controls.yaml")
    edited = text.replace(
        "    description: Secrets and credentials (gitleaks-style",
        "    description: Edited. Secrets (gitleaks-style",
        1,
    )
    assert edited != text
    r = await stack.put("controls.yaml", edited)
    assert r.status_code == 200, r.text


async def test_panel_cannot_loosen_or_remove_org_locks_but_can_add_one(stack: Stack) -> None:
    groups = stack.read("groups.yaml")
    loosened = groups.replace(LOCK01_TIERS, LOCK01_TIERS.replace("[local]", "[local, cloud]"), 1)
    r = await stack.put("groups.yaml", loosened)
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["error"] == "locked_control"
    assert body["details"]["org_locks"] == [{"lock_id": "LOCK-01", "changes": ["allowed_tiers"]}]
    assert "LOCK-01" in body["message"]

    narrowed = groups.replace("    data_classes: [confidential, restricted]\n", "    data_classes: [restricted]\n", 1)
    r = await stack.put("groups.yaml", narrowed)
    assert r.status_code == 422 and r.json()["details"]["org_locks"][0]["changes"] == ["data_classes"]

    start = groups.index("  - id: LOCK-01")
    end = groups.index("  - id: LOCK-02")
    removed = groups[:start] + groups[end:]
    r = await stack.put("groups.yaml", removed)
    assert r.status_code == 422 and r.json()["details"]["org_locks"] == [{"lock_id": "LOCK-01", "changes": ["removed"]}]
    assert stack.read("groups.yaml") == groups

    # validate and dry-run report the same without writing
    v = (await stack.client.post(f"{P}/validate", json={"files": {"groups.yaml": loosened}})).json()
    assert v["valid"] is False and any(e["path"] == "org_locks.LOCK-01" for e in v["errors"])

    added = groups.replace(
        "org_locks:\n",
        "org_locks:\n  - id: LOCK-99\n    kind: data_class_tier\n    data_classes: [internal]\n"
        "    allowed_tiers: [local]\n",
        1,
    )
    r = await stack.put("groups.yaml", added)
    assert r.status_code == 200, r.text


async def test_panel_cannot_switch_global_mode_to_monitor(stack: Stack) -> None:
    text = stack.read("controls.yaml")
    edited = text.replace("  mode: enforce ", "  mode: monitor ", 1)
    assert edited != text
    r = await stack.put("controls.yaml", edited)
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["error"] == "locked_control"
    assert body["details"]["restricted"][0]["path"] == "global.mode"
    assert "policy files" in body["message"]
    with pytest.raises(LockedControl):
        await stack.app.state.policy_writer.patch_file(
            "controls.yaml", [PathOp("set", ["global", "mode"], "monitor")], None
        )
    assert stack.read("controls.yaml") == text


async def test_panel_cannot_set_never_block_on_a_preset(stack: Stack) -> None:
    before = stack.read("controls.yaml")
    with pytest.raises(LockedControl) as exc:
        await stack.app.state.policy_writer.patch_file(
            "controls.yaml", [PathOp("set", ["presets", "strict", "never_block"], True)], None
        )
    assert exc.value.report.restricted[0].path == "presets.strict.never_block"
    assert "policy files" in exc.value.message
    assert stack.read("controls.yaml") == before
    # the monitor preset already has never_block in the files: unrelated panel edits to it still work
    await stack.app.state.policy_writer.patch_file(
        "controls.yaml", [PathOp("set", ["presets", "monitor", "injection_threshold"], 0.85)], None
    )


async def test_rollback_cannot_restore_weakened_locks_and_disk_edits_are_reported(stack: Stack) -> None:
    controls, groups = stack.read("controls.yaml"), stack.read("groups.yaml")
    n = len(stack.events())
    # a judge weakens things on disk: allowed, but reported
    stack.write("controls.yaml", _secret("    mode: monitor\n")(controls))
    await wait_for(lambda: len(stack.events()) == n + 1)
    ev = stack.events()[-1]
    assert ev["locked_control_modified"] == [{"control_id": "SEC-SECRET-01", "changes": ["mode"]}]
    assert ev["org_lock_modified"] == []
    stack.write("groups.yaml", groups.replace(LOCK01_TIERS, LOCK01_TIERS.replace("[local]", "[local, cloud]"), 1))
    await wait_for(lambda: len(stack.events()) == n + 2)
    ev = stack.events()[-1]
    assert ev["org_lock_modified"] == [{"lock_id": "LOCK-01", "changes": ["allowed_tiers"]}]
    sev = [kw["severity"] for t, kw in stack.sink.events if t == EventType.policy_change][-1]
    assert sev == "high"
    weakened_id = (await stack.client.get(f"{P}/versions")).json()[0]["id"]
    # restore on disk
    stack.write("controls.yaml", controls)
    stack.write("groups.yaml", groups)
    await wait_for(lambda: len(stack.events()) == n + 3)
    assert stack.app.state.policy_service.loaded.policy.org_locks[0].allowed_tiers == ["local"]
    # the panel cannot bring the weakened version back
    r = await stack.client.post(f"{P}/versions/{weakened_id}/rollback")
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["error"] == "locked_control"
    assert body["details"]["violations"] == [{"control_id": "SEC-SECRET-01", "changes": ["mode"]}]
    assert body["details"]["org_locks"] == [{"lock_id": "LOCK-01", "changes": ["allowed_tiers"]}]
    assert stack.read("groups.yaml") == groups and stack.read("controls.yaml") == controls


def test_lock_report_unit() -> None:
    base = read_policy_dir(REAL_POLICY)
    old = parse_documents(base).policy
    assert not lock_report(old, old, panel=True)
    off = dict(base)
    off["controls.yaml"] = base["controls.yaml"].replace(SECRET_HEAD, SECRET_HEAD.replace("true\n", "false\n", 1), 1)
    disabled = parse_documents(off).policy
    (v,) = lock_report(old, disabled, panel=True).controls
    assert v.changes == ("disabled",)
    # enabling a disabled locked control is a tightening: allowed
    assert not lock_report(disabled, old, panel=True)
    # disk-sourced comparison never reports the panel-only restrictions
    mon = dict(base)
    mon["controls.yaml"] = base["controls.yaml"].replace("  mode: enforce ", "  mode: monitor ", 1)
    monitor = parse_documents(mon).policy
    assert not lock_report(old, monitor, panel=False)
    assert [r.path for r in lock_report(old, monitor, panel=True).restricted] == ["global.mode"]
    # ... and a policy that is already in monitor mode may be edited from the panel
    assert not lock_report(monitor, monitor, panel=True)
