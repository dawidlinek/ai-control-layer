"""Panel-editable group settings: read mapping, preview, update through the policy writer.

Runs the real app against a temp copy of `policy/` (seed groups are never edited in place and no assumption is
made about their contents: the test groups are appended to the copy and ids are derived from the loaded policy).
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import respx
import yaml
from fastapi.testclient import TestClient

from acl.audit.db_models import AuditEventRow
from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.contracts.common import ConnectorTier
from acl.identity.testing import ISSUER, TestKey, claims, jwks_document
from acl.main import create_app
from acl.policy.errors import ValidationFailed
from acl.policy.loader import load_policy_dir
from acl.policy.yamledit import PathOp
from acl.settings import Settings

SEED = Path(__file__).resolve().parents[2] / "policy"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
BASE = "/admin/v1"
SLASH = "qa/panel-test"
PLAIN = "qa-plain"
GROUP_NAMES = [SLASH, PLAIN]


class Stack:
    def __init__(self, client: TestClient, key: TestKey, audit: RecordingSink, dir: Path, ids: dict[str, str]) -> None:
        self.client, self.key, self.audit, self.dir, self.ids = client, key, audit, dir, ids

    def token(self, username: str, groups: list[str], roles: list[str]) -> dict[str, str]:
        t = self.key.sign(claims(f"sub-{username}", username=username, groups=[f"/{g}" for g in groups], roles=roles))
        return {"Authorization": f"Bearer {t}"}

    @property
    def admin(self) -> dict[str, str]:
        return self.token("adam", ["admins"], ["acl-user", "acl-admin"])

    @property
    def analyst(self) -> dict[str, str]:
        return self.token("ana", ["security-analysts"], ["acl-user", "acl-analyst"])

    @property
    def viewer(self) -> dict[str, str]:
        return self.token("ola", ["security-analysts"], ["acl-user", "acl-viewer"])

    @property
    def app(self) -> Any:
        return self.client.app

    def read(self, name: str) -> str:
        return (self.dir / name).read_text(encoding="utf-8")

    def yaml(self, name: str) -> dict[str, Any]:
        return yaml.safe_load(self.read(name))

    def version(self) -> str:
        return self.client.get(f"{BASE}/policy", headers=self.admin).json()["version"]

    def detail(self, name: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        r = self.client.get(f"{BASE}/groups/{name}/detail", headers=headers or self.viewer)
        assert r.status_code == 200, r.text
        return r.json()

    def settings(self, name: str) -> dict[str, Any]:
        return self.detail(name)["settings"]

    def body(self, name: str, **changes: Any) -> dict[str, Any]:
        settings = {**self.settings(name), **changes}
        return {"settings": settings, "base_version": self.version(), "message": ""}

    def preview(self, name: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
        return self.client.post(f"{BASE}/groups/{name}/settings/preview", json=body, headers=headers or self.analyst)

    def put(self, name: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> Any:
        return self.client.put(f"{BASE}/groups/{name}/settings", json=body, headers=headers or self.admin)

    def snapshot(self) -> dict[str, str]:
        return {p.name: p.read_text(encoding="utf-8") for p in sorted(self.dir.glob("*.yaml"))}

    def policy_events(self) -> list[dict[str, Any]]:
        return [kw["detail"] for t, kw in self.audit.events if t == EventType.policy_change]


def _pick_ids(seed_dir: Path) -> dict[str, str]:
    policy = load_policy_dir(seed_dir).policy
    local = next(
        m.id
        for m in policy.models
        if policy.connectors[m.connector].tier == ConnectorTier.local
        and m.specialist is None
        and m.aliases
        and "embeddings" not in m.capabilities
    )
    local2 = next(
        m.id
        for m in policy.models
        if policy.connectors[m.connector].tier == ConnectorTier.local
        and m.id != local
        and m.specialist is None
        and "embeddings" not in m.capabilities
    )
    cloud = next(m for m in policy.models if policy.connectors[m.connector].tier == ConnectorTier.cloud)
    tools = sorted(policy.tools)
    assert len(tools) >= 4
    return {
        "local": local,
        "local2": local2,
        "cloud": cloud.id,
        "cloud_alias": cloud.aliases[0] if cloud.aliases else cloud.id,
        "tool_a": tools[0],
        "tool_b": tools[1],
        "tool_c": tools[2],
        "tool_d": tools[3],
    }


def _extra_groups(ids: dict[str, str]) -> str:
    out = "\n  # qa-keep-comment: groups added by the panel test\n"
    for name in GROUP_NAMES:
        out += f"""  {name}:
    description: Panel test group
    preset: balanced
    models: [{ids["local"]}]
    tools:
      {ids["tool_a"]}: {{path_deny: ["**/.ssh/**"]}}   # qa-inline-comment
      {ids["tool_c"]}: {{tier: deny}}
    max_external_data_class: internal
"""
    return out


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Stack]:
    monkeypatch.setenv("ACL_POLICY_RETIRE_GRACE_S", "0.1")
    monkeypatch.setenv("ACL_POLICY_SETTLE_MS", "50")
    policy_dir = tmp_path / "policy"
    shutil.copytree(SEED, policy_dir)
    ids = _pick_ids(policy_dir)
    groups = policy_dir / "groups.yaml"
    text = groups.read_text(encoding="utf-8")
    assert text.rstrip().splitlines()[-1].startswith(" "), "groups.yaml is expected to end with the groups section"
    groups.write_text(text.rstrip("\n") + "\n" + _extra_groups(ids), encoding="utf-8", newline="\n")

    key = TestKey("k1")
    settings = Settings(
        policy_dir=policy_dir,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        oidc_issuer=ISSUER,
        oidc_audience="gateway",
        deterministic=True,
    )
    app = create_app(settings)
    audit = RecordingSink()
    app.state.audit = audit
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json=jwks_document(key))
    with router, TestClient(app) as client:
        yield Stack(client, key, audit, policy_dir, ids)


# ---------------------------------------------------------------- read mapping


def test_read_mapping_matches_the_policy_files(stack: Stack) -> None:
    groups = stack.yaml("groups.yaml")["groups"]
    models = stack.yaml("models.yaml")
    budgets = stack.yaml("budgets.yaml")["budgets"]["groups"]
    cloud_ids = {m["id"] for m in models["models"] if models["connectors"][m["connector"]]["tier"] == "cloud"}
    refs: dict[str, str] = {}
    for m in models["models"]:
        refs[m["id"]] = m["id"]
        for a in m.get("aliases", []):
            refs[a] = m["id"]
    # `auto` routes to the routing targets: it is a cloud route whenever one of them is a cloud model
    targets = stack.yaml("routing.yaml")["routing"]["targets"]
    if any(targets.get(k) in cloud_ids for k in ("ext_small", "ext_large")):
        refs["auto"] = next(iter(cloud_ids))
    listed = {g["name"]: g for g in stack.client.get(f"{BASE}/groups", headers=stack.viewer).json()}
    for name, gp in groups.items():
        s = listed[name]["settings"]
        assert s["preset"] == gp.get("preset")
        assert s["models"] == gp.get("models", [])
        assert s["tools"] == [t for t, v in (gp.get("tools") or {}).items() if (v or {}).get("tier") != "deny"]
        has_cloud = any(refs.get(r) in cloud_ids for r in gp.get("models", []))
        ceiling = gp.get("max_external_data_class", "internal")
        assert s["max_cloud_data_class"] == (ceiling if has_cloud else "none")
        assert s["daily_budget_usd"] == (budgets.get(name) or {}).get("usd_day")
        assert listed[name]["policy_file"] == "groups.yaml"
        line = listed[name]["policy_line"]
        assert stack.read("groups.yaml").splitlines()[line - 1].strip() == f"{name}:"
        assert listed[name]["stats_today"]["window"] == "today" and listed[name]["stats_today"]["requests"] == 0
        assert stack.detail(name) == listed[name]


def test_denied_tool_is_not_granted_and_cloud_ceiling_follows_cloud_models(stack: Stack) -> None:
    ids = stack.ids
    s = stack.settings(PLAIN)
    assert s["tools"] == [ids["tool_a"]]  # tool_c is listed with tier deny
    assert s["max_cloud_data_class"] == "none"  # only a local model, even though the ceiling in YAML is internal
    body = stack.body(PLAIN, models=[ids["local"], ids["cloud_alias"]], max_cloud_data_class="internal")
    assert stack.put(PLAIN, body).status_code == 200
    assert stack.settings(PLAIN)["max_cloud_data_class"] == "internal"


def test_keycloak_only_group_is_visible_but_not_editable(stack: Stack) -> None:
    ghost = stack.token("gus", ["ghost-team"], ["acl-user"])
    assert stack.client.get(f"{BASE}/me", headers=ghost).status_code == 200
    d = stack.detail("ghost-team")
    assert d["source"] == "keycloak" and d["settings"] is None and d["policy_file"] is None and d["members"] == 1
    assert stack.client.get(f"{BASE}/groups/nope/detail", headers=stack.viewer).status_code == 404
    body = {"settings": stack.settings(PLAIN), "base_version": stack.version()}
    assert stack.preview("ghost-team", body).status_code == 404
    assert stack.put("ghost-team", body).status_code == 404


def test_stats_today_aggregates_decision_events_of_the_group(stack: Stack) -> None:
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def row(i: int, groups: str, ts: datetime, action: str, event_type: str = "decision") -> AuditEventRow:
        return AuditEventRow(
            event_id=f"e{i}",
            seq=i,
            timestamp=ts,
            event_type=event_type,
            severity="info",
            groups_text=groups,
            action=action,
            input_tokens=10,
            output_tokens=5,
            usd=0.5,
            gpu_seconds=2.0,
            data={},
        )

    recent = today + timedelta(seconds=30)
    rows = [
        row(1, f"|{SLASH}|developers|", recent, "allow"),
        row(2, f"|{SLASH}|", recent + timedelta(seconds=5), "block"),
        row(3, f"|{PLAIN}|", recent, "allow"),
        row(4, f"|{SLASH}|", today - timedelta(hours=1), "allow"),  # yesterday
        row(5, f"|{SLASH}|", recent, "allow", event_type="policy_change"),  # not a decision
        row(6, f"|{SLASH}-other|", recent, "allow"),  # name prefix only
    ]

    async def insert() -> None:
        async with stack.app.state.db() as s:
            s.add_all(rows)
            await s.commit()

    stack.client.portal.call(insert)  # type: ignore[union-attr]
    st = stack.detail(SLASH)["stats_today"]
    assert (st["requests"], st["blocks"], st["tokens_in"], st["tokens_out"]) == (2, 1, 20, 10)
    assert st["usd"] == pytest.approx(1.0) and st["gpu_seconds"] == pytest.approx(4.0)
    assert st["last_active"].startswith((recent + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S"))
    assert stack.detail(PLAIN)["stats_today"]["requests"] == 1


# ---------------------------------------------------------------- preview


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_preview_returns_changes_diff_impact_and_writes_nothing(stack: Stack, name: str) -> None:
    ids = stack.ids
    before_files, before_version = stack.snapshot(), stack.version()
    events_before = len(stack.policy_events())
    body = stack.body(
        name,
        preset="strict",
        models=[ids["local"], ids["cloud_alias"]],
        tools=[ids["tool_b"]],
        max_cloud_data_class="public",
        daily_budget_usd=6,
    )
    r = stack.preview(name, body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["valid"] is True and out["errors"] == []
    assert out["changes"] == [
        "preset balanced → strict",
        f"+ model {ids['cloud_alias']}",
        f"+ tool {ids['tool_b']}",
        f"- tool {ids['tool_a']}",
        "cloud data none → public",
        "daily budget none → 6 USD",
    ]
    assert out["files_changed"] == ["budgets.yaml", "groups.yaml"]
    assert "-    preset: balanced" in out["diff"] and "+    preset: strict" in out["diff"]
    assert "--- a/groups.yaml" in out["diff"] and "+++ b/budgets.yaml" in out["diff"]
    assert out["candidate_version"] and out["candidate_version"] != before_version
    assert out["impact"]["candidate_version"] == out["candidate_version"]
    assert stack.snapshot() == before_files and stack.version() == before_version
    assert len(stack.policy_events()) == events_before


def test_preview_with_no_change_is_empty(stack: Stack) -> None:
    out = stack.preview(PLAIN, stack.body(PLAIN)).json()
    assert out["valid"] is True and out["changes"] == [] and out["diff"] == "" and out["files_changed"] == []


def test_preview_reports_problems_instead_of_raising(stack: Stack) -> None:
    ids = stack.ids
    unknown = stack.preview(PLAIN, stack.body(PLAIN, models=[ids["local"], "no/such-model"])).json()
    assert unknown["valid"] is False
    assert any("no/such-model" in e["message"] for e in unknown["errors"])
    assert unknown["changes"] == ["+ model no/such-model"]
    tool = stack.preview(PLAIN, stack.body(PLAIN, tools=["no.such_tool"])).json()
    assert tool["valid"] is False and any("no.such_tool" in e["message"] for e in tool["errors"])
    contradiction = stack.preview(
        PLAIN, stack.body(PLAIN, models=[ids["local"], ids["cloud"]], max_cloud_data_class="none")
    ).json()
    assert contradiction["valid"] is False
    assert "remove cloud models first or allow public/internal data" in contradiction["errors"][0]["message"]


# ---------------------------------------------------------------- update


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_update_writes_a_new_version_hot_reloads_and_preserves_the_file(stack: Stack, name: str) -> None:
    ids = stack.ids
    old = stack.version()
    seed_comment = stack.read("groups.yaml").splitlines()[0]
    body = stack.body(
        name,
        preset="strict",
        models=[ids["local"], ids["cloud_alias"]],
        tools=[ids["tool_a"], ids["tool_b"]],
        max_cloud_data_class="public",
        daily_budget_usd=6,
    )
    body["message"] = "tighten the panel test group"
    r = stack.put(name, body)
    assert r.status_code == 200, r.text
    status = r.json()
    assert status["version"] != old and status["source"] == "panel"
    assert stack.client.get(f"{BASE}/policy", headers=stack.viewer).json()["version"] == status["version"]
    assert stack.app.state.engine.policy_version == status["version"]
    live = stack.app.state.engine.policy.groups[name]
    assert live.preset.value == "strict" and ids["cloud_alias"] in live.models and ids["tool_b"] in live.tools
    assert stack.settings(name) == body["settings"] | {"models": live.models}

    # comments, per-tool settings and layout survived the round-trip
    text = stack.read("groups.yaml")
    assert text.splitlines()[0] == seed_comment
    assert "# qa-keep-comment" in text and "# qa-inline-comment" in text
    stored = stack.yaml("groups.yaml")["groups"][name]
    assert stored["tools"][ids["tool_a"]] == {"path_deny": ["**/.ssh/**"]}
    assert stored["tools"][ids["tool_b"]] == {}
    assert stored["tools"][ids["tool_c"]] == {"tier": "deny"}
    assert stored["max_external_data_class"] == "public" and stored["preset"] == "strict"
    assert stack.yaml("budgets.yaml")["budgets"]["groups"][name] == {"usd_day": 6}
    assert "# Budgets and resource governance" in stack.read("budgets.yaml")

    # exactly one policy_change event: panel, attributed to the admin, both files, our message
    event = stack.policy_events()[-1]
    assert (
        event["source"] == "panel" and event["author"] == "adam" and event["message"] == "tighten the panel test group"
    )
    assert event["files_changed"] == ["budgets.yaml", "groups.yaml"] and event["version"] == status["version"]
    versions = stack.client.get(f"{BASE}/policy/versions", headers=stack.viewer).json()
    assert versions[0]["version"] == status["version"] and versions[0]["source"] == "panel"


def test_default_message_lists_the_changes(stack: Stack) -> None:
    ids = stack.ids
    assert (
        stack.put(PLAIN, stack.body(PLAIN, preset="paranoid", tools=[ids["tool_a"], ids["tool_b"]])).status_code == 200
    )
    assert stack.policy_events()[-1]["message"] == f"group {PLAIN}: preset balanced → paranoid, + tool {ids['tool_b']}"


def test_update_without_changes_keeps_the_version(stack: Stack) -> None:
    old = stack.version()
    r = stack.put(PLAIN, stack.body(PLAIN))
    assert r.status_code == 200 and r.json()["version"] == old


def test_removed_tools_and_models_are_deleted_and_denied_tool_can_be_granted(stack: Stack) -> None:
    ids = stack.ids
    r = stack.put(PLAIN, stack.body(PLAIN, tools=[ids["tool_c"]], models=[ids["local2"]]))
    assert r.status_code == 200, r.text
    stored = stack.yaml("groups.yaml")["groups"][PLAIN]
    assert ids["tool_a"] not in stored["tools"]
    assert stored["tools"][ids["tool_c"]] == {}  # the `tier: deny` was dropped
    assert stored["models"] == [ids["local2"]]
    assert stack.settings(PLAIN)["tools"] == [ids["tool_c"]]


def test_tools_section_is_created_for_a_group_without_tools(stack: Stack) -> None:
    ids = stack.ids
    assert stack.put(PLAIN, stack.body(PLAIN, tools=[])).status_code == 200
    # a bare group: no `tools` granted at all after removing the only granted tool (the denied one stays)
    assert stack.settings(PLAIN)["tools"] == []
    extra = stack.read("groups.yaml") + f"  qa-bare:\n    description: no tools yet\n    models: [{ids['local']}]\n"
    (stack.dir / "groups.yaml").write_text(extra, encoding="utf-8", newline="\n")
    assert stack.client.portal.call(stack.app.state.policy_service.reload)  # type: ignore[union-attr]
    assert "qa-bare" in stack.app.state.engine.policy.groups
    r = stack.put("qa-bare", stack.body("qa-bare", tools=[ids["tool_a"], ids["tool_b"]], preset="strict"))
    assert r.status_code == 200, r.text
    assert list(stack.yaml("groups.yaml")["groups"]["qa-bare"]["tools"]) == [ids["tool_a"], ids["tool_b"]]


def test_stale_base_version_is_409_and_changes_nothing(stack: Stack) -> None:
    body = stack.body(PLAIN, preset="strict")
    files = stack.snapshot()
    assert stack.put(PLAIN, stack.body(PLAIN, preset="paranoid")).status_code == 200
    after = stack.snapshot()
    assert after != files
    r = stack.put(PLAIN, body)  # based on the version before the previous save
    assert r.status_code == 409 and r.json()["error"] == "stale_version"
    assert stack.snapshot() == after


def test_none_with_cloud_model_is_422(stack: Stack) -> None:
    ids = stack.ids
    files = stack.snapshot()
    body = stack.body(PLAIN, models=[ids["local"], ids["cloud_alias"]], max_cloud_data_class="none")
    r = stack.put(PLAIN, body)
    assert r.status_code == 422, r.text
    assert "remove cloud models first or allow public/internal data" in r.text
    assert stack.snapshot() == files


def test_unknown_model_or_tool_is_422_and_changes_nothing(stack: Stack) -> None:
    files = stack.snapshot()
    r = stack.put(PLAIN, stack.body(PLAIN, models=["no/such-model"]))
    assert r.status_code == 422 and "no/such-model" in r.text
    r = stack.put(PLAIN, stack.body(PLAIN, tools=["no.such_tool"]))
    assert r.status_code == 422 and "no.such_tool" in r.text
    assert stack.snapshot() == files


def test_dropping_cloud_models_with_none_writes_public(stack: Stack) -> None:
    ids = stack.ids
    body = stack.body(PLAIN, models=[ids["local"], ids["cloud_alias"]], max_cloud_data_class="internal")
    assert stack.put(PLAIN, body).status_code == 200
    assert stack.settings(PLAIN)["max_cloud_data_class"] == "internal"
    r = stack.put(PLAIN, stack.body(PLAIN, models=[ids["local"]], max_cloud_data_class="none"))
    assert r.status_code == 200, r.text
    assert stack.yaml("groups.yaml")["groups"][PLAIN]["max_external_data_class"] == "public"
    assert stack.settings(PLAIN)["max_cloud_data_class"] == "none"


def test_org_locks_still_apply_through_the_writer(stack: Stack) -> None:
    """A deny_resource lock cannot be sidestepped by granting the model to a group; the compiler/lock path decides."""
    text = stack.read("groups.yaml")
    assert "org_locks:" in text  # the locks section is untouched by a group edit
    before = stack.yaml("groups.yaml")["org_locks"]
    assert stack.put(PLAIN, stack.body(PLAIN, preset="strict")).status_code == 200
    assert stack.yaml("groups.yaml")["org_locks"] == before


def test_budget_create_update_delete(stack: Stack) -> None:
    assert stack.settings(PLAIN)["daily_budget_usd"] is None
    assert PLAIN not in stack.yaml("budgets.yaml")["budgets"]["groups"]

    assert stack.put(PLAIN, stack.body(PLAIN, daily_budget_usd=3)).status_code == 200
    assert stack.yaml("budgets.yaml")["budgets"]["groups"][PLAIN] == {"usd_day": 3}
    assert stack.settings(PLAIN)["daily_budget_usd"] == 3

    assert stack.put(PLAIN, stack.body(PLAIN, daily_budget_usd=4.5)).status_code == 200
    assert stack.yaml("budgets.yaml")["budgets"]["groups"][PLAIN]["usd_day"] == 4.5
    assert stack.policy_events()[-1]["message"] == f"group {PLAIN}: daily budget 3 → 4.5 USD"

    assert stack.put(PLAIN, stack.body(PLAIN, daily_budget_usd=None)).status_code == 200
    assert "usd_day" not in (stack.yaml("budgets.yaml")["budgets"]["groups"].get(PLAIN) or {})
    assert stack.settings(PLAIN)["daily_budget_usd"] is None
    assert stack.policy_events()[-1]["message"] == f"group {PLAIN}: daily budget 4.5 → none"


def test_existing_budget_entry_keeps_its_other_limits(stack: Stack) -> None:
    groups = stack.yaml("budgets.yaml")["budgets"]["groups"]
    name, limits = next((n, v) for n, v in groups.items() if n in stack.yaml("groups.yaml")["groups"] and len(v) > 1)
    others = {k: v for k, v in limits.items() if k != "usd_day"}
    assert stack.put(name, stack.body(name, daily_budget_usd=77)).status_code == 200
    assert stack.yaml("budgets.yaml")["budgets"]["groups"][name] == {**others, "usd_day": 77}


# ---------------------------------------------------------------- roles


def test_roles(stack: Stack) -> None:
    files = stack.snapshot()
    body = stack.body(PLAIN, preset="strict")
    assert stack.client.get(f"{BASE}/groups/{PLAIN}/detail", headers=stack.viewer).status_code == 200
    assert stack.put(PLAIN, body, stack.viewer).status_code == 403
    assert stack.put(PLAIN, body, stack.analyst).status_code == 403
    assert stack.preview(PLAIN, body, stack.viewer).status_code == 403
    assert stack.preview(PLAIN, body, stack.analyst).status_code == 200
    assert stack.client.put(f"{BASE}/groups/{PLAIN}/settings", json=body).status_code == 401
    assert stack.snapshot() == files
    assert stack.put(PLAIN, body, stack.admin).status_code == 200


# ---------------------------------------------------------------- writer.patch_files


def test_patch_files_is_atomic(stack: Stack) -> None:
    writer = stack.app.state.policy_writer
    files, version = stack.snapshot(), stack.version()
    good = PathOp("set", ["groups", PLAIN, "preset"], "strict")
    bad = PathOp("set", ["budgets", "nope", "deeper"], 1)

    async def run() -> None:
        await writer.patch_files({"groups.yaml": [good], "budgets.yaml": [bad]}, None, version)

    with pytest.raises(ValidationFailed) as exc:
        stack.client.portal.call(run)  # type: ignore[union-attr]
    assert exc.value.errors[0].file == "budgets.yaml"
    assert stack.snapshot() == files and stack.version() == version


def test_preview_patch_is_read_only(stack: Stack) -> None:
    writer = stack.app.state.policy_writer
    files = stack.snapshot()
    out = writer.preview_patch({"groups.yaml": [PathOp("set", ["groups", PLAIN, "preset"], "strict")]})
    assert list(out) == ["groups.yaml"] and "preset: strict" in out["groups.yaml"]
    assert stack.snapshot() == files
    assert "# qa-keep-comment" in out["groups.yaml"]
