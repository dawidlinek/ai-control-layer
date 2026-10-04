"""S2: `/admin/v1/artifacts*` through the real app, the scan store, audit/incident records and the registry gate."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from acl.api.admin.artifacts import safe_filename
from acl.artifacts.testing import FIXTURES, fixture_bytes, fixture_filename
from acl.main import create_app
from acl.policy.models import ModelEntry
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
SCAN = "/admin/v1/artifacts/scan"
ART = "SEC-ART-01"


def hdr(user: str, roles: str) -> dict[str, str]:
    return {"X-ACL-Dev-User": user, "X-ACL-Dev-Groups": "admins", "X-ACL-Dev-Roles": roles}


ADMIN = hdr("adam", "acl-admin")
VIEWER = hdr("vera", "acl-viewer")
ANALYST = hdr("ola", "acl-analyst")


def sha_of(name: str) -> str:
    return hashlib.sha256(fixture_bytes(name)).hexdigest()


def feed_entry(sig_id: str, glob: str) -> dict[str, Any]:
    return {"id": sig_id, "type": "opcode", "pattern": glob, "severity": "critical", "stages": ["artifact_load"]}


def install_feed(app: Any, entries: list[dict[str, Any]]) -> None:
    from acl.contracts.feed import FeedBundle

    bundle = FeedBundle.model_validate(
        {
            "bundle_version": 1,
            "issued_at": "2026-10-03T12:00:00Z",
            "entries": entries,
            "signature": {"alg": "sha256", "value": "x"},
        }
    )
    app.state.feed_store.install(bundle, "digest")


AppFactory = Callable[..., Any]


@pytest.fixture
def make_app(tmp_path: Path) -> Iterator[AppFactory]:
    """Build an in-process app on a temp policy copy. `art_params` patches SEC-ART-01 params, `models` adds models."""
    clients: list[TestClient] = []
    counter = {"n": 0}

    def build(*, art_params: dict[str, Any] | None = None, models: list[dict[str, Any]] | None = None) -> Any:
        counter["n"] += 1
        root = tmp_path / f"app{counter['n']}"
        policy_dir = root / "policy"
        shutil.copytree(REPO / "policy", policy_dir)
        if art_params:
            path = policy_dir / "controls.yaml"
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            for control in doc["controls"]:
                if control["id"] == ART:
                    control["params"].update(art_params)
            path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        if models:
            path = policy_dir / "models.yaml"
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            doc["models"].extend(models)
            path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
            groups_path = policy_dir / "groups.yaml"  # admins may use the added models
            groups = yaml.safe_load(groups_path.read_text(encoding="utf-8"))
            groups["groups"]["admins"]["models"].extend(m["id"] for m in models)
            groups_path.write_text(yaml.safe_dump(groups, sort_keys=False), encoding="utf-8")
        settings = Settings(
            policy_dir=policy_dir,
            database_url=f"sqlite+aiosqlite:///{root / 'acl.db'}",
            audit_path=root / "audit.jsonl",
            deterministic=True,
            value_hash_salt="test-salt",  # type: ignore[arg-type]
        )
        app = create_app(settings, allow_anonymous_dev=True)
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        app.state.test_client = client
        return app

    yield build
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def app(make_app: AppFactory) -> Any:
    return make_app()


def upload(
    app: Any,
    name: str | None = None,
    *,
    filename: str | None = None,
    data: bytes | None = None,
    who: dict[str, str] = ADMIN,
    source: str | None = None,
):
    body = data if data is not None else fixture_bytes(name or "benign_safetensors")
    fname = filename or (fixture_filename(name) if name else "model.safetensors")
    form = {"source": source} if source is not None else None
    return app.state.test_client.post(
        SCAN, files={"file": (fname, body, "application/octet-stream")}, data=form, headers=who
    )


def audit_lines(app: Any) -> list[dict[str, Any]]:
    path: Path = app.state.settings.audit_path
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


@pytest.fixture
def private_tempdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Uploads land in a per-test temp dir: other xdist workers' in-flight uploads must not be counted."""
    d = tmp_path / "uploads"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


def leftover_temp_files() -> set[str]:
    return {p.name for p in Path(tempfile.gettempdir()).glob("acl-artifact-*")}


# ------------------------------------------------------------------ scan
def test_malicious_pickle_upload_is_reported_stored_audited_and_raises_an_incident(app: Any) -> None:
    r = upload(app, "pickle_os_system")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "malicious" and body["format_detected"] == "pickle"
    assert body["sha256"] == sha_of("pickle_os_system") and body["size"] == len(fixture_bytes("pickle_os_system"))
    assert body["filename"] == "os_system.pkl" and body["scanned_by"] == "adam" and body["id"].startswith("art-")
    rules = {f["rule_id"]: f for f in body["findings"]}
    assert {"ART-PICKLE-01", "ART-FORMAT-01"} <= set(rules)
    assert rules["ART-PICKLE-01"]["severity"] == "critical" and "os.system" in rules["ART-PICKLE-01"]["detail"]
    assert "malicious" not in rules["ART-PICKLE-01"]  # contract fields only
    assert body["decision_id"] and body["source"] is None and body["exception"] is None
    assert "rogatka-test" not in r.text

    events = audit_lines(app)
    scan_events = [e for e in events if e["event_type"] == "artifact_scan"]
    assert len(scan_events) == 1
    ev = scan_events[0]
    assert ev["severity"] == "critical"
    assert ev["detail"]["scan_id"] == body["id"] and ev["detail"]["verdict"] == "malicious"
    assert ev["detail"]["sha256"] == body["sha256"] and ev["detail"]["format"] == "pickle"
    assert "ART-PICKLE-01" in ev["detail"]["rule_ids"] and ev["detail"]["filename"] == "os_system.pkl"
    assert "rogatka-test" not in json.dumps(ev)
    # the artifact_load decision is in the audit log with the control's rule ids
    decisions = [e["decision"] for e in events if e["event_type"] == "decision" and e["point"] == "artifact_load"]
    assert len(decisions) == 1 and decisions[0]["action"] == "block" and decisions[0]["decided_by"] == ART
    assert ART in decisions[0]["rule_ids"] and "ART-PICKLE-01" in decisions[0]["rule_ids"]
    assert decisions[0]["reason"].startswith("artifact verdict malicious: ART-PICKLE-01")
    # incident
    incidents = app.state.test_client.get("/admin/v1/incidents", headers=VIEWER).json()
    assert any(i["category"] == "artifact_blocked" and i["severity"] == "critical" for i in incidents)
    assert app.state.test_client.get("/admin/v1/audit/verify", headers=ADMIN).json()["ok"] is True


def test_benign_safetensors_upload_is_safe_and_not_an_incident(app: Any) -> None:
    r = upload(app, "benign_safetensors")
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "safe" and body["format_detected"] == "safetensors" and body["findings"] == []
    events = audit_lines(app)
    ev = next(e for e in events if e["event_type"] == "artifact_scan")
    assert ev["severity"] == "info" and ev["detail"]["verdict"] == "safe"
    assert not any(e["event_type"] == "incident" for e in events)
    decision = next(e for e in events if e["event_type"] == "decision")
    assert decision["decision"]["action"] == "allow"


@pytest.mark.parametrize(
    ("fixture", "verdict", "rule", "severity"),
    [
        ("pickle_7z_wrapped", "malicious", "ART-ARCHIVE-01", "critical"),
        ("pickle_broken_stream", "malicious", "ART-PICKLE-03", "critical"),
        ("keras_lambda", "malicious", "ART-KERAS-01", "critical"),
        ("gguf_template_injection", "malicious", "ART-GGUF-02", "critical"),
        ("benign_torch_zip", "blocked_format", "ART-FORMAT-01", "high"),
        ("benign_gguf", "safe", None, "info"),
    ],
)
def test_other_files(app: Any, fixture: str, verdict: str, rule: str | None, severity: str) -> None:
    body = upload(app, fixture).json()
    assert body["verdict"] == verdict
    if rule:
        assert rule in {f["rule_id"] for f in body["findings"]}
    ev = next(e for e in audit_lines(app) if e["event_type"] == "artifact_scan")
    assert ev["severity"] == severity


def test_every_fixture_can_be_scanned_over_http(app: Any) -> None:
    verdicts = {}
    for name in FIXTURES:
        r = upload(app, name)
        assert r.status_code == 200, (name, r.text)
        verdicts[name] = r.json()["verdict"]
    assert verdicts["benign_safetensors"] == "safe" and verdicts["benign_gguf"] == "safe"
    assert verdicts["pickle_benign_blocked"] == "blocked_format"
    assert verdicts["pickle_os_system"] == "malicious"
    assert sorted(set(verdicts.values())) == ["blocked_format", "malicious", "safe"]


def test_hf_source_is_checked(app: Any) -> None:
    pinned = upload(app, "benign_safetensors", source=f"hf:meta-llama/Llama-3-8B@{'b' * 40}").json()
    assert pinned["verdict"] == "safe" and pinned["source"] == f"hf:meta-llama/Llama-3-8B@{'b' * 40}"
    branch = upload(app, "benign_safetensors", source="hf:meta-llama/Llama-3-8B@main").json()
    assert branch["verdict"] == "suspicious" and {f["rule_id"] for f in branch["findings"]} == {"ART-HF-01"}
    unlisted = upload(app, "benign_safetensors", source=f"hf:evil/x@{'b' * 40}").json()
    assert unlisted["verdict"] == "suspicious" and {f["rule_id"] for f in unlisted["findings"]} == {"ART-HF-02"}
    assert upload(app, "benign_safetensors", source="upload").json()["verdict"] == "safe"


def test_exception_in_policy_admits_a_benign_pickle_but_never_a_malicious_one(make_app: AppFactory) -> None:
    params = {
        "exceptions": [
            {"sha256": sha_of("benign_pickle_plain"), "reason": "legacy checkpoint reviewed"},
            {"sha256": sha_of("pickle_os_system"), "reason": "attacker-friendly exception"},
        ]
    }
    app = make_app(art_params=params)
    ok = upload(app, "benign_pickle_plain").json()
    assert ok["verdict"] == "safe" and ok["exception"] == "legacy checkpoint reviewed"
    assert ok["format_detected"] == "pickle"
    bad = upload(app, "pickle_os_system").json()
    assert bad["verdict"] == "malicious" and bad["exception"] is None
    assert upload(app, "pickle_benign_blocked").json()["verdict"] == "blocked_format"  # different sha256


def test_feed_opcode_signature_makes_an_admitted_file_malicious_with_the_sig_id(make_app: AppFactory) -> None:
    params = {
        "exceptions": [{"sha256": sha_of("benign_torch_zip"), "reason": "reviewed"}],
        "use_feed_opcodes": False,
    }
    app = make_app(art_params=params)
    assert upload(app, "benign_torch_zip").json()["verdict"] == "safe"
    install_feed(app, [feed_entry("SIG-OPCODE-REBUILD", "torch._utils._rebuild_tensor*")])
    body = upload(app, "benign_torch_zip").json()
    assert body["verdict"] == "malicious"
    sig = next(f for f in body["findings"] if f["rule_id"] == "SIG-OPCODE-REBUILD")
    assert sig["severity"] == "high"
    ev = [e for e in audit_lines(app) if e["event_type"] == "artifact_scan"][-1]
    assert "SIG-OPCODE-REBUILD" in ev["detail"]["rule_ids"] and ev["severity"] == "critical"


def test_feed_signature_with_the_scanner_applying_it_too(app: Any) -> None:
    install_feed(app, [feed_entry("SIG-OPCODE-POSIX", "posix.*")])
    body = upload(app, "torch_zip_os_system").json()
    assert body["verdict"] == "malicious"
    assert {"SIG-OPCODE-POSIX", "ART-PICKLE-01"} <= {f["rule_id"] for f in body["findings"]}


def test_temp_file_is_removed_after_the_scan(app: Any, private_tempdir: Path) -> None:
    before = leftover_temp_files()
    assert upload(app, "pickle_os_system").status_code == 200
    assert upload(app, "benign_safetensors").status_code == 200
    assert upload(app, data=b"", filename="empty.bin").status_code == 200
    assert leftover_temp_files() == before


def test_filename_with_path_components_is_sanitised(app: Any) -> None:
    body = upload(app, "benign_safetensors", filename="../../etc/passwd\\..\\evil/model.safetensors").json()
    assert body["filename"] == "model.safetensors"
    assert upload(app, "benign_safetensors", filename="/abs/dir/x.safetensors").json()["filename"] == "x.safetensors"
    assert safe_filename("a\x00b\x1b[31m.pt") == "ab[31m.pt"
    assert (
        safe_filename("") == "upload.bin"
        and safe_filename(None) == "upload.bin"
        and safe_filename("../") == "upload.bin"
    )
    assert len(safe_filename("x" * 1000 + ".pt")) <= 200
    ev = next(e for e in audit_lines(app) if e["event_type"] == "artifact_scan")
    assert ev["detail"]["filename"] == "model.safetensors"


def test_oversize_upload_is_rejected_with_413_and_nothing_is_stored(
    make_app: AppFactory, private_tempdir: Path
) -> None:
    app = make_app(art_params={"max_file_bytes": 64})
    before = leftover_temp_files()
    r = upload(app, data=b"\x00" * 200, filename="big.safetensors")
    assert r.status_code == 413
    assert upload(app, data=b"\x00" * 64, filename="exact.safetensors").status_code == 200
    assert leftover_temp_files() == before
    listing = app.state.test_client.get("/admin/v1/artifacts", headers=VIEWER).json()
    assert [x["filename"] for x in listing] == ["exact.safetensors"]


def test_unreadable_garbage_is_blocked_not_an_error(app: Any) -> None:
    body = upload(app, data=bytes(range(256)) * 4, filename="weights.pt").json()
    assert body["verdict"] == "malicious" and "ART-FORMAT-02" in {f["rule_id"] for f in body["findings"]}
    assert upload(app, data=b"", filename="empty.safetensors").json()["verdict"] == "malicious"


# ------------------------------------------------------------------ auth
def test_roles(app: Any) -> None:
    assert upload(app, "benign_safetensors", who=VIEWER).status_code == 403
    assert upload(app, "benign_safetensors", who=ANALYST).status_code == 403
    client = app.state.test_client
    assert client.get("/admin/v1/artifacts", headers=VIEWER).status_code == 200
    assert client.get("/admin/v1/artifacts", headers=ANALYST).status_code == 200
    assert client.get("/admin/v1/artifacts", headers=hdr("nobody", "")).status_code == 403
    scan_id = upload(app, "benign_safetensors").json()["id"]
    assert client.get(f"/admin/v1/artifacts/{scan_id}", headers=VIEWER).status_code == 200
    assert client.get(f"/admin/v1/artifacts/{scan_id}", headers=hdr("nobody", "")).status_code == 403


def test_scan_requires_the_form_file(app: Any) -> None:
    assert app.state.test_client.post(SCAN, headers=ADMIN).status_code == 422


# ------------------------------------------------------------------ list and get
def test_list_and_get(app: Any) -> None:
    client = app.state.test_client
    assert client.get("/admin/v1/artifacts", headers=VIEWER).json() == []
    first = upload(app, "benign_safetensors").json()
    second = upload(app, "pickle_os_system").json()
    third = upload(app, "benign_gguf").json()
    listing = client.get("/admin/v1/artifacts", headers=VIEWER).json()
    assert [x["id"] for x in listing] == [third["id"], second["id"], first["id"]]  # newest first
    one = client.get(f"/admin/v1/artifacts/{second['id']}", headers=VIEWER)
    assert one.status_code == 200 and one.json() == second
    missing = client.get("/admin/v1/artifacts/art-doesnotexist", headers=VIEWER)
    assert missing.status_code == 404


def test_results_survive_a_restart(tmp_path: Path) -> None:
    def build() -> Any:
        settings = Settings(
            policy_dir=REPO / "policy",
            database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
            audit_path=tmp_path / "audit.jsonl",
            deterministic=True,
            value_hash_salt="test-salt",  # type: ignore[arg-type]
        )
        return create_app(settings, allow_anonymous_dev=True)

    first = build()
    with TestClient(first) as client:
        scan_id = client.post(
            SCAN, files={"file": ("m.safetensors", fixture_bytes("benign_safetensors"), "x")}, headers=ADMIN
        ).json()["id"]
    second = build()
    with TestClient(second) as client:
        got = client.get(f"/admin/v1/artifacts/{scan_id}", headers=VIEWER)
        assert got.status_code == 200 and got.json()["verdict"] == "safe"
        assert second.state.artifacts.passing(sha_of("benign_safetensors")) == scan_id


# ------------------------------------------------------------------ fail closed
def test_scanner_disabled_reports_suspicious_with_art_scan_00(make_app: AppFactory, tmp_path: Path) -> None:
    app = make_app()
    engine = app.state.engine
    policy = engine.policy.model_copy(update={"controls": [c for c in engine.policy.controls if c.id != ART]})
    app.state.engine = app.state.build_engine(policy, "no-art")
    body = upload(app, "benign_safetensors").json()
    assert body["verdict"] == "suspicious"
    assert [f["rule_id"] for f in body["findings"]] == ["ART-SCAN-00"]
    assert body["format_detected"] == "unknown"


def test_missing_engine_or_audit_is_503(app: Any) -> None:
    app.state.engine, saved = None, app.state.engine
    assert upload(app, "benign_safetensors").status_code == 503
    app.state.engine = saved
    audit, app.state.audit = app.state.audit, None
    assert upload(app, "benign_safetensors").status_code == 503
    app.state.audit = audit
    assert upload(app, "benign_safetensors").status_code == 200


# ------------------------------------------------------------------ registry load hook
def gated_model(model_id: str, sha: str, **ref: Any) -> dict[str, Any]:
    return {
        "id": model_id,
        "connector": "local",
        "upstream_model": "env:LOCAL_GENERAL_MODEL",
        "data_classes": ["public", "internal"],
        "artifact": {"sha256": sha, **ref},
    }


def admin_model(app: Any, model_id: str) -> dict[str, Any]:
    models = app.state.test_client.get("/admin/v1/models", headers=VIEWER).json()
    return next(m for m in models if m["id"] == model_id)


def problem(app: Any, model_id: str) -> str | None:
    engine = app.state.engine
    return app.state.connectors.table_for(engine.policy, engine.policy_version).model_problem(model_id)


def test_model_with_unscanned_artifact_is_unavailable_until_a_passing_scan_exists(make_app: AppFactory) -> None:
    sha = sha_of("benign_safetensors")
    app = make_app(models=[gated_model("local/scanned", sha)])
    info = admin_model(app, "local/scanned")
    assert info["artifact_status"] == "unscanned" and info["available"] is False
    assert problem(app, "local/scanned") == f"artifact {sha[:12]} has no passing scan"
    assert admin_model(app, "local/qwen3.8-27b")["artifact_status"] == "n/a"
    assert problem(app, "local/qwen3.8-27b") is None

    # scanning the matching file makes it available without a policy reload
    scan_id = upload(app, "benign_safetensors").json()["id"]
    info = admin_model(app, "local/scanned")
    assert info["artifact_status"] == "scanned_ok" and info["available"] is True
    assert problem(app, "local/scanned") is None
    listing = app.state.test_client.get(f"/admin/v1/artifacts/{scan_id}", headers=VIEWER).json()
    assert listing["model_ids"] == ["local/scanned"]


def test_scan_id_pin_must_name_a_passing_scan_of_that_sha(make_app: AppFactory) -> None:
    sha = sha_of("benign_safetensors")
    app = make_app(models=[gated_model("local/pinned", sha, scan_id="art-000000000000")])
    scan_id = upload(app, "benign_safetensors").json()["id"]  # a passing scan exists, but it is not the pinned one
    assert admin_model(app, "local/pinned")["available"] is False
    assert problem(app, "local/pinned") is not None
    # re-pin the model to the real scan (policy swap): now it loads
    engine = app.state.engine
    models = [
        m.model_copy(update={"artifact": m.artifact.model_copy(update={"scan_id": scan_id})})
        if m.artifact is not None
        else m
        for m in engine.policy.models
    ]
    app.state.engine = app.state.build_engine(engine.policy.model_copy(update={"models": models}), "pinned")
    assert admin_model(app, "local/pinned")["available"] is True
    # a scan id of a different file does not count even if it passes
    other = upload(app, "benign_gguf").json()["id"]
    models = [
        m.model_copy(update={"artifact": m.artifact.model_copy(update={"scan_id": other})})
        if m.artifact is not None
        else m
        for m in app.state.engine.policy.models
    ]
    app.state.engine = app.state.build_engine(app.state.engine.policy.model_copy(update={"models": models}), "other")
    assert admin_model(app, "local/pinned")["available"] is False


def test_artifact_with_a_failing_scan_is_scanned_bad_and_stays_unavailable(make_app: AppFactory) -> None:
    sha = sha_of("pickle_benign_blocked")
    app = make_app(models=[gated_model("local/pickled", sha)])
    assert upload(app, "pickle_benign_blocked").json()["verdict"] == "blocked_format"
    info = admin_model(app, "local/pickled")
    assert info["artifact_status"] == "scanned_bad" and info["available"] is False
    assert problem(app, "local/pickled") is not None


def test_newest_scan_decides_exception_admits_and_rescan_revokes(make_app: AppFactory) -> None:
    sha = sha_of("benign_pickle_plain")
    app = make_app(models=[gated_model("local/legacy", sha)])
    assert upload(app, "benign_pickle_plain").json()["verdict"] == "blocked_format"
    assert admin_model(app, "local/legacy")["artifact_status"] == "scanned_bad"
    # an admin grants an exception for that exact file: the next scan passes and the model loads
    engine = app.state.engine
    controls = []
    for c in engine.policy.controls:
        if c.id == ART:
            c = c.model_copy(update={"params": {**c.params, "exceptions": [{"sha256": sha, "reason": "reviewed"}]}})
        controls.append(c)
    app.state.engine = app.state.build_engine(engine.policy.model_copy(update={"controls": controls}), "exc")
    assert upload(app, "benign_pickle_plain").json()["verdict"] == "safe"
    info = admin_model(app, "local/legacy")
    assert info["artifact_status"] == "scanned_ok" and info["available"] is True
    # the exception is withdrawn: the next re-scan fails and revokes the model (the newest scan decides)
    app.state.engine = engine
    assert upload(app, "benign_pickle_plain").json()["verdict"] == "blocked_format"
    info = admin_model(app, "local/legacy")
    assert info["artifact_status"] == "scanned_bad" and info["available"] is False


def test_requests_for_a_gated_model_are_not_served_by_it_until_scanned(make_app: AppFactory) -> None:
    sha = sha_of("benign_safetensors")
    app = make_app(models=[gated_model("local/scanned", sha)])
    client = app.state.test_client
    payload = {"model": "local/scanned", "messages": [{"role": "user", "content": "hello"}]}
    before = client.post("/v1/chat/completions", json=payload, headers=ADMIN)
    # unavailable models fall back to the degraded target (routing.yaml), never to the unscanned weights
    assert "MOCK[local/scanned]" not in before.text
    upload(app, "benign_safetensors")
    after = client.post("/v1/chat/completions", json=payload, headers=ADMIN)
    assert after.status_code == 200, after.text
    assert "MOCK[local/scanned]" in after.text


def test_registry_gate_is_not_installed_without_the_installer(tmp_path: Path) -> None:
    settings = Settings(
        policy_dir=REPO / "policy",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'x.db'}",
        audit_path=tmp_path / "a.jsonl",
        deterministic=True,
        value_hash_salt="s",  # type: ignore[arg-type]
    )
    from acl.main import INSTALLERS

    app = create_app(settings, allow_anonymous_dev=True, installers=[i for i in INSTALLERS if "artifacts" not in i])
    with TestClient(app):
        assert app.state.connectors.artifact_gate is None
        assert getattr(app.state, "artifacts", None) is None
        # fail closed: without the gate a model that pins an artifact is never served unchecked
        engine = app.state.engine
        entry = ModelEntry.model_validate(gated_model("local/pinned", "a" * 64))
        policy = engine.policy.model_copy(update={"models": [*engine.policy.models, entry]})
        app.state.engine = app.state.build_engine(policy, "gated")
        assert problem(app, "local/pinned") == "artifact gate unavailable"
