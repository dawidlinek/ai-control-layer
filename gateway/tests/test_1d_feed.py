"""1D: signature feed — verification, atomic swap, polling, feed server, and the live "add a rule" demo."""

from __future__ import annotations

import base64
import importlib.util
import json
import shutil
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi.testclient import TestClient

from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.contracts.canonical import bundle_digest, canonical_json
from acl.contracts.common import Action, InspectionPoint
from acl.contracts.feed import FeedBundle
from acl.controls.base import ControlDeps
from acl.engine.engine import Engine
from acl.feed.store import InstallOutcome, SignatureStore
from acl.feed.sync import FeedConfig, FeedSync
from acl.feed.verify import FeedVerifyError, parse_public_key, verify_bundle
from acl.main import create_app
from acl.policy.loader import load_policy_dir
from acl.settings import Settings
from acl.testing import make_context

ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = ROOT / "policy"
SERVER_PY = ROOT / "feed-server" / "server.py"
URL = "http://feed.test/bundle.json"


def _load_feed_server():
    spec = importlib.util.spec_from_file_location("acl_feed_server", SERVER_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


feed_server = _load_feed_server()


def entry(eid: str, pattern: str = "(?i)forbidden-phrase", **kw: Any) -> dict[str, Any]:
    base = {
        "id": eid,
        "type": "regex",
        "pattern": pattern,
        "severity": "high",
        "action": "block",
        "stages": ["ingress"],
        "description": "",
        "atlas_technique": [],
        "owasp": [],
        "cve": [],
        "source": "internal",
        "expires": None,
        "metadata": {},
    }
    return {**base, **kw}


def bundle(version: int, entries: list[dict[str, Any]] | None = None, *, key: Ed25519PrivateKey | None = None) -> dict:
    body = {
        "schema_version": "1.0",
        "bundle_version": version,
        "issued_at": datetime(2026, 10, 3, 12, 0, tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": "acl-feed-server",
        "entries": entries if entries is not None else [entry("SIG-TEST-ONE-01")],
    }
    if key is None:
        sig = {"alg": "sha256", "key_id": None, "value": bundle_digest(body)}
    else:
        sig = {
            "alg": "ed25519",
            "key_id": "k1",
            "value": base64.b64encode(key.sign(canonical_json(body).encode())).decode(),
        }
    return {**body, "signature": sig}


def raw_seed(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


@lru_cache(maxsize=1)
def _loaded():
    return load_policy_dir(POLICY_DIR)


# --------------------------------------------------------------------------- ed25519 signer (stdlib)


def test_pure_python_ed25519_matches_rfc8032_vector() -> None:
    ed = feed_server.ed25519
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert ed.public_key(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed.sign(seed, b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )


def test_pure_python_signatures_verify_with_cryptography() -> None:
    ed = feed_server.ed25519
    key = Ed25519PrivateKey.generate()
    seed = raw_seed(key)
    assert ed.public_key(seed) == key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    msg = canonical_json(bundle(3)).encode()
    key.public_key().verify(ed.sign(seed, msg), msg)  # raises on mismatch


# --------------------------------------------------------------------------- verification


def test_sha256_bundle_verifies_and_tampering_is_rejected() -> None:
    b = bundle(1)
    assert verify_bundle(b).bundle_version == 1
    tampered = json.loads(json.dumps(b))
    tampered["entries"][0]["pattern"] = ".*"
    with pytest.raises(FeedVerifyError) as exc:
        verify_bundle(tampered)
    assert exc.value.code == "digest_mismatch"
    wrong_sig = {**b, "signature": {**b["signature"], "value": "0" * 64}}
    with pytest.raises(FeedVerifyError):
        verify_bundle(wrong_sig)


def test_schema_violations_are_rejected() -> None:
    b = bundle(1)
    for broken in ({**b, "bundle_version": 0}, {**b, "extra": 1}, {k: v for k, v in b.items() if k != "entries"}):
        with pytest.raises(FeedVerifyError) as exc:
            verify_bundle(broken)
        assert exc.value.code == "schema"
    bad_entry = bundle(1, [{**entry("SIG-X-01"), "type": "nonsense"}])
    with pytest.raises(FeedVerifyError):
        verify_bundle(bad_entry)


def test_ed25519_bundle_verification() -> None:
    key = Ed25519PrivateKey.generate()
    b = bundle(2, key=key)
    assert verify_bundle(b, mode="ed25519", public_key=pub_b64(key)).bundle_version == 2
    other = Ed25519PrivateKey.generate()
    with pytest.raises(FeedVerifyError) as exc:
        verify_bundle(b, mode="ed25519", public_key=pub_b64(other))
    assert exc.value.code == "bad_signature"
    tampered = json.loads(json.dumps(b))
    tampered["entries"] = []
    with pytest.raises(FeedVerifyError) as exc:
        verify_bundle(tampered, mode="ed25519", public_key=pub_b64(key))
    assert exc.value.code == "bad_signature"
    with pytest.raises(FeedVerifyError) as exc:
        verify_bundle(b, mode="ed25519", public_key=None)
    assert exc.value.code == "no_public_key"
    with pytest.raises(FeedVerifyError) as exc:
        verify_bundle(b, mode="ed25519", public_key="not a key")
    assert exc.value.code == "bad_public_key"


def test_verification_mode_cannot_be_downgraded() -> None:
    key = Ed25519PrivateKey.generate()
    with pytest.raises(FeedVerifyError) as exc:  # operator requires ed25519; a mere checksum must not pass
        verify_bundle(bundle(2), mode="ed25519", public_key=pub_b64(key))
    assert exc.value.code == "alg_mismatch"
    with pytest.raises(FeedVerifyError) as exc:
        verify_bundle(bundle(2, key=key), mode="sha256")
    assert exc.value.code == "alg_mismatch"


def test_public_key_formats() -> None:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    for form in (base64.b64encode(raw).decode(), raw.hex(), pem):
        assert parse_public_key(form).public_bytes(Encoding.Raw, PublicFormat.Raw) == raw


# --------------------------------------------------------------------------- store


def _install(store: SignatureStore, b: dict):
    parsed = FeedBundle.model_validate(b)
    return store.install(parsed, bundle_digest(b))


def test_store_swap_is_monotonic() -> None:
    store = SignatureStore()
    assert store.current() is None and store.version is None
    assert _install(store, bundle(2))[0] == InstallOutcome.installed
    first = store.current()
    assert _install(store, bundle(2))[0] == InstallOutcome.unchanged
    assert _install(store, bundle(2, [entry("SIG-OTHER-01")]))[0] == InstallOutcome.conflict
    assert _install(store, bundle(1))[0] == InstallOutcome.not_increasing
    assert store.current() is first  # nothing changed
    assert _install(store, bundle(3, [entry("SIG-OTHER-01")]))[0] == InstallOutcome.installed
    assert store.version == 3 and [e.id for e in store.current().entries] == ["SIG-OTHER-01"]
    assert store.status().entries == 1 and store.status().verified


def test_store_skips_entries_that_do_not_compile() -> None:
    store = SignatureStore()
    b = bundle(
        1,
        [
            entry("SIG-GOOD-01"),
            entry("SIG-BAD-RX-01", "(unclosed"),
            entry("SIG-BAD-PKG-01", "noecosystem", type="package_version"),
            entry("SIG-BAD-YARA-01", "rule {", type="yara"),
            entry("SIG-BAD-HASH-01", "zz", type="manifest_hash"),
        ],
    )
    _, compiled = _install(store, b)
    assert [e.id for e in compiled.entries] == ["SIG-GOOD-01"] and len(compiled.errors) == 4


def test_re2_rejected_patterns_fall_back_to_re() -> None:
    store = SignatureStore()
    _install(store, bundle(1, [entry("SIG-LOOKAHEAD-01", r"foo(?=bar)")]))  # look-ahead is not RE2
    (ce,) = store.current().entries
    assert ce.matcher.search("xx foobar") == (3, 6)


# --------------------------------------------------------------------------- sync (respx)


def _sync(store: SignatureStore, sink: RecordingSink | None = None, **cfg: Any) -> FeedSync:
    return FeedSync(store, config=lambda: FeedConfig(url=URL, **cfg), audit=lambda: sink)


@respx.mock
async def test_valid_bundle_swaps_and_audits() -> None:
    store, sink = SignatureStore(), RecordingSink()
    respx.get(URL).mock(return_value=httpx.Response(200, json=bundle(1)))
    res = await _sync(store, sink).sync_once()
    assert res.outcome == "updated" and store.version == 1
    assert [e[0] for e in sink.events] == [EventType.feed_update]
    assert sink.events[0][1]["detail"]["bundle_version"] == 1
    assert store.status().source_url == URL and store.status().last_error is None


@respx.mock
async def test_tampered_bundle_is_rejected_and_last_good_kept() -> None:
    store, sink = SignatureStore(), RecordingSink()
    sync = _sync(store, sink)
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=bundle(1)))
    await sync.sync_once()
    good = store.current()

    tampered = bundle(2)
    tampered["entries"][0]["action"] = "allow"  # attacker weakens a rule without re-signing
    route.mock(return_value=httpx.Response(200, json=tampered))
    res = await sync.sync_once()
    assert res.outcome == "rejected" and res.code == "digest_mismatch"
    assert store.current() is good and store.version == 1
    assert "rejected" in (store.status().last_error or "")
    failed = [e for e in sink.events if e[0] == EventType.feed_verify_failed]
    assert len(failed) == 1 and failed[0][1]["detail"]["code"] == "digest_mismatch"
    assert failed[0][1]["detail"]["offered_version"] == 2 and failed[0][1]["detail"]["active_version"] == 1

    await sync.sync_once()  # the same bad bundle again: no alert storm
    assert len([e for e in sink.events if e[0] == EventType.feed_verify_failed]) == 1


@respx.mock
async def test_lower_and_conflicting_versions_are_rejected() -> None:
    store, sink = SignatureStore(), RecordingSink()
    sync = _sync(store, sink)
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=bundle(5)))
    await sync.sync_once()

    route.mock(return_value=httpx.Response(200, json=bundle(4, [entry("SIG-OLD-01")])))  # validly signed but older
    res = await sync.sync_once()
    assert res.code == "version_not_increasing" and store.version == 5

    route.mock(return_value=httpx.Response(200, json=bundle(5, [entry("SIG-FORK-01")])))  # same version, other content
    assert (await sync.sync_once()).code == "version_conflict"

    route.mock(return_value=httpx.Response(200, json=bundle(5)))  # unchanged re-poll is not an error
    assert (await sync.sync_once()).outcome == "unchanged"
    codes = [e[1]["detail"]["code"] for e in sink.events if e[0] == EventType.feed_verify_failed]
    assert codes == ["version_not_increasing", "version_conflict"]


@respx.mock
async def test_network_errors_keep_last_good_and_do_not_alert() -> None:
    store, sink = SignatureStore(), RecordingSink()
    sync = _sync(store, sink)
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=bundle(1)))
    await sync.sync_once()
    for bad in (httpx.Response(500), httpx.Response(200, text="<html>not json"), httpx.ConnectError("down")):
        route.mock(side_effect=bad) if isinstance(bad, Exception) else route.mock(return_value=bad)
        res = await sync.sync_once()
        assert res.outcome == "error" and store.version == 1
    assert store.status().last_error.startswith("fetch failed")
    assert all(e[0] != EventType.feed_verify_failed for e in sink.events)


@respx.mock
async def test_non_object_and_garbage_bundles_are_rejected() -> None:
    store = SignatureStore()
    sync = _sync(store)
    respx.get(URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    assert (await sync.sync_once()).outcome == "rejected" and store.current() is None


@respx.mock
async def test_ed25519_policy_rejects_checksum_only_bundle() -> None:
    key = Ed25519PrivateKey.generate()
    store, sink = SignatureStore(), RecordingSink()
    sync = _sync(store, sink, verify="ed25519", public_key=pub_b64(key))
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=bundle(1)))  # sha256-signed
    assert (await sync.sync_once()).code == "alg_mismatch"
    route.mock(return_value=httpx.Response(200, json=bundle(1, key=key)))
    assert (await sync.sync_once()).outcome == "updated"


async def test_no_feed_configured() -> None:
    store = SignatureStore()
    res = await FeedSync(store, config=lambda: None).sync_once()
    assert res.outcome == "unconfigured" and store.status().last_error == "no feed configured"


@respx.mock
async def test_audit_failures_never_block_a_swap() -> None:
    class Boom(RecordingSink):
        async def record_event(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("audit down")

    store = SignatureStore()
    respx.get(URL).mock(return_value=httpx.Response(200, json=bundle(1)))
    assert (await _sync(store, Boom()).sync_once()).outcome == "updated"


# --------------------------------------------------------------------------- feed server


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Any]:
    srv = feed_server.make_server(
        "127.0.0.1",
        0,
        bundle_dir=ROOT / "feed-server" / "bundles",
        state_dir=tmp_path / "state",
        admin_token="s3cr3t-token",
    )
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def _auth(token: str = "s3cr3t-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_seed_bundle_is_served_valid_and_matches_policy_baseline(server) -> None:
    async with httpx.AsyncClient() as c:
        raw = (await c.get(server.base + "/bundle.json")).json()
        digest = (await c.get(server.base + "/bundle.sha256")).text
    assert verify_bundle(raw).bundle_version == 1 and digest == raw["signature"]["value"]
    ids = [e["id"] for e in raw["entries"]]
    assert len(ids) == len(set(ids)) >= 20
    # the offline baseline in policy/controls.yaml is the same rule set (kept in sync by hand → pinned here)
    local = {r.id: r for r in _loaded().policy.signatures.local_rules}
    assert set(local) == set(ids)
    for e in raw["entries"]:
        assert FeedBundle.model_validate(raw).entries  # schema-valid
        lr = local[e["id"]].model_dump(mode="json")
        assert {k: lr[k] for k in ("type", "pattern", "severity", "action", "stages", "metadata")} == {
            k: e[k] for k in ("type", "pattern", "severity", "action", "stages", "metadata")
        }


async def test_live_edit_requires_the_token_and_bumps_the_version(server) -> None:
    new = entry("SIG-DEMO-01", "(?i)nightingale")
    async with httpx.AsyncClient() as c:
        assert (await c.post(server.base + "/entries", json=new)).status_code == 401
        assert (await c.post(server.base + "/entries", json=new, headers=_auth("wrong"))).status_code == 401
        r = await c.post(server.base + "/entries", json=new, headers=_auth())
        assert r.status_code == 201 and r.json()["bundle_version"] == 2 and r.json()["upserted"] == ["SIG-DEMO-01"]
        raw = (await c.get(server.base + "/bundle.json")).json()
        assert verify_bundle(raw).bundle_version == 2 and "SIG-DEMO-01" in [e["id"] for e in raw["entries"]]
        # upsert replaces by id, deleting removes
        new2 = entry("SIG-DEMO-01", "(?i)other")
        assert (await c.post(server.base + "/entries", json={"entries": [new2]}, headers=_auth())).json()[
            "entries"
        ] == (len(raw["entries"]))
        assert (await c.delete(server.base + "/entries/SIG-DEMO-01", headers=_auth())).status_code == 200
        assert (await c.delete(server.base + "/entries/SIG-DEMO-01", headers=_auth())).status_code == 404
        final = (await c.get(server.base + "/bundle.json")).json()
        assert final["bundle_version"] == 4 and "SIG-DEMO-01" not in [e["id"] for e in final["entries"]]


async def test_live_edit_validates_entries_and_can_be_disabled(server, tmp_path: Path) -> None:
    async with httpx.AsyncClient() as c:
        for bad in (
            {**entry("SIG-X-01"), "type": "nope"},
            {**entry("SIG-X-01"), "id": "lower-case"},
            {**entry("SIG-X-01", "(unclosed")},
            {**entry("SIG-X-01"), "unknown_field": 1},
            {**entry("SIG-X-01"), "stages": ["nowhere"]},
            {**entry("SIG-X-01"), "action": "explode"},
            [],
            "text",
        ):
            r = await c.post(server.base + "/entries", json=bad, headers=_auth())
            assert r.status_code == 422, bad
    off = feed_server.make_server(
        "127.0.0.1", 0, bundle_dir=ROOT / "feed-server" / "bundles", state_dir=tmp_path / "s2"
    )
    threading.Thread(target=off.serve_forever, daemon=True).start()
    try:
        async with httpx.AsyncClient() as c:
            r = await c.post(
                f"http://127.0.0.1:{off.server_address[1]}/entries", json=entry("SIG-X-01"), headers=_auth()
            )
            assert r.status_code == 403
    finally:
        off.shutdown()
        off.server_close()


async def test_server_signs_with_ed25519_when_configured(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    seed = raw_seed(key)
    srv = feed_server.make_server(
        "127.0.0.1",
        0,
        bundle_dir=ROOT / "feed-server" / "bundles",
        state_dir=tmp_path / "s",
        signing_seed=seed,
        key_id="k1",
    )
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        async with httpx.AsyncClient() as c:
            raw = (await c.get(f"http://127.0.0.1:{srv.server_address[1]}/bundle.json")).json()
        assert raw["signature"]["alg"] == "ed25519" and raw["signature"]["key_id"] == "k1"
        assert verify_bundle(raw, mode="ed25519", public_key=pub_b64(key)).bundle_version == 1
        with pytest.raises(FeedVerifyError):
            verify_bundle(raw, mode="ed25519", public_key=pub_b64(Ed25519PrivateKey.generate()))
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------------------ the demo: add a rule → next request blocked


async def test_adding_a_rule_to_the_feed_blocks_the_next_request(server) -> None:
    store = SignatureStore()
    loaded = _loaded()
    engine = Engine.build(loaded.policy, loaded.version, deps=ControlDeps(signatures=store))
    sync = FeedSync(store, config=lambda: FeedConfig(url=server.base + "/bundle.json"))
    prompt = "Please summarise the Project Nightingale roadmap"

    assert (await sync.sync_once()).outcome == "updated"
    assert (await engine.evaluate(make_context(prompt))).action == Action.allow

    async with httpx.AsyncClient() as c:
        r = await c.post(
            server.base + "/entries",
            json=entry("SIG-DEMO-NIGHTINGALE-01", r"(?i)project\s+nightingale", stages=["ingress"]),
            headers=_auth(),
        )
    assert r.status_code == 201
    assert (await sync.sync_once()).outcome == "updated"  # = POST /admin/v1/feed/sync

    d = await engine.evaluate(make_context(prompt))
    assert d.action == Action.block and d.final and d.rule_ids == ["SIG-DEMO-NIGHTINGALE-01"]
    assert (await engine.evaluate(make_context("Tell me about nightingales"))).action == Action.allow

    # removing the rule unblocks the next request after the following sync
    async with httpx.AsyncClient() as c:
        await c.delete(server.base + "/entries/SIG-DEMO-NIGHTINGALE-01", headers=_auth())
    await sync.sync_once()
    assert (await engine.evaluate(make_context(prompt))).action == Action.allow


# --------------------------------------------------------------------------- admin routes + wiring


def test_admin_feed_routes_and_wiring(server) -> None:
    settings = Settings(policy_dir=POLICY_DIR, feed_url=server.base + "/bundle.json", deterministic=True)
    app = create_app(
        settings, allow_anonymous_dev=True, installers=["acl.feed.wiring:install", "acl.controls.pii.wiring:install"]
    )
    with TestClient(app) as client:
        assert app.state.control_deps.get("signatures") is app.state.feed_store
        assert app.state.control_deps.get("vault") is not None
        st = client.get("/admin/v1/feed").json()
        assert st["bundle_version"] is None and st["entries"] == 0 and not st["verified"]

        st = client.post("/admin/v1/feed/sync").json()
        assert st["bundle_version"] == 1 and st["entries"] >= 20 and st["verified"] and st["last_error"] is None
        assert st["source_url"].endswith("/bundle.json") and st["last_sync_at"]

        # the engine built by the app sees the live store
        ctx = make_context(
            {"tool": "opencode.bash", "arguments": {"command": "rm -rf /"}}, point=InspectionPoint.tool_call
        )
        import asyncio

        decision = asyncio.run(app.state.engine.evaluate(ctx))
        assert decision.action == Action.block and "SIG-CMD-RM-RF-ROOT-01" in decision.rule_ids
        assert client.get("/admin/v1/feed").json()["bundle_version"] == 1


def test_startup_syncs_and_the_poller_picks_up_new_rules(server, tmp_path: Path) -> None:
    policy_dir = tmp_path / "policy"
    shutil.copytree(POLICY_DIR, policy_dir)
    controls = policy_dir / "controls.yaml"
    controls.write_text(controls.read_text(encoding="utf-8").replace("poll_s: 30", "poll_s: 1"), encoding="utf-8")
    settings = Settings(policy_dir=policy_dir, feed_url=server.base + "/bundle.json", deterministic=False)
    app = create_app(settings, allow_anonymous_dev=True, installers=["acl.feed.wiring:install"])
    with TestClient(app):
        store = app.state.feed_store
        assert store.version == 1  # synced during startup, before the first request
        r = httpx.post(
            server.base + "/entries", json=entry("SIG-POLL-01", "(?i)zebra-stripes"), headers=_auth(), timeout=5
        )
        assert r.status_code == 201
        deadline = time.monotonic() + 5
        while store.version != 2 and time.monotonic() < deadline:
            time.sleep(0.1)
        assert store.version == 2  # picked up by the poll loop, no manual sync
    assert app.state.feed_sync._task is None  # poller stopped at shutdown


def test_admin_feed_requires_a_role() -> None:
    app = create_app(Settings(policy_dir=POLICY_DIR, deterministic=True))
    with TestClient(app) as client:
        assert client.get("/admin/v1/feed").status_code == 401
        assert client.post("/admin/v1/feed/sync").status_code == 401
