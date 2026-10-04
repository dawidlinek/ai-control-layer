"""S2: SEC-ART-01 (artifact_scan) through the engine, with SEC-SIG-01 feed opcode matching."""

from __future__ import annotations

import hashlib
import json
from datetime import date, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from acl.artifacts.testing import fixture_filename, fixture_path
from acl.contracts.common import Action, InspectionPoint, Phase, Preset
from acl.contracts.feed import FeedBundle
from acl.contracts.inspection import ArtifactPayload, InspectionContext
from acl.controls.base import ControlDeps, load_builtin_controls, registry
from acl.engine.engine import Engine
from acl.feed.store import SignatureStore
from acl.policy.loader import load_policy_dir
from acl.policy.models import Policy
from acl.testing import make_context

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
ART = "SEC-ART-01"


@lru_cache(maxsize=1)
def _seed() -> Policy:
    return load_policy_dir(POLICY_DIR).policy


def make_policy(**params: Any) -> Policy:
    """The seed policy reduced to the two controls that see artifact_load, with SEC-ART-01 params patched."""
    base = _seed()
    controls = []
    for c in base.controls:
        if c.id == ART:
            c = c.model_copy(update={"params": {**c.params, **params}})
        if c.id in (ART, "SEC-SIG-01"):
            controls.append(c)
    return base.model_copy(update={"controls": controls})


def bundle(entries: list[dict[str, Any]], version: int = 1) -> FeedBundle:
    return FeedBundle.model_validate(
        {
            "bundle_version": version,
            "issued_at": "2026-10-03T12:00:00Z",
            "entries": entries,
            "signature": {"alg": "sha256", "value": "x"},
        }
    )


def opcode_entry(sig_id: str, glob: str) -> dict[str, Any]:
    return {
        "id": sig_id,
        "type": "opcode",
        "pattern": glob,
        "severity": "critical",
        "action": "block",
        "stages": ["artifact_load"],
    }


def art_ctx(
    fixture: str, preset: Preset = Preset.balanced, *, filename: str | None = None, **payload: Any
) -> InspectionContext:
    path = fixture_path(fixture)
    fields: dict[str, Any] = {
        "filename": filename or fixture_filename(fixture),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
        "local_path": str(path),
        "source": "upload",
    }
    fields.update(payload)
    ctx = make_context("x", point=InspectionPoint.ingress, preset=preset)
    return ctx.model_copy(
        update={"point": InspectionPoint.artifact_load, "payload": ArtifactPayload(**fields), "attributes": {}}
    )


def sha(fixture: str) -> str:
    return hashlib.sha256(fixture_path(fixture).read_bytes()).hexdigest()


def engine_for(policy: Policy, store: SignatureStore | None = None) -> Engine:
    deps = ControlDeps(signatures=store) if store is not None else ControlDeps()
    return Engine.build(policy, "t", deps=deps)


async def run(engine: Engine, ctx: InspectionContext):
    decision = await engine.evaluate(ctx)
    return decision, ctx


# ------------------------------------------------------------------ registration and params
def test_control_is_registered_and_runs_in_the_normalise_phase() -> None:
    assert "artifact_scan" in load_builtin_controls()
    cls = registry.get("artifact_scan")
    assert cls.phase == Phase.normalise and cls.cacheable is False
    cfg = next(c for c in _seed().controls if c.id == ART)
    assert cfg.enabled and cfg.stages == [InspectionPoint.artifact_load]
    assert cfg.fail_mode is not None and cfg.fail_mode.value == "closed" and cfg.timeout_ms >= 5000


def test_seed_params_are_default_deny() -> None:
    params = next(c for c in _seed().controls if c.id == ART).params
    assert params["allowed_formats"] == ["safetensors", "gguf"]
    assert params["exceptions"] == []
    assert "meta-llama/*" in params["hf_repo_allowlist"]


def test_params_reject_unknown_and_malformed_values() -> None:
    cls = registry.get("artifact_scan")
    cls.Params.model_validate({})
    with pytest.raises(ValueError):
        cls.Params.model_validate({"bogus": 1})
    with pytest.raises(ValueError):
        cls.Params.model_validate({"exceptions": [{"sha256": "nothex", "reason": "because"}]})
    with pytest.raises(ValueError):
        cls.Params.model_validate({"exceptions": [{"sha256": "a" * 64, "reason": "because", "extra": 1}]})


# ------------------------------------------------------------------ verdicts
@pytest.mark.asyncio
async def test_malicious_pickle_is_a_final_block_with_findings_and_no_raw_values() -> None:
    engine = engine_for(make_policy())
    decision, ctx = await run(engine, art_ctx("pickle_os_system"))
    assert decision.action == Action.block and decision.final and decision.decided_by == ART
    assert decision.decided_phase == Phase.normalise
    assert decision.rule_ids[0] == ART and "ART-PICKLE-01" in decision.rule_ids
    verdict = next(v for v in decision.verdicts if v.control_id == ART)
    assert verdict.final and verdict.action == Action.block
    assert verdict.reason is not None and verdict.reason.startswith("artifact verdict malicious: ART-PICKLE-01")
    assert "GLOBAL os.system via REDUCE" in verdict.reason
    assert {f.entity_type for f in verdict.findings} >= {"ART-PICKLE-01", "ART-FORMAT-01"}
    assert all(f.field == "artifact" and f.start is None and f.value_hash is None for f in verdict.findings)
    assert "LLM03:2025" in verdict.taxonomy.owasp_llm and "AML.T0010" in verdict.taxonomy.atlas
    assert "rogatka-test" not in json.dumps(decision.model_dump(mode="json"))
    # outputs are merged for later phases, and are never serialised
    assert ctx.attributes["pickle_globals"] == ["os.system"]
    assert ctx.attributes["artifact_scan"]["verdict"] == "malicious"
    assert "outputs" not in verdict.model_dump(mode="json")


@pytest.mark.asyncio
async def test_benign_safetensors_and_gguf_are_allowed_with_the_report_attached() -> None:
    engine = engine_for(make_policy())
    for name in ("benign_safetensors", "benign_gguf", "benign_gguf_template", "benign_safetensors_metadata"):
        decision, ctx = await run(engine, art_ctx(name))
        assert decision.action == Action.allow and decision.rule_ids == [], name
        assert ctx.attributes["artifact_scan"]["verdict"] == "safe"
        assert ctx.attributes["pickle_globals"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fixture", "verdict", "rule"),
    [
        ("pickle_benign_blocked", "blocked_format", "ART-FORMAT-01"),
        ("keras_benign", "blocked_format", "ART-FORMAT-01"),
        ("pickle_7z_wrapped", "malicious", "ART-ARCHIVE-01"),
        ("pickle_broken_stream", "malicious", "ART-PICKLE-03"),
        ("keras_lambda", "malicious", "ART-KERAS-01"),
        ("gguf_template_injection", "malicious", "ART-GGUF-02"),
        ("safetensors_offsets_overlap", "malicious", "ART-ST-01"),
        ("gguf_bad_alignment", "malicious", "ART-GGUF-01"),
        ("safetensors_disguised_pickle", "malicious", "ART-FORMAT-02"),
        ("torch_zip_hidden_member", "malicious", "ART-PICKLE-01"),
    ],
)
async def test_every_non_safe_verdict_blocks(fixture: str, verdict: str, rule: str) -> None:
    decision, ctx = await run(engine_for(make_policy()), art_ctx(fixture))
    assert decision.action == Action.block and decision.final
    assert rule in decision.rule_ids and decision.rule_ids[0] == ART
    assert ctx.attributes["artifact_scan"]["verdict"] == verdict


@pytest.mark.asyncio
async def test_suspicious_verdict_blocks_too() -> None:
    # a benign safetensors with an unpinned Hugging Face source is `suspicious`: still default deny
    ctx = art_ctx("benign_safetensors", source="hf:meta-llama/Llama-3@main")
    decision, ctx = await run(engine_for(make_policy()), ctx)
    assert ctx.attributes["artifact_scan"]["verdict"] == "suspicious"
    assert decision.action == Action.block and "ART-HF-01" in decision.rule_ids


@pytest.mark.asyncio
async def test_hf_pinned_allowlisted_source_passes_and_unlisted_repo_does_not() -> None:
    engine = engine_for(make_policy())
    ok = art_ctx("benign_safetensors", source=f"hf:google/gemma-2b@{'a' * 40}")
    assert (await run(engine, ok))[0].action == Action.allow
    bad = art_ctx("benign_safetensors", source=f"hf:someone/else@{'a' * 40}")
    decision, _ = await run(engine, bad)
    assert decision.action == Action.block and "ART-HF-02" in decision.rule_ids
    custom = engine_for(make_policy(hf_repo_allowlist=["someone/*"]))
    assert (await run(custom, art_ctx("benign_safetensors", source=f"hf:someone/else@{'a' * 40}")))[0].action == (
        Action.allow
    )


@pytest.mark.asyncio
async def test_declared_hash_mismatch_blocks() -> None:
    decision, _ = await run(engine_for(make_policy()), art_ctx("benign_safetensors", sha256="0" * 64))
    assert decision.action == Action.block and "ART-HASH-01" in decision.rule_ids


@pytest.mark.asyncio
async def test_missing_or_unreadable_file_fails_closed() -> None:
    engine = engine_for(make_policy())
    for payload in ({"local_path": None}, {"local_path": "/nonexistent/path/model.safetensors"}):
        decision, ctx = await run(engine, art_ctx("benign_safetensors", **payload))
        assert decision.action == Action.block and decision.final and decision.rule_ids[0] == ART
        verdict = next(v for v in decision.verdicts if v.control_id == ART)
        assert verdict.reason is not None and "unavailable" in verdict.reason
        assert "artifact_scan" not in ctx.attributes


@pytest.mark.asyncio
async def test_directory_as_path_fails_closed(tmp_path: Path) -> None:
    decision, _ = await run(engine_for(make_policy()), art_ctx("benign_safetensors", local_path=str(tmp_path)))
    assert decision.action == Action.block and decision.rule_ids[0] == ART


@pytest.mark.asyncio
async def test_control_ignores_other_inspection_points() -> None:
    engine = engine_for(make_policy())
    decision = await engine.evaluate(make_context("hello"))
    assert not any(v.control_id == ART for v in decision.verdicts)


@pytest.mark.asyncio
async def test_monitor_preset_records_would_block_without_enforcing() -> None:
    decision, _ = await run(engine_for(make_policy()), art_ctx("pickle_os_system", Preset.monitor))
    assert decision.action == Action.monitor and decision.would_action == Action.block and not decision.final
    for preset in (Preset.balanced, Preset.strict, Preset.paranoid):
        enforced, _ = await run(engine_for(make_policy()), art_ctx("pickle_os_system", preset))
        assert enforced.action == Action.block and enforced.final


# ------------------------------------------------------------------ exceptions
def exception_for(fixture: str, **kw: Any) -> dict[str, Any]:
    return {"sha256": sha(fixture), "reason": "reviewed by security", **kw}


@pytest.mark.asyncio
async def test_exception_admits_a_benign_pickle_and_torch_zip() -> None:
    for fixture in ("benign_pickle_plain", "benign_torch_zip", "keras_benign"):
        engine = engine_for(make_policy(exceptions=[exception_for(fixture)]))
        decision, ctx = await run(engine, art_ctx(fixture))
        assert decision.action == Action.allow, fixture
        assert ctx.attributes["artifact_scan"]["exception"] == "reviewed by security"
    # without the exception the same file is blocked
    assert (await run(engine_for(make_policy()), art_ctx("benign_torch_zip")))[0].action == Action.block


@pytest.mark.asyncio
async def test_exception_never_admits_a_malicious_pickle() -> None:
    for fixture in ("pickle_os_system", "torch_zip_os_system", "pickle_broken_stream", "pickle_7z_wrapped"):
        engine = engine_for(make_policy(exceptions=[exception_for(fixture)]))
        decision, ctx = await run(engine, art_ctx(fixture))
        assert decision.action == Action.block and decision.final, fixture
        assert ctx.attributes["artifact_scan"]["verdict"] == "malicious"
        assert ctx.attributes["artifact_scan"]["exception"] is None


@pytest.mark.asyncio
async def test_exception_expiry_and_format_scope() -> None:
    yesterday = date.today() - timedelta(days=1)
    expired = engine_for(make_policy(exceptions=[exception_for("benign_torch_zip", expires=yesterday.isoformat())]))
    assert (await run(expired, art_ctx("benign_torch_zip")))[0].action == Action.block
    future = date.today() + timedelta(days=30)
    valid = engine_for(make_policy(exceptions=[exception_for("benign_torch_zip", expires=future.isoformat())]))
    assert (await run(valid, art_ctx("benign_torch_zip")))[0].action == Action.allow
    scoped = engine_for(make_policy(exceptions=[exception_for("benign_torch_zip", formats=["pickle"])]))
    assert (await run(scoped, art_ctx("benign_torch_zip")))[0].action == Action.block


@pytest.mark.asyncio
async def test_widened_allowed_formats() -> None:
    engine = engine_for(make_policy(allowed_formats=["safetensors", "gguf", "keras_v3"]))
    assert (await run(engine, art_ctx("keras_benign")))[0].action == Action.allow
    assert (await run(engine, art_ctx("keras_lambda")))[0].action == Action.block


# ------------------------------------------------------------------ feed opcode signatures
@pytest.mark.asyncio
async def test_feed_opcode_entry_blocks_an_admitted_pickle_via_sec_sig_01() -> None:
    store = SignatureStore()
    store.install(bundle([opcode_entry("SIG-OPCODE-TORCH-REBUILD", "torch._utils._rebuild_tensor*")]), "d")
    policy = make_policy(exceptions=[exception_for("benign_torch_zip")], use_feed_opcodes=False)
    engine = engine_for(policy, store)
    decision, ctx = await run(engine, art_ctx("benign_torch_zip"))
    art = next(v for v in decision.verdicts if v.control_id == ART)
    assert art.action == Action.allow  # the scanner itself admitted it under the exception
    assert ctx.attributes["pickle_globals"] == [
        "collections.OrderedDict",
        "torch._utils._rebuild_tensor_v2",
        "torch.FloatStorage",
    ]
    assert decision.action == Action.block and decision.decided_by == "SEC-SIG-01"
    assert decision.rule_ids == ["SIG-OPCODE-TORCH-REBUILD"] and decision.decided_phase == Phase.deterministic
    # without the feed entry the same file passes
    assert (await run(engine_for(policy, SignatureStore()), art_ctx("benign_torch_zip")))[0].action == Action.allow


@pytest.mark.asyncio
async def test_feed_opcode_entry_is_also_applied_by_the_scanner() -> None:
    store = SignatureStore()
    store.install(bundle([opcode_entry("SIG-OPCODE-TORCH-REBUILD", "torch._utils._rebuild_tensor*")]), "d")
    policy = make_policy(exceptions=[exception_for("benign_torch_zip")])  # use_feed_opcodes defaults to true
    decision, ctx = await run(engine_for(policy, store), art_ctx("benign_torch_zip"))
    assert decision.action == Action.block and decision.decided_by == ART
    assert "SIG-OPCODE-TORCH-REBUILD" in decision.rule_ids
    assert ctx.attributes["artifact_scan"]["verdict"] == "malicious"


@pytest.mark.asyncio
async def test_feed_swap_applies_to_the_next_scan_without_an_engine_rebuild() -> None:
    store = SignatureStore()
    engine = engine_for(make_policy(exceptions=[exception_for("benign_torch_zip")], use_feed_opcodes=False), store)
    assert (await run(engine, art_ctx("benign_torch_zip")))[0].action == Action.allow
    store.install(bundle([opcode_entry("SIG-OPCODE-ORDEREDDICT", "collections.OrderedDict")]), "d")
    decision, _ = await run(engine, art_ctx("benign_torch_zip"))
    assert decision.action == Action.block and decision.rule_ids == ["SIG-OPCODE-ORDEREDDICT"]


@pytest.mark.asyncio
async def test_feed_opcode_glob_matches_dangerous_globals_of_a_malicious_file() -> None:
    store = SignatureStore()
    store.install(bundle([opcode_entry("SIG-OPCODE-POSIX", "posix.*")]), "d")
    decision, ctx = await run(engine_for(make_policy(), store), art_ctx("torch_zip_os_system"))
    assert decision.action == Action.block and {"SIG-OPCODE-POSIX", "ART-PICKLE-01"} <= set(decision.rule_ids)
    assert ctx.attributes["pickle_globals"] == ["posix.system"]
