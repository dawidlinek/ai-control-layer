"""Loading YAML cases and turning them into inspection contexts (format: tests/cases/README.md)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter
from ruamel.yaml import YAML

from acl.contracts.common import InspectionPoint, PolicyMode, Preset
from acl.contracts.inspection import InspectionContext, Payload, SessionState
from acl.testing import make_context, make_principal

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"
DEFAULT_PRESET = "balanced"

# Named session states for `session:` in a case. A case may also give a dict of `SessionState` fields
# (optionally with `preset:` to start from one of these), e.g. `session: {preset: untrusted, step: 3}`.
SESSION_PRESETS: dict[str, dict[str, Any]] = {
    "clean": {},
    "untrusted": {"labels": {"integrity": "untrusted", "taint": ["untrusted"]}},
    "sensitive": {"labels": {"confidentiality": "confidential", "taint": ["sensitive"]}},
    "untrusted_sensitive": {
        "labels": {"integrity": "untrusted", "confidentiality": "confidential", "taint": ["untrusted", "sensitive"]}
    },
    "egress_used": {"labels": {"taint": ["egress_used"]}},
    "downgraded": {"downgraded": True},
    "deep_agent": {"step": 20, "tool_depth": 6},
}


def load_case_file(path: Path) -> list[dict[str, Any]]:
    raw = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{path.name}: expected a YAML list of cases")
    return [{**c, "_file": path.name} for c in raw]


def load_all_cases(directory: Path = CASES_DIR) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
        out.extend(load_case_file(path))
    return out


def case_presets(case: dict[str, Any]) -> list[str]:
    matrix = case.get("matrix")
    return [str(p) for p in matrix] if matrix else [str(case.get("preset", DEFAULT_PRESET))]


def primary_preset(case: dict[str, Any]) -> str:
    """The one cell per case used for per-control statistics (so matrix cells are not counted as independent)."""
    presets = case_presets(case)
    if case.get("matrix"):
        return DEFAULT_PRESET if DEFAULT_PRESET in presets else presets[0]
    return presets[0]


def mode_markers(case: dict[str, Any], mode: str) -> list[str]:
    """Markers for a case cell in run mode `mode`: `skip` (not enabled in this mode) and/or `live`.

    `make test` selects "not live", `make test-live` selects "live". In live mode every enabled case is a
    live run, so it carries `live`; a live-only case also carries it in deterministic mode (where it is skipped).
    """
    modes = case.get("modes", ["deterministic"])
    out = []
    if mode not in modes:
        out.append("skip")
    if mode == "live" or "deterministic" not in modes:
        out.append("live")
    return out


def expected_action(case: dict[str, Any], preset: str) -> str | None:
    if case.get("matrix"):
        return case["matrix"].get(preset)
    return (case.get("expect") or {}).get("action")


def build_session(spec: Any, session_id: str) -> SessionState:
    if spec is None:
        return SessionState(session_id=session_id)
    if isinstance(spec, str):
        spec = {"preset": spec}
    spec = dict(spec)
    base = dict(SESSION_PRESETS[spec.pop("preset")]) if "preset" in spec else {}
    labels = {**base.pop("labels", {}), **spec.pop("labels", {})}
    data: dict[str, Any] = {**base, **spec, "session_id": session_id}
    if labels:
        data["labels"] = labels
    return SessionState.model_validate(data)


FIXTURE_PREFIX = "fixture:"


def resolve_artifact_fixture(data: Any) -> Any:
    """Expand the artifact fixture shorthand of a case input (payload dicts with `kind: artifact` only).

        {kind: artifact, local_path: "fixture:<name>"}                # filename / sha256 / size derived
        {kind: artifact, local_path: "fixture:<name>", filename: auto, sha256: auto, size: auto}

    `local_path: fixture:<name>` becomes the path of the generated fixture (`acl.artifacts.testing.fixture_path`);
    a missing / `auto` `filename` becomes `fixture_filename(name)`, a missing / `auto` `sha256` the file's SHA-256
    and a missing / `auto` `size` the file size. Explicit values are kept (so a case can lie about a hash on purpose).
    The testing module is imported lazily: cases without fixtures never need it. Returns a copy.
    """
    if not isinstance(data, dict) or data.get("kind") != "artifact":
        return data
    local = data.get("local_path")
    if not isinstance(local, str) or not local.startswith(FIXTURE_PREFIX):
        return data
    from acl.artifacts import testing as artifact_testing

    name = local[len(FIXTURE_PREFIX) :]
    path = Path(artifact_testing.fixture_path(name))
    out = dict(data)
    out["local_path"] = str(path)
    if out.get("filename") in (None, "auto"):
        out["filename"] = artifact_testing.fixture_filename(name)
    if out.get("sha256") in (None, "auto"):
        out["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    if out.get("size") in (None, "auto"):
        out["size"] = path.stat().st_size
    return out


def build_context(case: dict[str, Any], preset: str, *, policy_version: str = "test") -> InspectionContext:
    point = InspectionPoint(case.get("point", "ingress"))
    p = dict(case.get("principal") or {})
    principal = make_principal(p.pop("username", "anna"), p.pop("groups", None), **p)
    sid = f"sess-{case['id']}-{preset}"
    kwargs: dict[str, Any] = {
        "point": point,
        "principal": principal,
        "preset": Preset(preset),
        "mode": PolicyMode(case.get("policy_mode", "enforce")),
        "session_id": sid,
        "session": build_session(case.get("session"), sid),
        "policy_version": policy_version,
        "model_requested": case.get("model_requested", "auto"),
    }
    if case.get("user_request"):
        kwargs["user_request"] = case["user_request"]
    data = resolve_artifact_fixture(case["input"])
    try:
        return make_context(data, **kwargs)
    except ValueError:
        # Points without a shorthand (mcp_*, artifact_load): the input must be a full payload dict with `kind`.
        ctx = make_context("x", **{**kwargs, "point": InspectionPoint.ingress})
        payload = TypeAdapter(Payload).validate_python(data)
        return ctx.model_copy(update={"point": point, "payload": payload})
