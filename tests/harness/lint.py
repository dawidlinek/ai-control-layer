"""Case-corpus lint: enforces the paired-case rules of CLAUDE.md rule 7 / concept §16.

  * every control id used by cases has >= 5 `positive` and >= 5 `negative` cases
  * every `negative` has a `pair` key shared with at least one `positive` (its near-miss)
  * structural checks (ids unique, kind/point/preset/action valid, expectation present)

Findings are warnings by default (the corpus is still being written by several tasks). Structural
errors always fail; set `ACL_STRICT_CASE_LINT=1` to make warnings fail too.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from acl.contracts.common import Action, InspectionPoint, Preset

MIN_PER_KIND = 5
ROOT = Path(__file__).resolve().parents[2]
_ACTIONS = {a.value for a in Action}
_PRESETS = {p.value for p in Preset}
_POINTS = {p.value for p in InspectionPoint}


@dataclass
class LintIssue:
    level: str  # error | warn | info
    code: str
    message: str
    control: str | None = None
    case: str | None = None


@dataclass
class LintReport:
    issues: list[LintIssue] = field(default_factory=list)
    per_control: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(self, level: str, code: str, message: str, control: str | None = None, case: str | None = None) -> None:
        self.issues.append(LintIssue(level, code, message, control, case))

    @property
    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[LintIssue]:
        return [i for i in self.issues if i.level == "warn"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "per_control": self.per_control,
            "issues": [asdict(i) for i in self.issues],
        }

    def format(self, limit: int = 20) -> str:
        lines = [f"case lint: {len(self.errors)} errors, {len(self.warnings)} warnings"]
        shown = [i for i in self.issues if i.level in ("error", "warn")]
        for i in shown[:limit]:
            lines.append(f"  [{i.level}] {i.code}: {i.message}")
        if len(shown) > limit:
            lines.append(f"  ... and {len(shown) - limit} more (see reports/case_lint.json)")
        return "\n".join(lines)


def policy_controls(policy_dir: Path | None = None) -> dict[str, bool]:
    """control id -> enabled, read straight from policy/controls.yaml (no engine needed)."""
    path = (policy_dir or ROOT / "policy") / "controls.yaml"
    if not path.exists():
        return {}
    doc = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8")) or {}
    return {c["id"]: bool(c.get("enabled", True)) for c in doc.get("controls", [])}


def lint_cases(
    cases: list[dict[str, Any]], *, known_controls: dict[str, bool] | None = None, min_per_kind: int = MIN_PER_KIND
) -> LintReport:
    rep = LintReport()
    seen: dict[str, str] = {}
    by_control: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for c in cases:
        cid = str(c.get("id", "<missing id>"))
        where = c.get("_file", "?")
        if "id" not in c:
            rep.add("error", "missing-id", f"{where}: case without id")
        elif cid in seen:
            rep.add("error", "duplicate-id", f"{cid} defined in {seen[cid]} and {where}", case=cid)
        else:
            seen[cid] = where
        if c.get("kind") not in ("positive", "negative"):
            rep.add("error", "bad-kind", f"{cid}: kind must be positive|negative, got {c.get('kind')!r}", case=cid)
        if "control" not in c:
            rep.add("error", "missing-control", f"{cid}: no `control` (use `none` for infrastructure cases)", case=cid)
        if "input" not in c:
            rep.add("error", "missing-input", f"{cid}: no `input`", case=cid)
        if c.get("point", "ingress") not in _POINTS:
            rep.add("error", "bad-point", f"{cid}: unknown point {c.get('point')!r}", case=cid)
        matrix = c.get("matrix")
        if matrix:
            for preset, action in matrix.items():
                if preset not in _PRESETS or action not in _ACTIONS:
                    rep.add("error", "bad-matrix", f"{cid}: matrix cell {preset!r}: {action!r} is invalid", case=cid)
        else:
            action = (c.get("expect") or {}).get("action")
            if action not in _ACTIONS:
                rep.add("error", "bad-expect", f"{cid}: expect.action {action!r} is missing/invalid", case=cid)
            if c.get("preset", "balanced") not in _PRESETS:
                rep.add("error", "bad-preset", f"{cid}: unknown preset {c.get('preset')!r}", case=cid)
        by_control[str(c.get("control", "none"))].append(c)

    known = known_controls or {}
    for control, cs in sorted(by_control.items()):
        if control == "none":
            continue
        pos = [c for c in cs if c.get("kind") == "positive"]
        neg = [c for c in cs if c.get("kind") == "negative"]
        pos_pairs = {c["pair"] for c in pos if c.get("pair")}
        paired = 0
        for n in neg:
            if not n.get("pair"):
                rep.add("warn", "unpaired-negative", f"{n.get('id')}: negative has no `pair`", control, n.get("id"))
            elif n["pair"] not in pos_pairs:
                rep.add(
                    "warn",
                    "orphan-negative",
                    f"{n.get('id')}: no positive case with pair {n['pair']!r}",
                    control,
                    n.get("id"),
                )
            else:
                paired += 1
        rep.per_control[control] = {
            "positive": len(pos),
            "negative": len(neg),
            "paired_negatives": paired,
            "matrix_cases": sum(1 for c in cs if c.get("matrix")),
        }
        if len(pos) < min_per_kind:
            rep.add("warn", "few-positives", f"{control}: {len(pos)} positive cases (need >= {min_per_kind})", control)
        if len(neg) < min_per_kind:
            rep.add("warn", "few-negatives", f"{control}: {len(neg)} negative cases (need >= {min_per_kind})", control)
        if not any(c.get("matrix") for c in cs):
            rep.add("info", "no-matrix-case", f"{control}: no strictness-matrix case", control)
        if known and control not in known:
            rep.add("warn", "unknown-control", f"{control}: not defined in policy/controls.yaml", control)

    for cid, enabled in sorted(known.items()):
        if cid not in by_control:
            rep.add("warn" if enabled else "info", "uncovered-control", f"{cid}: no cases (enabled={enabled})", cid)
    return rep
