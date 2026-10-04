"""Mutation testing machinery: switch one control off, run every YAML case cell, count the cells that notice.

    "switch off each control -> a test must fail"  (concept §16, the 15 % self-testing criterion)

A *mutant* is the live policy with one enabled control set to `enabled: false`. The policy is edited in
process (`model_copy`, no validation, so org locks and `locked: true` do not get in the way: this is a test
tool, the gateway itself never relaxes a locked control). The mutant engine is built through the same app
wiring as the real one (`app.state.build_engine`, so vault / signature store / session services are the real
ones), swapped into the session host for the duration of the run and restored afterwards.

Scoring:
  * cells = every deterministic-mode case cell (all presets of matrix cases), run exactly like the pytest
    collector does (`CaseRunner(...).run`), but with `record=False` so reports are not polluted;
  * the baseline (unmodified policy) runs first; cells that already fail there are excluded from every mutant
    and reported (a cell that fails regardless of the mutation cannot prove anything about a control);
  * a control is KILLED when at least one non-baseline-failing cell fails with it switched off; a SURVIVOR is
    a control nobody tests (or one whose cases are not sensitive to it): the suite must gain cases for it;
  * an evaluation that raises counts as a failing cell, flagged `ERROR` in the examples (a crash is a weaker
    kill than an expectation mismatch; the markdown report lists the count).

The result is `acl.contracts.admin.MutationCoverage` (`reports/mutation.json`).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from harness.cases import case_presets, load_all_cases, mode_markers
from harness.host import EngineHost
from harness.runner import CaseRunner

from acl.contracts.admin import MutantResult, MutationCoverage
from acl.engine.engine import Engine
from acl.policy.models import Policy

SUITE = "system-cases"
MAX_EXAMPLES = 5

Cell = tuple[dict[str, Any], str]  # (case, preset)


def cell_id(case: dict[str, Any], preset: str) -> str:
    return f"{case['id']}[{preset}]"


def deterministic_cells(cases: Iterable[dict[str, Any]] | None = None) -> list[Cell]:
    """Every deterministic-mode cell (a matrix case contributes one cell per preset)."""
    cells: list[Cell] = []
    for case in load_all_cases() if cases is None else cases:
        if "skip" in mode_markers(case, "deterministic"):
            continue
        cells.extend((case, preset) for preset in case_presets(case))
    return cells


def enabled_control_ids(policy: Policy) -> list[str]:
    return [c.id for c in policy.controls if c.enabled]


def mutant_policy(policy: Policy, control_id: str | None) -> Policy:
    """The policy with `control_id` switched off (None = unchanged copy: the no-op mutant)."""
    if control_id is None:
        return policy.model_copy()
    if control_id not in {c.id for c in policy.controls}:
        raise KeyError(f"unknown control {control_id!r}")
    controls = [c.model_copy(update={"enabled": False}) if c.id == control_id else c for c in policy.controls]
    return policy.model_copy(update={"controls": controls})


def _build(host: EngineHost, policy: Policy, version: str) -> Engine:
    if host.app is not None:
        return host.app.state.build_engine(policy, version)
    return Engine.build(policy, version)


def _swap(host: EngineHost, engine: Engine) -> Engine:
    """Install `engine` as the host's current engine, returning the previous one."""
    if host.app is not None:
        old, host.app.state.engine = host.app.state.engine, engine
    else:
        old, host._fallback_engine = host._fallback_engine, engine  # fallback mode: bare engine
    return old


def run_cells(host: EngineHost, cells: list[Cell], *, policy_version: str = "mutation") -> dict[str, list[str]]:
    """Run each cell against the host's CURRENT engine; returns `{cell id: failures}` for FAILING cells only."""
    runner = CaseRunner(host.evaluate, record=False, policy_version=policy_version)
    failing: dict[str, list[str]] = {}
    for case, preset in cells:
        try:
            result = runner.run(case, preset)
        except Exception as exc:  # a crashing evaluation is a failing cell, never a silent pass
            failing[cell_id(case, preset)] = [f"ERROR {type(exc).__name__}: {str(exc)[:200]}"]
            continue
        if not result.passed:
            failing[cell_id(case, preset)] = list(result.outcome.failures)
    return failing


def run_with_policy(
    host: EngineHost, policy: Policy, cells: list[Cell], *, version: str | None = None
) -> dict[str, list[str]]:
    """Build an engine from `policy`, swap it into the host, run the cells, restore the original engine."""
    base = host.engine
    new = host.run(_build_on_loop(host, policy, version or f"{base.policy_version}+mutant"))
    old = _swap(host, new)
    try:
        return run_cells(host, cells)
    finally:
        _swap(host, old)
        host.run(new.aclose())


async def _build_on_loop(host: EngineHost, policy: Policy, version: str) -> Engine:
    """Controls may create loop-bound objects in `__init__`: build on the host loop, like the app does."""
    return _build(host, policy, version)


@dataclass
class MutationRun:
    coverage: MutationCoverage
    baseline_failing: dict[str, list[str]]
    failures: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # control -> cell -> failures
    errors: dict[str, int] = field(default_factory=dict)  # control -> failing cells that were crashes
    own: dict[str, int] = field(default_factory=dict)  # control -> failing cells of cases written for that control
    cells: int = 0
    seconds: float = 0.0


def run_mutation(
    host: EngineHost,
    *,
    controls: list[str] | None = None,
    cells: list[Cell] | None = None,
    progress: Callable[[str], None] | None = None,
) -> MutationRun:
    """Mutate every enabled control (or just `controls`) and score the suite. See the module docstring."""
    say = progress or (lambda _msg: None)
    t0 = time.perf_counter()
    cells = deterministic_cells() if cells is None else cells
    policy = host.engine.policy
    all_controls = [(c.id, c.enabled) for c in policy.controls]
    selected = [(cid, en) for cid, en in all_controls if controls is None or cid in controls]
    unknown = sorted(set(controls or []) - {cid for cid, _ in all_controls})
    if unknown:
        raise KeyError(f"unknown control(s): {', '.join(unknown)}")

    say(f"baseline: {len(cells)} cells ...")
    baseline = run_cells(host, cells)
    say(f"baseline: {len(baseline)} failing cell(s) (excluded from every mutant)")
    live_cells = [c for c in cells if cell_id(*c) not in baseline]

    owner = {cell_id(case, preset): str(case.get("control", "none")) for case, preset in cells}
    results: list[MutantResult] = []
    failures: dict[str, dict[str, list[str]]] = {}
    errors: dict[str, int] = {}
    own: dict[str, int] = {}
    for i, (cid, enabled) in enumerate(selected, 1):
        if not enabled:
            results.append(MutantResult(control_id=cid, enabled=False, killed=False))
            say(f"[{i}/{len(selected)}] {cid}: disabled in policy, not scored")
            continue
        t1 = time.perf_counter()
        failing = run_with_policy(host, mutant_policy(policy, cid), live_cells)
        failures[cid] = failing
        errors[cid] = sum(1 for f in failing.values() if f and f[0].startswith("ERROR"))
        own[cid] = sum(1 for key in failing if owner.get(key) == cid)
        # examples: the control's own cases first, then the collateral ones
        ordered = sorted(failing, key=lambda key: owner.get(key) != cid)
        results.append(
            MutantResult(
                control_id=cid,
                enabled=True,
                killed=bool(failing),
                failing_cells=len(failing),
                failing_examples=ordered[:MAX_EXAMPLES],
            )
        )
        verdict = "killed" if failing else "SURVIVED"
        say(f"[{i}/{len(selected)}] {cid}: {verdict} ({len(failing)} failing cells, {time.perf_counter() - t1:.1f}s)")

    scored = [r for r in results if r.enabled]
    killed = sum(r.killed for r in scored)
    coverage = MutationCoverage(
        generated_at=datetime.now(UTC),
        suite=SUITE,
        controls_mutated=len(scored),
        controls_killed=killed,
        score=round(killed / len(scored), 6) if scored else 1.0,
        survivors=[r.control_id for r in scored if not r.killed],
        results=results,
    )
    return MutationRun(
        coverage=coverage,
        baseline_failing=baseline,
        failures=failures,
        errors=errors,
        own=own,
        cells=len(cells),
        seconds=time.perf_counter() - t0,
    )


def noop_failures(host: EngineHost, cells: list[Cell]) -> dict[str, list[str]]:
    """Failing cells of the no-op mutant (policy rebuilt unchanged) that pass on the baseline: must be empty."""
    baseline = run_cells(host, cells)
    noop = run_with_policy(host, mutant_policy(host.engine.policy, None), cells)
    return {k: v for k, v in noop.items() if k not in baseline}


def format_markdown(run: MutationRun) -> str:
    cov = run.coverage
    lines = [
        "# Mutation testing report",
        "",
        f"Generated {cov.generated_at.isoformat(timespec='seconds')}; suite `{cov.suite}`; {run.cells} case cells "
        f"per mutant; {run.seconds:.0f} s.",
        "",
        "Every enabled control is switched off in turn (policy edited in process, org locks bypassed by this tool "
        "only) and the whole deterministic suite is re-run. A control is **killed** when at least one cell fails "
        'without it; a **survivor** is a control no case is sensitive to. "Own cases" counts failing cells of cases '
        "written for that control (`control:` key); a kill with zero own cases is flagged as weak.",
        "",
        f"**Score: {cov.controls_killed}/{cov.controls_mutated} enabled controls killed "
        f"({cov.score:.0%}).** Survivors: {', '.join(cov.survivors) or 'none'}.",
        "",
        "| control | failing cells | of which own cases | example failing cells | verdict |",
        "|---|---:|---:|---|---|",
    ]
    for r in cov.results:
        if not r.enabled:
            lines.append(f"| {r.control_id} | - | - | - | disabled in policy (not scored) |")
            continue
        ex = ", ".join(f"`{e}`" for e in r.failing_examples) or "-"
        err = run.errors.get(r.control_id, 0)
        note = "KILLED" if r.killed else "**SURVIVED**"
        if err:
            note += f" ({err} of the failing cells are crashes, not expectation mismatches)"
        own = run.own.get(r.control_id, 0)
        if r.killed and own == 0:
            note += " (weak: only other controls' cases notice it)"
        lines.append(f"| {r.control_id} | {r.failing_cells} | {own} | {ex} | {note} |")
    lines += ["", f"Baseline failing cells (excluded from all mutants): {len(run.baseline_failing)}"]
    for key, fails in sorted(run.baseline_failing.items()):
        lines.append(f"- `{key}`: {fails[0][:160] if fails else ''}")
    return "\n".join(lines) + "\n"


__all__ = [
    "Cell",
    "MutationRun",
    "cell_id",
    "deterministic_cells",
    "enabled_control_ids",
    "format_markdown",
    "mutant_policy",
    "noop_failures",
    "run_cells",
    "run_mutation",
    "run_with_policy",
]
