"""Quick check of the mutation machinery (the full run is `make mutation`): a control that is switched off must be
noticed by the cases written for it, and a no-op mutant must not change a single cell."""

from __future__ import annotations

import json

import pytest
from harness.cases import load_all_cases
from mutation.core import (
    cell_id,
    deterministic_cells,
    format_markdown,
    mutant_policy,
    noop_failures,
    run_mutation,
    run_with_policy,
)

from acl.contracts.admin import MutationCoverage

# Cases of these areas are enough to prove the machinery (the full run uses every case).
QUICK_FILES = {"secrets.yaml", "taint_labels.yaml", "pii.yaml"}
QUICK_CONTROLS = ["SEC-SECRET-01", "SEC-TAINT-01", "SEC-PII-01"]


@pytest.fixture(scope="module")
def quick_cells():
    cases = [c for c in load_all_cases() if c["_file"] in QUICK_FILES]
    return deterministic_cells(cases)


def test_switched_off_controls_are_killed_by_their_own_cases(host, quick_cells) -> None:
    run = run_mutation(host, controls=QUICK_CONTROLS, cells=quick_cells)
    assert run.baseline_failing == {}, run.baseline_failing
    by_id = {r.control_id: r for r in run.coverage.results}
    for cid in QUICK_CONTROLS:
        r = by_id[cid]
        assert r.enabled and r.killed and r.failing_cells > 0, f"{cid} survived its own mutant"
        assert run.own[cid] > 0, f"{cid}: no case written for it noticed the mutation"
        assert all(ex.endswith("]") for ex in r.failing_examples)
    assert run.coverage.survivors == [] and run.coverage.score == 1.0
    assert run.coverage.controls_mutated == len(QUICK_CONTROLS)
    # the engine of the session host is restored after every mutant
    assert host.engine.pipeline.controls and "SEC-SECRET-01" in [c.id for c in host.engine.pipeline.controls]


def test_report_is_a_valid_mutation_coverage_and_renders(host, quick_cells) -> None:
    run = run_mutation(host, controls=["SEC-TAINT-01"], cells=quick_cells)
    MutationCoverage.model_validate(json.loads(run.coverage.model_dump_json()))
    md = format_markdown(run)
    assert "SEC-TAINT-01" in md and "KILLED" in md and "Score: 1/1" in md


def test_noop_mutant_kills_nothing(host, quick_cells) -> None:
    assert noop_failures(host, quick_cells) == {}
    policy = host.engine.policy
    assert [c.enabled for c in mutant_policy(policy, None).controls] == [c.enabled for c in policy.controls]


def test_a_mutant_only_fails_cells_of_the_switched_off_control_area(host, quick_cells) -> None:
    """Switching off SEC-SECRET-01 must not break the PII cases (the mutation is surgical)."""
    failing = run_with_policy(host, mutant_policy(host.engine.policy, "SEC-SECRET-01"), quick_cells)
    pii_cells = {cell_id(c, p) for c, p in quick_cells if c["control"] == "SEC-PII-01"}
    assert failing and not (set(failing) & pii_cells)


def test_unknown_control_is_an_error(host, quick_cells) -> None:
    with pytest.raises(KeyError):
        run_mutation(host, controls=["SEC-NOPE-99"], cells=quick_cells)
    with pytest.raises(KeyError):
        mutant_policy(host.engine.policy, "SEC-NOPE-99")
