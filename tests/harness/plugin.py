"""pytest plugin: JUnit + `reports/summary.json` (+ `reports/case_lint.json`) and the end-of-run digest.

Registered from tests/conftest.py. JUnit goes to `reports/junit.xml` unless `--junitxml` is given.
`summary.json` is only written when at least one system case ran (so `pytest gateway/tests` does not clobber it).
Evidence reports written by `make mutation` / `make adaptive` are merged into it (`metrics.merge_evidence`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from harness import runner
from harness.cases import load_all_cases
from harness.host import host_if_started, shutdown_host
from harness.lint import lint_cases, policy_controls
from harness.metrics import build_summary, merge_evidence, validate_summary

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def lint_corpus() -> Any:
    return lint_cases(load_all_cases(), known_controls=policy_controls())


class MetricsPlugin:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.summary: dict[str, Any] | None = None
        self.fallback_reason: str | None = None

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        try:
            host = host_if_started()
            if host is not None and host.mode == "fallback":
                self.fallback_reason = host.fallback_reason
            if runner.RESULTS:
                extra: dict[str, Any] = {"engine_host": host.info() if host else None}
                extra["cases_defined"] = len(load_all_cases())
                extra["partial_run"] = bool(session.config.option.keyword)
                leak = _leak_rates()
                self.summary = build_summary(runner.RESULTS, mode=self.mode, extra=extra, leak_rate_by_channel=leak)
                merge_evidence(self.summary, REPORTS)  # reports/mutation.json, reports/adaptive.json when present
                validate_summary(self.summary)
                write_json(REPORTS / "summary.json", self.summary)
            write_json(REPORTS / "case_lint.json", lint_corpus().to_dict())
        finally:
            shutdown_host()

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        tr = terminalreporter
        if self.fallback_reason:
            tr.section("ACL harness WARNING", yellow=True)
            tr.write_line(f"app lifespan failed, results are from a bare Engine.build(): {self.fallback_reason}")
        if self.summary is None:
            return
        s = self.summary
        tr.section("guard quality (reports/summary.json)")
        ex = s["extra"]
        pr = ex["pass_rate"]
        if pr:
            tr.write_line(
                f"cells {ex['cells_passed']}/{ex['cells_total']} passed "
                f"({pr['value']:.1%}, 95% CI {pr['ci_low']:.1%}-{pr['ci_high']:.1%}); mode={s['mode']}"
            )
        for key in ("asr", "fpr_per_call"):
            r = s[key]
            if r:
                tr.write_line(f"{key}: {r['value']:.1%} (95% CI {r['ci_low']:.1%}-{r['ci_high']:.1%}, n={r['n']})")
        if s["layer_attribution"]:
            tr.write_line(f"layer attribution: {s['layer_attribution']}")
        mut, ada = s.get("mutation"), s.get("adaptive")
        if mut:
            tr.write_line(
                f"mutation (reports/mutation.json): {mut['controls_killed']}/{mut['controls_mutated']} "
                f"enabled controls killed (score {mut['score']:.0%}); survivors: {mut['survivors'] or 'none'}"
            )
        if ada and ada.get("detection"):
            d = ada["detection"]
            tr.write_line(
                f"adaptive (reports/adaptive.json): detection {d['value']:.1%} "
                f"(95% CI {d['ci_low']:.1%}-{d['ci_high']:.1%}) over {d['n']} cells of {ada['variants']} variants"
            )
        if ex["flaky_cases"]:
            tr.write_line(f"flaky (live): {ex['flaky_cases']}")
        rep = lint_corpus()
        tr.write_line(rep.format(limit=8))
        if os.environ.get("ACL_STRICT_CASE_LINT") == "1" and (rep.errors or rep.warnings):
            tr.write_line("ACL_STRICT_CASE_LINT=1: the lint test fails the run", red=True)


def _leak_rates() -> dict[str, float]:
    try:
        from oracle.leak import LEAK_STATS
    except ImportError:  # pragma: no cover
        return {}
    return LEAK_STATS.rates()
