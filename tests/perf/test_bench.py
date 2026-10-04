"""Benchmark smoke test: the harness runs, the output matches the contract, percentiles are sane. No thresholds."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from harness.host import get_host
from perf import bench

from acl.contracts.admin import PerformanceSummary
from acl.contracts.common import InspectionPoint


@pytest.fixture(scope="module")
def result() -> bench.BenchResult:
    return bench.run_bench(iterations=5, warmup=1, http_iterations=3)


def test_nearest_rank_percentiles() -> None:
    values = [float(v) for v in range(1, 101)]
    assert [bench.percentile(values, q) for q in (0.5, 0.95, 0.99, 1.0)] == [50.0, 95.0, 99.0, 100.0]
    assert bench.percentile([7.0], 0.99) == 7.0 and bench.percentile([], 0.5) == 0.0
    assert bench.percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0  # rank ceil(0.5 * 4) = 2, no interpolation
    d = bench.dist([3.0, 1.0, 2.0])
    assert (d["n"], d["p50_ms"], d["p99_ms"], d["max_ms"]) == (3, 2.0, 3.0, 3.0)


def test_summary_validates_against_the_contract_and_percentiles_are_monotonic(result: bench.BenchResult) -> None:
    again = PerformanceSummary.model_validate_json(result.summary.model_dump_json())
    assert again == result.summary
    assert again.stages, "no stage rows"
    for s in again.stages:
        assert s.count > 0
        assert 0 <= s.p50_ms <= s.p95_ms <= s.p99_ms, s
    assert 0.0 <= again.cache_hit_rate <= 1.0 and 0.0 <= again.judge_escalation_rate <= 1.0
    assert again.fail_open_count >= 0


def test_every_enabled_control_at_the_benchmarked_points_appears(result: bench.BenchResult) -> None:
    host = get_host(deterministic=True)
    benchmarked = {w.point.value for w in bench.WORKLOADS}
    expected = {c.id for c in host.engine.policy.controls if c.enabled and benchmarked & {str(s) for s in c.stages}}
    assert expected, "the shipped policy enables no control at the benchmarked points?"
    seen = {s.control_id for s in result.summary.stages if s.control_id}
    assert expected <= seen, f"controls missing from the benchmark: {sorted(expected - seen)}"
    assert {p.value for p in InspectionPoint} >= benchmarked


def test_pseudo_stage_rows_and_phase_rows_are_present(result: bench.BenchResult) -> None:
    phases = {s.phase for s in result.summary.stages if s.control_id is None}
    assert bench.PHASE_TOTAL in phases and bench.PHASE_HTTP in phases and "deterministic" in phases


def test_detail_report_carries_workloads_http_cache_and_machine(result: bench.BenchResult) -> None:
    d = result.detail
    assert set(d["per_workload"]) == {w.name for w in bench.WORKLOADS}
    assert d["iterations"] == 5 and d["warmup"] == 1 and d["http_iterations"] == 3
    assert d["machine"]["cpu_count"] and d["machine"]["python"]
    assert d["http"]["per_workload"] and all(v["n"] == 3 for v in d["http"]["per_workload"].values())
    cache = d["cache"]
    assert cache["unique_payload_hit_rate"] == 0.0, "unique payloads must miss the verdict cache"
    assert cache["repeated_payload_hit_rate"] > 0.0, "identical payloads must hit the cache for cacheable controls"
    assert "nearest-rank" in d["percentile_method"]
    md = result.markdown()
    assert "nearest-rank" in md and "Verdict cache" in md and "End to end" in md
    json.dumps(d)  # serialisable


def test_cli_writes_the_three_reports(tmp_path: Path) -> None:
    out = {k: tmp_path / f"{k}.out" for k in ("json", "detail", "md")}
    argv = ["-n", "3", "--warmup", "1", "--http-iterations", "2"]
    argv += ["--json", str(out["json"]), "--detail-json", str(out["detail"]), "--md", str(out["md"])]
    assert bench.main(argv) == 0
    PerformanceSummary.model_validate_json(out["json"].read_text(encoding="utf-8"))
    assert json.loads(out["detail"].read_text(encoding="utf-8"))["iterations"] == 3
    assert out["md"].read_text(encoding="utf-8").startswith("# Gateway latency benchmark")
