"""Adaptive red-team tier CLI: deterministic attack variants of the negative cases, evaluated against the real app.

    uv run python tests/redteam/adaptive/run.py [--techniques base64,polish] [--controls SEC-PII-01] [--max-cases N]

Writes `reports/adaptive.json` (exactly `acl.contracts.admin.AdaptiveTierSummary`), `reports/adaptive.md` (tables and
an honest "what is not caught" section) and `reports/adaptive_detail.json` (every missed cell, skipped cases), then
re-merges the summary into an existing `reports/summary.json`. The exit code is 0 whatever the detection rate is:
this tier measures, it does not gate. `--min-detection 0.9` turns it into a gate when wanted. See
`tests/redteam/adaptive/evaluation.py` for the method and its limits.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2]
ROOT = TESTS.parent
if str(TESTS) not in sys.path:  # `harness.*`, `redteam.*` live under tests/ (it is not a package)
    sys.path.insert(0, str(TESTS))
os.environ.setdefault("ACL_DETERMINISTIC", "1")
os.environ.setdefault("ACL_TEST_MODE", "deterministic")

REPORTS = ROOT / "reports"


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--techniques", help="comma-separated technique names (default: all that apply)")
    ap.add_argument("--controls", help="only cases of these controls")
    ap.add_argument("--max-cases", type=int, help="stop after N usable cases (smoke runs)")
    ap.add_argument("--min-detection", type=float, help="exit 1 when overall detection is below this rate")
    ap.add_argument("--out-dir", type=Path, default=REPORTS, help="where adaptive.json / adaptive.md go")
    args = ap.parse_args(argv)

    from harness.cases import load_all_cases
    from harness.host import get_host, shutdown_host
    from harness.metrics import remerge_summary_file
    from redteam.adaptive.evaluation import TECHNIQUES, format_markdown, run_adaptive

    techniques = tuple(t.strip() for t in args.techniques.split(",") if t.strip()) if args.techniques else None
    unknown = sorted(set(techniques or ()) - set(TECHNIQUES))
    if unknown:
        ap.error(f"unknown technique(s): {', '.join(unknown)} (known: {', '.join(TECHNIQUES)})")
    cases = load_all_cases()
    if args.controls:
        wanted = {c.strip() for c in args.controls.split(",")}
        cases = [c for c in cases if c.get("control") in wanted]

    host = get_host(deterministic=True)
    try:
        if host.mode != "app":
            print(f"WARNING: app lifespan failed, running against a bare Engine: {host.fallback_reason}", flush=True)
        run = run_adaptive(
            host, cases=cases, techniques=techniques, max_cases=args.max_cases, progress=lambda m: print(m, flush=True)
        )
    finally:
        shutdown_host()

    out = args.out_dir
    write_text(out / "adaptive.json", json.dumps(json.loads(run.summary.model_dump_json()), indent=2) + "\n")
    write_text(out / "adaptive.md", format_markdown(run))
    write_text(out / "adaptive_detail.json", json.dumps(run.detail, indent=2, ensure_ascii=False) + "\n")
    if out == REPORTS and remerge_summary_file(REPORTS):
        print(f"merged into {REPORTS / 'summary.json'}")

    det = run.summary.detection
    if det is None:
        print("no variants evaluated")
        return 1
    print(
        f"\nadaptive detection: {det.value:.1%} (95% CI {det.ci_low:.1%}-{det.ci_high:.1%}) over {det.n} cells, "
        f"{run.summary.variants} unique variants, {run.cases_used} cases"
    )
    for name, r in run.summary.by_technique.items():
        print(f"  {name:11s} {r.value:6.1%}  n={r.n}")
    print(f"wrote {out / 'adaptive.json'}, {out / 'adaptive.md'}")
    if args.min_detection is not None and det.value < args.min_detection:
        print(f"detection {det.value:.1%} < required {args.min_detection:.1%}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
