"""Mutation testing CLI: switch every enabled control off in turn and check that the case suite notices.

    uv run python tests/mutation/run.py [--controls SEC-PII-01,SEC-TAINT-01] [--json reports/mutation.json]

Writes `reports/mutation.json` (exactly `acl.contracts.admin.MutationCoverage`) and `reports/mutation.md`, re-merges
the result into an existing `reports/summary.json`, and exits 1 when any enabled control survives. See
`tests/mutation/core.py` for the method and its limits. One session host (the real app lifespan) serves every
mutant, nothing is restarted between them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
ROOT = TESTS.parent
if str(TESTS) not in sys.path:  # `harness.*`, `mutation.*` live under tests/ (it is not a package)
    sys.path.insert(0, str(TESTS))
os.environ.setdefault("ACL_DETERMINISTIC", "1")
os.environ.setdefault("ACL_TEST_MODE", "deterministic")

DEFAULT_JSON = ROOT / "reports" / "mutation.json"


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--controls", help="comma-separated control ids to mutate (default: every enabled control)")
    ap.add_argument("--json", type=Path, default=DEFAULT_JSON, help="output path of the MutationCoverage JSON")
    args = ap.parse_args(argv)

    from harness.host import get_host, shutdown_host
    from harness.metrics import remerge_summary_file
    from mutation.core import format_markdown, run_mutation

    controls = [c.strip() for c in args.controls.split(",") if c.strip()] if args.controls else None
    host = get_host(deterministic=True)
    try:
        if host.mode != "app":
            print(f"WARNING: app lifespan failed, running against a bare Engine: {host.fallback_reason}", flush=True)
        run = run_mutation(host, controls=controls, progress=lambda m: print(m, flush=True))
    finally:
        shutdown_host()

    out_json = args.json
    out_md = out_json.with_suffix(".md")
    write_text(out_json, json.dumps(json.loads(run.coverage.model_dump_json()), indent=2) + "\n")
    write_text(out_md, format_markdown(run))
    if out_json.parent == DEFAULT_JSON.parent and remerge_summary_file(out_json.parent):
        print(f"merged into {out_json.parent / 'summary.json'}")

    cov = run.coverage
    print(f"\nmutation score: {cov.controls_killed}/{cov.controls_mutated} enabled controls killed ({cov.score:.0%})")
    print(f"survivors: {', '.join(cov.survivors) or 'none'}")
    print(f"wrote {out_json} and {out_md}")
    return 1 if cov.survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
