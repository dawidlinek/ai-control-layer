"""Cross-platform task runner (the Makefile delegates here, so Windows works without `make`).

    uv run python scripts/dev.py <task> [args...]

Tasks: env, up, down, logs, ps, demo, seed, test, test-live, e2e, bench, replay, mutation, adaptive, lint, fmt,
contracts
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "--env-file", str(ROOT / ".env"), "-f", str(ROOT / "deploy" / "docker-compose.yml")]
GENERATED_SECRETS = {
    "POSTGRES_PASSWORD",
    "KC_ADMIN_PASSWORD",
    "DEMO_USER_PASSWORD",
    "KC_PANEL_SECRET",
    "PANEL_AUTH_SECRET",
    "KC_LIBRECHAT_SECRET",
    "KC_AGENT_RESEARCH_BOT_SECRET",
    "LIBRECHAT_APP_SECRET",
    "ACL_VALUE_HASH_SALT",
    "ACL_API_KEY_PEPPER",
    "FEED_ADMIN_TOKEN",
    "LOCAL_LLM_API_KEY",
}


def run(cmd: list[str], env: dict[str, str] | None = None) -> int:
    print("+", " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=ROOT, env={**os.environ, **(env or {})})


def task_env(_: list[str]) -> int:
    """Create/complete .env from .env.example; generate any empty secret. Never overwrites set values."""
    example = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    env_path = ROOT / ".env"
    current = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    have = {m.group(1): m.group(2) for line in current if (m := re.match(r"^([A-Z0-9_]+)=(.*)$", line))}
    added = []
    out = list(current)
    for line in example:
        m = re.match(r"^([A-Z0-9_]+)=(.*)$", line)
        if not m:
            continue
        key, default = m.groups()
        if key in GENERATED_SECRETS and not have.get(key):
            value = secrets.token_urlsafe(24)
        elif key in have:
            continue
        else:
            value = default
        if key in have:  # present but empty secret: replace in place
            out = [f"{key}={value}" if ln.startswith(f"{key}=") else ln for ln in out]
        else:
            out.append(f"{key}={value}")
        added.append(key)
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f".env: set {len(added)} keys ({', '.join(added) or 'none'})")
    return 0


def task_up(args: list[str]) -> int:
    if not (ROOT / ".env").exists():
        task_env([])
    return run([*COMPOSE, "up", "-d", "--build", "--wait", *args])


def task_down(args: list[str]) -> int:
    return run([*COMPOSE, "down", *args])


def task_logs(args: list[str]) -> int:
    return run([*COMPOSE, "logs", "--tail", "200", *args])


def task_ps(args: list[str]) -> int:
    return run([*COMPOSE, "ps", *args])


def task_test(args: list[str]) -> int:
    """Deterministic suite; writes reports/{junit.xml,summary.json}.

    Gateway unit tests run in parallel (pytest-xdist); system cases + harness self-tests run in one
    process because the metrics plugin aggregates results in-process. With args, runs a single pytest.
    """
    env = {"ACL_TEST_MODE": "deterministic", "ACL_DETERMINISTIC": "1"}
    marker = ["-m", "not live and not e2e"]
    if args:
        return run(["uv", "run", "pytest", *marker, *args], env=env)
    workers = str(min(4, os.cpu_count() or 1))
    serial = "gateway/tests/test_1b_policy_service.py"  # real file watching + timing budgets: keep off the pool
    rc = run(["uv", "run", "pytest", "gateway/tests", f"--ignore={serial}", *marker, "-n", workers, "-q"], env=env)
    rc |= run(["uv", "run", "pytest", serial, *marker, "-q"], env={**env, "ACL_NO_JUNIT": "1"})
    return rc | run(["uv", "run", "pytest", "tests", *marker, "-q"], env=env)


def task_test_live(args: list[str]) -> int:
    """Live-mode cases against the real model server: every case runs 3x, passes on 2 of 3."""
    return run(
        ["uv", "run", "pytest", "tests", "-m", "live", *args],
        env={"ACL_TEST_MODE": "live", "ACL_DETERMINISTIC": "0"},
    )


def task_e2e(args: list[str]) -> int:
    """tests/e2e against the running docker-compose stack (skips cleanly when it is down)."""
    return run(["uv", "run", "pytest", "tests/e2e", "-m", "e2e", "-rs", *args])


def task_bench(args: list[str]) -> int:
    """Latency benchmark (reports/bench.json, bench_detail.json, bench.md); see tests/perf/bench.py --help."""
    return run(["uv", "run", "python", "tests/perf/bench.py", *args], env={"ACL_DETERMINISTIC": "1"})


def task_replay(args: list[str]) -> int:
    """Offline trace replay through the engine (default: the AgentDojo-style sample); see tests/replay/README.md."""
    return run(["uv", "run", "python", "tests/replay/replay.py", *args], env={"ACL_DETERMINISTIC": "1"})


def task_mutation(args: list[str]) -> int:
    """Mutation testing: switch every enabled control off in turn; the case suite must notice (reports/mutation.*)."""
    return run(["uv", "run", "python", "tests/mutation/run.py", *args], env={"ACL_DETERMINISTIC": "1"})


def task_adaptive(args: list[str]) -> int:
    """Adaptive red-team tier: deterministic attack variants (encodings, Polish, split...) of the negative cases."""
    return run(["uv", "run", "python", "tests/redteam/adaptive/run.py", *args], env={"ACL_DETERMINISTIC": "1"})


def task_lint(_: list[str]) -> int:
    rc = run(["uv", "run", "ruff", "check", "."])
    rc |= run(["uv", "run", "ruff", "format", "--check", "gateway", "tests", "scripts", "feed-server"])
    rc |= run(["uv", "run", "python", "-m", "acl.contracts.export", "--check"])
    return rc


def task_fmt(_: list[str]) -> int:
    run(["uv", "run", "ruff", "check", "--fix", "."])
    return run(["uv", "run", "ruff", "format", "gateway", "tests", "scripts", "feed-server"])


def task_contracts(_: list[str]) -> int:
    return run(["uv", "run", "python", "-m", "acl.contracts.export"])


def task_seed(_: list[str]) -> int:
    print("seed: nothing to seed yet (Phase 1+)")
    return 0


def task_demo(args: list[str]) -> int:
    return task_up(args) or task_seed([])


TASKS = {name[5:].replace("_", "-"): fn for name, fn in globals().items() if name.startswith("task_")}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in TASKS:
        print(__doc__)
        return 2
    return TASKS[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
