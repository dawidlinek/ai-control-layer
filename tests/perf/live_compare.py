"""Direct model server versus the same call through the gateway (for the integrator; never run by the test suite).

    LOCAL_LLM_BASE_URL=http://gpu-box:8000/v1 LOCAL_LLM_API_KEY=... LOCAL_GENERAL_MODEL=<model> \\
    ACL_GATEWAY_URL=http://localhost:8080 ACL_API_KEY=<gateway API key> \\
        uv run python tests/perf/live_compare.py [--requests 30] [--stream] [--max-tokens 64]

Sends N identical chat requests to the model server directly (`LOCAL_LLM_BASE_URL`, model `LOCAL_GENERAL_MODEL`) and
through the gateway (`ACL_GATEWAY_URL`, model alias `local`, which the shipped policy maps to the same upstream model),
strictly interleaved (direct, gateway, direct, ... with the order swapped every round so neither side always goes
first). Reports p50 / p95 / p99 (nearest rank) of the total response time, the gateway overhead at each percentile and
the median of the paired per-round differences. With `--stream` it also reports time to first token (first content
delta) and total time of streaming requests.

The prompt is short and benign so the guard path stays on the deterministic tiers plus whichever semantic controls the
deployment enables; set `--prompt` to try others. Prompts are unique per round (a counter is appended) so the gateway's
verdict cache does not flatter the result. Writes `reports/live_compare.json` and `reports/live_compare.md`.
Exits with status 2 and a clear message when a required environment variable is missing.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

REQUIRED_ENV = {
    "LOCAL_LLM_BASE_URL": "OpenAI-compatible base URL of the model server, e.g. http://gpu-box:8000/v1",
    "LOCAL_LLM_API_KEY": "API key of the model server (any non-empty value for servers without auth)",
    "LOCAL_GENERAL_MODEL": "upstream model name the gateway alias `local` maps to",
    "ACL_API_KEY": "personal API key issued by the gateway (admin panel)",
}
DEFAULT_GATEWAY_URL = "http://localhost:8080"
GATEWAY_ALIAS = "local"
DEFAULT_PROMPT = "In two sentences, explain what a hash function is."


def _os_name() -> str:
    """No `platform.platform()`: on Windows it goes through WMI, which can crash the process."""
    if sys.platform == "win32":
        v = sys.getwindowsversion()
        return f"Windows {v.major}.{v.minor}.{v.build}"
    return f"{platform.system()} {platform.release()}"


def missing_env(env: Mapping[str, str]) -> list[str]:
    """Names of the required variables that are unset or empty."""
    return [name for name in REQUIRED_ENV if not env.get(name, "").strip()]


def percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile (rank ceil(q * n) of the ascending sample)."""
    if not sorted_values:
        return 0.0
    return sorted_values[min(len(sorted_values), max(1, math.ceil(q * len(sorted_values)))) - 1]


def dist(values: list[float]) -> dict[str, float | int]:
    s = sorted(values)
    return {
        "n": len(s),
        "p50_ms": round(percentile(s, 0.50), 3),
        "p95_ms": round(percentile(s, 0.95), 3),
        "p99_ms": round(percentile(s, 0.99), 3),
        "mean_ms": round(sum(s) / len(s), 3) if s else 0.0,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Compare a direct model-server call with the same call through the Rogatka gateway.",
        epilog="Required environment: "
        + "; ".join(f"{k} ({v})" for k, v in REQUIRED_ENV.items())
        + f". Optional: ACL_GATEWAY_URL (default {DEFAULT_GATEWAY_URL}).",
    )
    ap.add_argument("--requests", "-n", type=int, default=30, help="measured rounds (one direct + one gateway each)")
    ap.add_argument("--warmup", type=int, default=3, help="warm-up rounds, discarded")
    ap.add_argument("--max-tokens", type=int, default=64, help="max_tokens of every request")
    ap.add_argument("--prompt", default=DEFAULT_PROMPT, help="user prompt (a round counter is appended)")
    ap.add_argument("--stream", action="store_true", help="also measure streaming: time to first token and total")
    ap.add_argument("--timeout", type=float, default=120.0, help="per-request timeout in seconds")
    ap.add_argument("--json", type=Path, default=ROOT / "reports" / "live_compare.json")
    ap.add_argument("--md", type=Path, default=ROOT / "reports" / "live_compare.md")
    args = ap.parse_args(argv)
    if args.requests < 1 or args.warmup < 0:
        ap.error("--requests must be >= 1 and --warmup >= 0")
    return args


@dataclass
class Target:
    name: str
    url: str
    model: str
    headers: dict[str, str]


@dataclass
class Samples:
    total_ms: list[float] = field(default_factory=list)
    ttft_ms: list[float] = field(default_factory=list)
    stream_total_ms: list[float] = field(default_factory=list)
    errors: int = 0


def targets(env: Mapping[str, str]) -> tuple[Target, Target]:
    direct_base = env["LOCAL_LLM_BASE_URL"].rstrip("/")
    gateway_base = env.get("ACL_GATEWAY_URL", DEFAULT_GATEWAY_URL).rstrip("/")
    direct = Target(
        "direct",
        f"{direct_base}/chat/completions",
        env["LOCAL_GENERAL_MODEL"],
        {"Authorization": f"Bearer {env['LOCAL_LLM_API_KEY']}"},
    )
    gateway = Target(
        "gateway",
        f"{gateway_base}/v1/chat/completions",
        GATEWAY_ALIAS,
        {"Authorization": f"Bearer {env['ACL_API_KEY']}"},
    )
    return direct, gateway


def _body(target: Target, prompt: str, max_tokens: int, stream: bool) -> dict[str, Any]:
    return {
        "model": target.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0,
        "stream": stream,
    }


def one_request(client: Any, target: Target, prompt: str, max_tokens: int, stream: bool) -> tuple[float, float | None]:
    """(total ms, time-to-first-content-token ms or None). Raises on a non-200 answer."""
    t0 = time.perf_counter()
    if not stream:
        r = client.post(target.url, json=_body(target, prompt, max_tokens, False), headers=target.headers)
        total = (time.perf_counter() - t0) * 1000
        if r.status_code != 200:
            raise RuntimeError(f"{target.name}: HTTP {r.status_code}")
        return total, None
    first: float | None = None
    with client.stream("POST", target.url, json=_body(target, prompt, max_tokens, True), headers=target.headers) as r:
        if r.status_code != 200:
            raise RuntimeError(f"{target.name}: HTTP {r.status_code}")
        for line in r.iter_lines():
            if first is None and line.startswith("data:") and line[5:].strip() not in ("", "[DONE]"):
                try:
                    delta = json.loads(line[5:])["choices"][0].get("delta", {})
                except (ValueError, KeyError, IndexError):
                    continue
                if delta.get("content"):
                    first = (time.perf_counter() - t0) * 1000
    return (time.perf_counter() - t0) * 1000, first


def run(args: argparse.Namespace, env: Mapping[str, str], client: Any) -> dict[str, Any]:
    direct, gateway = targets(env)
    samples = {direct.name: Samples(), gateway.name: Samples()}
    paired: list[float] = []
    paired_ttft: list[float] = []
    for rnd in range(-args.warmup, args.requests):
        prompt = f"{args.prompt} (round {rnd + args.warmup})"
        order = (direct, gateway) if rnd % 2 == 0 else (gateway, direct)
        got: dict[str, float] = {}
        got_ttft: dict[str, float] = {}
        for t in order:
            try:
                total, _ = one_request(client, t, prompt, args.max_tokens, False)
                got[t.name] = total
                if args.stream:
                    st_total, ttft = one_request(client, t, prompt, args.max_tokens, True)
                    if rnd >= 0 and ttft is not None:
                        samples[t.name].stream_total_ms.append(st_total)
                        samples[t.name].ttft_ms.append(ttft)
                        got_ttft[t.name] = ttft
            except Exception as exc:  # report, do not abort a long run for one failed request
                if rnd >= 0:
                    samples[t.name].errors += 1
                print(f"  round {rnd}: {type(exc).__name__}: {exc}", file=sys.stderr)
        if rnd >= 0:
            for name, total in got.items():
                samples[name].total_ms.append(total)
            if len(got) == 2:
                paired.append(got[gateway.name] - got[direct.name])
            if len(got_ttft) == 2:
                paired_ttft.append(got_ttft[gateway.name] - got_ttft[direct.name])
    out: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "requests": args.requests,
        "warmup": args.warmup,
        "max_tokens": args.max_tokens,
        "streaming_measured": bool(args.stream),
        "gateway_alias": GATEWAY_ALIAS,
        "direct_model": env["LOCAL_GENERAL_MODEL"],
        "percentile_method": "nearest-rank (rank ceil(q*n), no interpolation)",
        "machine": {"python": platform.python_version(), "platform": _os_name(), "cpu_count": os.cpu_count()},
        "interleaved": "direct and gateway alternate within a round; the first target swaps every round",
        "direct": dist(samples["direct"].total_ms),
        "gateway": dist(samples["gateway"].total_ms),
        "errors": {name: s.errors for name, s in samples.items()},
        "overhead_ms": {
            k: round(float(dist(samples["gateway"].total_ms)[k]) - float(dist(samples["direct"].total_ms)[k]), 3)
            for k in ("p50_ms", "p95_ms", "p99_ms", "mean_ms")
        },
        "paired_difference_median_ms": round(statistics.median(paired), 3) if paired else None,
    }
    if args.stream:
        out["stream"] = {
            "direct_ttft": dist(samples["direct"].ttft_ms),
            "gateway_ttft": dist(samples["gateway"].ttft_ms),
            "direct_total": dist(samples["direct"].stream_total_ms),
            "gateway_total": dist(samples["gateway"].stream_total_ms),
            "ttft_paired_difference_median_ms": round(statistics.median(paired_ttft), 3) if paired_ttft else None,
        }
    return out


def render_markdown(r: dict[str, Any]) -> str:
    rows = [("direct", r["direct"]), ("gateway", r["gateway"])]
    out = [
        "# Direct versus gateway latency (live model server)",
        "",
        f"{r['requests']} measured rounds ({r['warmup']} warm-up), max_tokens {r['max_tokens']}, model "
        f"`{r['direct_model']}` direct, alias `{r['gateway_alias']}` via the gateway. {r['generated_at']}.",
        f"{r['interleaved']}. Percentiles: {r['percentile_method']}. Errors: {r['errors']}.",
        "",
        "## Total response time, non-streaming (ms)",
        "",
        "| Path | n | p50 | p95 | p99 | mean |",
        "|---|---|---|---|---|---|",
    ]
    out += [f"| {n} | {d['n']} | {d['p50_ms']} | {d['p95_ms']} | {d['p99_ms']} | {d['mean_ms']} |" for n, d in rows]
    o = r["overhead_ms"]
    out += [
        f"| **gateway overhead** | | {o['p50_ms']} | {o['p95_ms']} | {o['p99_ms']} | {o['mean_ms']} |",
        "",
        f"Median of the paired per-round differences (gateway minus direct): {r['paired_difference_median_ms']} ms.",
    ]
    if "stream" in r:
        s = r["stream"]
        out += [
            "",
            "## Streaming (ms)",
            "",
            "| Path | n | TTFT p50 | TTFT p95 | TTFT p99 | total p50 | total p95 |",
            "|---|---|---|---|---|---|---|",
        ]
        for name in ("direct", "gateway"):
            t, tot = s[f"{name}_ttft"], s[f"{name}_total"]
            ttft = f"{t['p50_ms']} | {t['p95_ms']} | {t['p99_ms']}"
            out.append(f"| {name} | {t['n']} | {ttft} | {tot['p50_ms']} | {tot['p95_ms']} |")
        out += ["", f"TTFT paired difference (median): {s['ttft_paired_difference_median_ms']} ms."]
    out += [
        "",
        "The gateway path includes authentication, ingress inspection, routing, egress inspection and the audit write; "
        "the model time is common to both paths. Streaming holds back a window of output for egress moderation, which "
        "shows up as extra time to first token.",
    ]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = parse_args(argv)
    env = os.environ if env is None else env
    missing = missing_env(env)
    if missing:
        print("live_compare: missing environment variables:", file=sys.stderr)
        for name in missing:
            print(f"  {name}: {REQUIRED_ENV[name]}", file=sys.stderr)
        print("Nothing was sent. See the module docstring for a full example.", file=sys.stderr)
        return 2
    import httpx

    with httpx.Client(timeout=args.timeout) as client:
        result = run(args, env, client)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    args.md.write_text(render_markdown(result), encoding="utf-8", newline="\n")
    print(render_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
