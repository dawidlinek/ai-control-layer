"""Adaptive tier: generate deterministic variants of the negative (attack) cases and measure what still gets caught.

Method
------
1. Eligible cases: `kind: negative`, not monitor-only, with a text payload (see `slots.py` for the skip reasons).
2. Per case and preset in `PRESETS` (balanced / strict / paranoid; monitor is excluded because it never enforces) the
   ORIGINAL input is evaluated; the preset counts for the case only where the system intervenes on the original
   (a variant is not expected to be caught where the original attack is not).
3. Per text slot a *neutral probe* replaces just that slot by a harmless filler. A slot is **causal** at a preset
   when the original is intervened on and the probe is not. Slots that never are cause nothing: when no slot of a
   case is causal at any preset, the case is skipped (`independent_of_text`): the system's decision comes from
   the tool tier, the group, session labels, ... and obfuscating text could not tell us anything.
4. Every technique that applies to the slot's role generates its forms (`techniques.py`); each variant changes one
   causal slot, and is evaluated at every preset where that slot is causal.
5. Detection = the decision's EFFECTIVE action (`would_action` in monitor mode, else `action`) is stronger than
   allow / monitor, i.e. the system intervened. A variant is a "hit" per (variant, preset) cell.

The numbers are properties of THIS corpus and THIS policy: the corpus is small (a few dozen distinct attacks), the
variants of one case are strongly correlated and the three presets of one variant even more so, so the Wilson
intervals are optimistic about generalisation. They bound sampling noise on these cells, nothing more. The report
says so, lists what is missed (never hidden) and keeps the unique-variant count next to the cell count.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from harness.cases import load_all_cases
from harness.host import EngineHost
from harness.runner import CaseRunner, RunOutcome
from harness.stats import rate_with_ci
from redteam.adaptive.slots import (
    SKIP_POINTS,
    Slot,
    apply_messages,
    extract_slots,
    neutralise,
    replace_slot,
)
from redteam.adaptive.techniques import TECHNIQUES, Form, generate

from acl.contracts.admin import AdaptiveTierSummary

PRESETS = ("balanced", "strict", "paranoid")
MAX_FORMS_PER_TECHNIQUE = 6


@dataclass
class Variant:
    variant_id: str
    case_id: str
    control: str
    technique: str
    form: str
    slot: str
    role: str
    input: Any
    presets: tuple[str, ...]  # presets at which the slot is causal
    translated: bool | None = None


@dataclass
class Cell:
    variant: Variant
    preset: str
    detected: bool
    phase: str  # decided_phase of an intervention, "missed" otherwise
    error: str | None = None
    action: str = "allow"  # effective action
    owner_fired: bool = False  # the control the case was written for took part in the intervention


@dataclass
class AdaptiveRun:
    summary: AdaptiveTierSummary
    cells: list[Cell]
    variants: list[Variant]
    skipped: dict[str, list[str]]  # reason -> case ids
    cases_used: int
    seconds: float
    detail: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- generation


def static_skip_reason(case: dict[str, Any]) -> str | None:
    if case.get("kind") != "negative":
        return "not_negative"
    if case.get("preset") == "monitor" or case.get("policy_mode") == "monitor":
        return "monitor_case"
    data = case.get("input")
    if case.get("point", "ingress") in SKIP_POINTS or (
        isinstance(data, dict) and data.get("kind") in ("mcp", "artifact")
    ):
        return "non_text_payload"
    if case.get("control") == "SEC-HYG-01":
        text = data if isinstance(data, str) else ""
        if "canary" not in text.lower():
            return "format_property"
    return None


def _intervened(
    runner: CaseRunner, case: dict[str, Any], data: Any, preset: str
) -> tuple[RunOutcome | None, str | None]:
    probe = {**case, "input": data, "matrix": None, "expect": {"action": "allow"}}
    try:
        return runner.run_once(probe, preset), None
    except Exception as exc:  # an input the payload models reject: the variant is simply not evaluable
        return None, f"{type(exc).__name__}: {str(exc)[:120]}"


def analyse_case(
    runner: CaseRunner, case: dict[str, Any], presets: tuple[str, ...]
) -> tuple[list[tuple[Slot, tuple[str, ...]]], str | None]:
    """(causal slots with their causal presets, skip reason)."""
    base = case["input"]
    slots = extract_slots(base)
    if not slots:
        return [], "no_text_slot"
    original: dict[str, bool] = {}
    for p in presets:
        out, err = _intervened(runner, case, base, p)
        original[p] = bool(out and out.intervened) and err is None
    live = [p for p in presets if original[p]]
    if not live:
        return [], "baseline_not_intervened"
    causal: list[tuple[Slot, tuple[str, ...]]] = []
    for slot in slots:
        neutral = neutralise(base, slot)
        flipped: list[str] = []
        for p in live:
            out, err = _intervened(runner, case, neutral, p)
            if err is None and out is not None and not out.intervened:
                flipped.append(p)
        if flipped:
            causal.append((slot, tuple(flipped)))
    if not causal:
        return [], "independent_of_text"
    return causal, None


def variants_for(
    case: dict[str, Any], slot: Slot, presets: tuple[str, ...], *, techniques: tuple[str, ...] | None = None
) -> list[Variant]:
    out: list[Variant] = []
    point = str(case.get("point", "ingress"))
    forms_by_tech = generate(slot.value, slot.role, key=f"{case['id']}:{slot.key}", techniques=techniques)
    for tech, forms in forms_by_tech.items():
        for form in forms[:MAX_FORMS_PER_TECHNIQUE]:
            data = _apply(case["input"], slot, form, point)
            if data is None:
                continue
            out.append(
                Variant(
                    variant_id=f"{case['id']}#{slot.key}:{tech}.{form.name}",
                    case_id=case["id"],
                    control=str(case.get("control", "none")),
                    technique=tech,
                    form=form.name,
                    slot=slot.key,
                    role=slot.role,
                    input=data,
                    presets=presets,
                    translated=form.translated,
                )
            )
    return out


def _apply(base: Any, slot: Slot, form: Form, point: str) -> Any | None:
    if form.messages:
        return apply_messages(base, slot, form.messages, point=point)
    return replace_slot(base, slot, form.text)


# ---------------------------------------------------------------- evaluation + aggregation


def run_adaptive(
    host: EngineHost,
    *,
    cases: list[dict[str, Any]] | None = None,
    techniques: tuple[str, ...] | None = None,
    presets: tuple[str, ...] = PRESETS,
    max_cases: int | None = None,
    progress: Callable[[str], None] | None = None,
) -> AdaptiveRun:
    say = progress or (lambda _m: None)
    t0 = time.perf_counter()
    runner = CaseRunner(host.evaluate, record=False, policy_version="adaptive")
    corpus = load_all_cases() if cases is None else cases
    skipped: dict[str, list[str]] = defaultdict(list)
    variants: list[Variant] = []
    used = 0
    for case in corpus:
        reason = static_skip_reason(case)
        if reason:
            if reason != "not_negative":
                skipped[reason].append(case["id"])
            continue
        if max_cases is not None and used >= max_cases:
            break
        causal, reason = analyse_case(runner, case, presets)
        if reason:
            skipped[reason].append(case["id"])
            continue
        used += 1
        for slot, causal_presets in causal:
            variants.extend(variants_for(case, slot, causal_presets, techniques=techniques))
    say(
        f"{used} cases usable, {len(variants)} variants generated, skipped: { {k: len(v) for k, v in skipped.items()} }"
    )

    by_id = {c["id"]: c for c in corpus}
    cells: list[Cell] = []
    for i, v in enumerate(variants, 1):
        case = by_id[v.case_id]
        for preset in v.presets:
            out, err = _intervened(runner, case, v.input, preset)
            if err is not None or out is None:
                cells.append(Cell(v, preset, False, "error", err))
                continue
            phase = (out.decided_phase or "unknown") if out.intervened else "missed"
            cells.append(
                Cell(v, preset, out.intervened, phase, None, out.effective_action, v.control in out.fired_controls)
            )
        if i % 500 == 0:
            say(f"  evaluated {i}/{len(variants)} variants")
    scored = [c for c in cells if c.error is None]
    summary = build_summary(scored, variants=len({c.variant.variant_id for c in scored}))
    return AdaptiveRun(
        summary=summary,
        cells=cells,
        variants=variants,
        skipped=dict(skipped),
        cases_used=used,
        seconds=time.perf_counter() - t0,
        detail=_detail(cells, variants, skipped),
    )


def _rate(cells: list[Cell]) -> dict[str, float | int] | None:
    return rate_with_ci(sum(c.detected for c in cells), len(cells))


def build_summary(cells: list[Cell], *, variants: int) -> AdaptiveTierSummary:
    def group(key: Callable[[Cell], str]) -> dict[str, dict[str, float | int] | None]:
        buckets: dict[str, list[Cell]] = defaultdict(list)
        for c in cells:
            buckets[key(c)].append(c)
        return {k: _rate(v) for k, v in sorted(buckets.items())}

    layers = Counter(c.phase for c in cells)
    return AdaptiveTierSummary.model_validate(
        {
            "generated_at": datetime.now(UTC),
            "variants": variants,
            "detection": _rate(cells),
            "by_technique": {k: v for k, v in group(lambda c: c.variant.technique).items() if v},
            "by_control": {k: v for k, v in group(lambda c: c.variant.control).items() if v},
            "by_preset": {k: v for k, v in group(lambda c: c.preset).items() if v},
            "layer_attribution": dict(sorted(layers.items())),
        }
    )


def _detail(cells: list[Cell], variants: list[Variant], skipped: dict[str, list[str]]) -> dict[str, Any]:
    scored = [c for c in cells if c.error is None]
    missed = [c for c in scored if not c.detected]
    hits = [c for c in scored if c.detected]
    pl = [c for c in scored if c.variant.technique == "polish"]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "cells": len(scored),
        "errors": [{"variant": c.variant.variant_id, "preset": c.preset, "error": c.error} for c in cells if c.error],
        "unique_variants": len({c.variant.variant_id for c in scored}),
        "skipped": {k: sorted(v) for k, v in skipped.items()},
        "missed": [
            {
                "variant": c.variant.variant_id,
                "case": c.variant.case_id,
                "control": c.variant.control,
                "technique": c.variant.technique,
                "form": c.variant.form,
                "preset": c.preset,
            }
            for c in missed
        ],
        "detected_by_owner_control": _rate_of(hits, lambda c: c.owner_fired),
        "detected_as_require_approval": _rate_of(hits, lambda c: c.action == "require_approval"),
        "action_mix": {
            t: dict(sorted(Counter(c.action for c in hits if c.variant.technique == t).items()))
            for t in sorted({c.variant.technique for c in scored})
        },
        "polish": {
            "translated": _rate([c for c in pl if c.variant.translated]),
            "framing_only": _rate([c for c in pl if c.variant.translated is False]),
        },
        "by_technique_form": {
            k: _rate(v) for k, v in sorted(_bucket(scored, lambda c: f"{c.variant.technique}.{c.variant.form}").items())
        },
        "by_technique_control_missed": [
            {"technique": t, "control": ctl, "missed": n, "cells": tot}
            for (t, ctl), (n, tot) in sorted(_combos(scored).items(), key=lambda kv: (-kv[1][0], kv[0]))
            if n
        ],
    }


def _rate_of(cells: list[Cell], pred: Callable[[Cell], bool]) -> dict[str, float | int] | None:
    return rate_with_ci(sum(pred(c) for c in cells), len(cells))


def _bucket(cells: list[Cell], key: Callable[[Cell], str]) -> dict[str, list[Cell]]:
    out: dict[str, list[Cell]] = defaultdict(list)
    for c in cells:
        out[key(c)].append(c)
    return out


def _combos(cells: list[Cell]) -> dict[tuple[str, str], tuple[int, int]]:
    out: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for c in cells:
        out[(c.variant.technique, c.variant.control)][1] += 1
        out[(c.variant.technique, c.variant.control)][0] += not c.detected
    return {k: (v[0], v[1]) for k, v in out.items()}


# ---------------------------------------------------------------- markdown

HYPOTHESES = {
    "homoglyph": "look-alike letters inside a keyword or value are not folded back by normalisation (hypothesis)",
    "zero_width": "zero-width characters inside a token are not removed before matching (hypothesis)",
    "polish": "context keywords (NIP, tel., ...) or phrases are not matched in Polish / translated form (hypothesis)",
    "paraphrase": "the detector relies on the original context words around the value (hypothesis)",
    "split": "the value is no longer contiguous: line / separator / message boundaries break the match (hypothesis)",
    "base64": "the encoded blob is not decoded, or the decoded text is not re-inspected (hypothesis)",
    "hex": "the encoded blob is not decoded, or the decoded text is not re-inspected (hypothesis)",
    "url": "percent-encoding is not decoded before matching (hypothesis)",
    "case_mix": "matching is case-sensitive for this pattern (hypothesis)",
    "leetspeak": "keyword matching is exact (hypothesis)",
}


def _pct(r: dict[str, float | int] | None) -> str:
    if not r:
        return "-"
    return f"{r['value']:.1%} ({r['ci_low']:.1%}-{r['ci_high']:.1%}), n={r['n']}"


def format_markdown(run: AdaptiveRun) -> str:
    s = run.summary
    d = run.detail
    lines = [
        "# Adaptive red-team tier",
        "",
        f"Generated {s.generated_at.isoformat(timespec='seconds')}; {run.cases_used} attack cases, "
        f"**{s.variants} unique variants**, {d['cells']} (variant, preset) cells, {run.seconds:.0f} s.",
        "",
        "Deterministic variants (seeded, no network) of the negative cases: paraphrase, base64, hex, url, zero_width, "
        "homoglyph, polish, split, case_mix, leetspeak. A cell counts as detected when the system's effective action "
        "is stronger than allow/monitor. A variant is only evaluated at presets where the original attack is "
        "intervened on and the text slot is causal (neutralising it removes the intervention). monitor is excluded. "
        "Intervals are Wilson 95 %; variants of one case and the three presets of one variant are strongly "
        "correlated, so the intervals describe sampling noise on this corpus, not generalisation.",
        "",
        f"**Overall detection: {_pct(s.detection.model_dump() if s.detection else None)}**",
        "",
        "## By technique",
        "",
        "| technique | detection (95% CI) |",
        "|---|---|",
    ]
    lines += [f"| {k} | {_pct(v.model_dump())} |" for k, v in s.by_technique.items()]
    lines += [
        "",
        "## By control (the control of the original case)",
        "",
        "| control | detection (95% CI) |",
        "|---|---|",
    ]
    lines += [f"| {k} | {_pct(v.model_dump())} |" for k, v in s.by_control.items()]
    lines += ["", "## By preset", "", "| preset | detection (95% CI) |", "|---|---|"]
    lines += [f"| {k} | {_pct(v.model_dump())} |" for k, v in s.by_preset.items()]
    lines += ["", "## Layer attribution (decided_phase of the cells)", "", "| layer | cells |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in s.layer_attribution.items()]
    lines += [
        "",
        "## By technique and form (weakest first)",
        "",
        "| technique.form | detection (95% CI) |",
        "|---|---|",
    ]
    weakest = sorted((kv for kv in d["by_technique_form"].items() if kv[1]), key=lambda kv: kv[1]["value"])[:15]
    lines += [f"| {k} | {_pct(v)} |" for k, v in weakest]
    owner = d["detected_by_owner_control"]
    lines += [
        "",
        "## Who caught it",
        "",
        f"Of the detected cells, {_pct(owner)} involved the control the case was written for; the rest were caught "
        "by another control (for example the secret / entropy detector on an encoded blob, the shell checker's "
        "default-deny on an unrecognised command, or the egress filter). Detection here means 'the system "
        "intervened', as in the guard-quality summary; per-technique action mix is in `adaptive_detail.json`.",
        "",
        f"Detected cells whose only outcome is `require_approval` (a human is asked, nothing is blocked or redacted): "
        f"{_pct(d['detected_as_require_approval'])}. For shell-command variants this is likely the checker's "
        "default-deny on a command it cannot classify, not recognition of the hidden command (not verified per cell).",
    ]
    pl = d["polish"]
    lines += [
        "",
        "## Polish",
        "",
        f"- variants where a phrase was really translated (table-based): {_pct(pl['translated'])}",
        f"- Polish framing around the unchanged original (no translation happened): {_pct(pl['framing_only'])}",
        "",
        "## What is not caught, and why",
        "",
    ]
    combos = d["by_technique_control_missed"]
    if not combos:
        lines.append("Every evaluated cell was detected. That is a statement about this corpus and these techniques, ")
        lines.append(
            "not a guarantee: a stronger adversary (semantic paraphrase, multi-turn, novel encodings) is not "
            "modelled here."
        )
    else:
        lines += [
            "Top missed technique x control combinations (cells missed / evaluated). The likely cause is a "
            "hypothesis from the technique, not a verified diagnosis.",
            "",
            "| technique | control | missed / cells | likely cause (hypothesis) | example variants |",
            "|---|---|---:|---|---|",
        ]
        examples: dict[tuple[str, str], list[str]] = defaultdict(list)
        for m in d["missed"]:
            ex = examples[(m["technique"], m["control"])]
            if m["variant"] not in ex:
                ex.append(m["variant"])
        for row in combos[:15]:
            ex = ", ".join(f"`{v}`" for v in examples[(row["technique"], row["control"])][:3])
            lines.append(
                f"| {row['technique']} | {row['control']} | {row['missed']} / {row['cells']} | "
                f"{HYPOTHESES.get(row['technique'], '')} | {ex} |"
            )
        lines += ["", f"All {len(d['missed'])} missed cells are listed in `reports/adaptive_detail.json`."]
    lines += ["", "## Skipped cases", "", "| reason | cases |", "|---|---:|"]
    lines += [f"| {k} | {len(v)} |" for k, v in sorted(run.skipped.items())]
    lines += [
        "",
        "Reasons: `non_text_payload` (mcp / artifact: detection depends on descriptors, URLs, metadata), "
        "`monitor_case` (monitor-only duplicates), `format_property` (SEC-HYG-01 think-block / reasoning / logprobs "
        "cases: a response-format property, not hidden content), `no_text_slot` (no string to change), "
        "`baseline_not_intervened` (the original is not intervened on at balanced/strict/paranoid), "
        "`independent_of_text` (the system intervenes even with every text slot neutralised: tool tier, group, "
        "session labels, budgets, loop limits ...).",
    ]
    if d["errors"]:
        lines += ["", f"{len(d['errors'])} cell(s) could not be evaluated (invalid payload) and are excluded."]
    return "\n".join(lines) + "\n"


def known_techniques() -> tuple[str, ...]:
    return tuple(TECHNIQUES)
