"""Streaming egress guard: hold-back window, incremental inspection, safe placeholder restoration.

Text from the model is buffered. Nothing is emitted before it has been inspected:

    raw buffer:  [ emitted ........ | safe to emit now ...... | held back (holdback_chars) ]
                  0              emit_raw                    cut                       len(buf)

* every `step` new characters the guard evaluates egress on a window (the not-yet-emitted text plus a
  small overlap of emitted text so findings that straddle the boundary are still seen) as a partial
  `CompletionPayload`; a block/approval decision stops the stream before the offending text is emitted;
* the cut never splits a pseudonym placeholder (`<PERSON_1>`, or one the vault knows) nor a finding that
  carries a replacement, so redaction and restoration always see whole tokens;
* at the end `finish()` evaluates the full completion (incl. tool calls) once, authoritatively. Tool-call
  fragments are never streamed: the caller emits them only after `finish()` returns them inspected.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

from acl.contracts.common import Action
from acl.contracts.decision import Decision, Finding
from acl.contracts.inspection import CompletionPayload, ToolCall
from acl.engine.text import apply_replacements
from acl.engine.transforms import PARTIAL_PLACEHOLDER_RE, PLACEHOLDER_RE

OVERLAP_CHARS = 128
MIN_RESTORE_HOLDBACK = 64

Evaluate = Callable[[CompletionPayload], Awaitable[Decision]]
FindingsOf = Callable[[Decision], list[Finding]]
Restore = Callable[[str], Awaitable[str]]


def is_blocking(decision: Decision) -> bool:
    return decision.action in (Action.block, Action.require_approval)


@dataclass
class StreamStep:
    text: str = ""
    blocked: Decision | None = None


@dataclass
class StreamEnd:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    decision: Decision | None = None
    blocked: bool = False


class RepeatDetector:
    """Endless-generation guard: flags a word n-gram that repeats more than `max_repeats` times."""

    def __init__(self, n: int, max_repeats: int, max_tracked: int = 50_000) -> None:
        self.n = max(2, n)
        self.max_repeats = max_repeats
        self._counts: dict[tuple[str, ...], int] = {}
        self._tail: list[str] = []
        self._partial = ""
        self._max_tracked = max_tracked

    def feed(self, text: str) -> bool:
        data = self._partial + text
        words = data.split()
        if data and not data[-1].isspace() and words:
            self._partial = words.pop()  # last word may continue in the next chunk
        else:
            self._partial = ""
        seq = self._tail + words
        for i in range(len(seq) - self.n + 1):
            gram = tuple(seq[i : i + self.n])
            count = self._counts.get(gram, 0) + 1
            if count > self.max_repeats:
                return True
            if count > 1 or len(self._counts) < self._max_tracked:
                self._counts[gram] = count
        self._tail = seq[-(self.n - 1) :] if len(seq) >= self.n - 1 else seq
        return False


def _valid(f: Finding) -> bool:
    return f.start is not None and f.end is not None and f.end > f.start and f.field == "content"


class StreamGuard:
    def __init__(
        self,
        *,
        evaluate: Evaluate,
        findings_of: FindingsOf,
        restore: Restore | None = None,
        placeholders: Iterable[str] = (),
        holdback_chars: int = 256,
        inspect: bool = True,
        overlap: int = OVERLAP_CHARS,
    ) -> None:
        self._evaluate = evaluate
        self._findings_of = findings_of
        self._restore = restore
        self._known = sorted({p for p in placeholders if p}, key=len, reverse=True)
        self.inspect = inspect
        needs_hold = inspect or restore is not None
        self.holdback = (max(holdback_chars, MIN_RESTORE_HOLDBACK if restore else 0)) if needs_hold else 0
        self.step = max(self.holdback // 2, 32)
        self.overlap = overlap
        self.buf = ""
        self.emit_raw = 0
        self._evaluated = 0
        self.decisions: list[Decision] = []

    # ------------------------------------------------------------ helpers

    def _spans(self, extra: Iterable[Finding]) -> list[tuple[int, int]]:
        spans = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(self.buf)]
        for p in self._known:
            start = self.buf.find(p)
            while start != -1:
                spans.append((start, start + len(p)))
                start = self.buf.find(p, start + 1)
        spans.extend((f.start, f.end) for f in extra if _valid(f))  # type: ignore[misc]
        return spans

    def _cut(self, extra: Iterable[Finding] = ()) -> int:
        cut = max(self.emit_raw, len(self.buf) - self.holdback)
        for start, end in self._spans(extra):
            if start < cut < end:
                cut = max(self.emit_raw, start)
        tail = PARTIAL_PLACEHOLDER_RE.search(self.buf)
        if tail is not None and tail.start() < cut and self.restore_enabled:
            cut = max(self.emit_raw, tail.start())
        return cut

    @property
    def restore_enabled(self) -> bool:
        return self._restore is not None

    def _apply(self, findings: Iterable[Finding], lo: int, hi: int) -> str:
        """buf[lo:hi] with enforced replacements applied (findings use absolute buffer offsets)."""
        out: list[str] = []
        pos = lo  # next raw index to copy
        for f in sorted((f for f in findings if _valid(f)), key=lambda f: (f.start, -(f.end or 0))):  # type: ignore[operator]
            start, end = f.start, f.end
            assert start is not None and end is not None
            if end <= pos or start >= hi:
                continue
            if start < pos:
                # Straddles the already-emitted boundary: emit the replacement for the remainder.
                # Partially overlaps a finding applied just before: swallow the remainder (never leak it).
                if start < lo:
                    out.append(f.replacement or "")
                pos = min(end, hi)
                continue
            out.append(self.buf[pos:start])
            out.append(f.replacement or "")
            pos = min(end, hi)
        out.append(self.buf[pos:hi])
        return "".join(out)

    async def _emit(self, findings: list[Finding], hi: int) -> str:
        text = self._apply(findings, self.emit_raw, hi)
        self.emit_raw = max(self.emit_raw, hi)
        return await self._restore(text) if self._restore and text else text

    # ------------------------------------------------------------ API

    async def feed(self, text: str) -> StreamStep:
        if not text:
            return StreamStep()
        self.buf += text
        if not self.inspect:
            return StreamStep(text=await self._emit([], self._cut()))
        if len(self.buf) - self._evaluated < self.step:
            return StreamStep()
        window_start = max(0, self.emit_raw - self.overlap)
        decision = await self._evaluate(CompletionPayload(content=self.buf[window_start:], is_partial=True))
        self._evaluated = len(self.buf)
        self.decisions.append(decision)
        if is_blocking(decision):
            return StreamStep(blocked=decision)
        findings = [
            f.model_copy(update={"start": f.start + window_start, "end": f.end + window_start})  # type: ignore[operator]
            for f in self._findings_of(decision)
            if _valid(f)
        ]
        return StreamStep(text=await self._emit(findings, self._cut(findings)))

    async def finish(
        self, tool_calls: list[ToolCall], finish_reason: str | None, reasoning: str | None = None
    ) -> StreamEnd:
        payload = CompletionPayload(
            content=self.buf or None,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            reasoning=reasoning,
            is_partial=False,
        )
        decision = await self._evaluate(payload)
        self.decisions.append(decision)
        if is_blocking(decision):
            return StreamEnd(decision=decision, blocked=True)
        findings = self._findings_of(decision)
        text = await self._emit([f for f in findings if _valid(f)], len(self.buf))
        tc_findings = [f for f in findings if f.field.startswith("tool_calls")]
        out_calls = apply_replacements(payload, tc_findings)[0].tool_calls if tc_findings else tool_calls
        return StreamEnd(text=text, tool_calls=out_calls, decision=decision)
