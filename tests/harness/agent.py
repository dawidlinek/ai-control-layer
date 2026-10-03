"""Scripted agent: a deterministic tool-calling loop against the gateway's `/v1/chat/completions`.

The agent has no brain. A *script* (list of steps) says what the "model" does at each turn, encoded as the
mock connector's `[[mock:...]]` directives (see `acl.routing.connectors.mock`), so the gateway sees real
OpenAI-shaped traffic: the model emits a tool call, the agent runs the tool from its `ToolBox`, the result
goes back as a `tool` message, the model emits the next call, and so on. Requires the gateway to run with
deterministic/mock connectors (`ACL_DETERMINISTIC=1`).

    script = [tool("files.read_file", {"path": "README.md"}), tool("web.fetch", {"url": sink + "/x"}), reply("done")]
    trace = await ScriptedAgent(client, toolbox=ToolBox({...})).run("Summarise the repo", script)

Evidence for oracles, in priority order: environment state (`ToolBox.executed`, the attacker sink log), the
structured trace (`AgentTrace.turns`), and only then `final_text`.

Works with any `httpx.AsyncClient`: in-process (`host.async_client()` inside `host.run(...)`) or against the
live stack (`httpx.AsyncClient(base_url="http://localhost:8000", headers={"Authorization": "Bearer ..."})`).
"""

from __future__ import annotations

import inspect
import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

ToolFn = Callable[[dict[str, Any]], "str | Awaitable[str]"]
_STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


# ---------------------------------------------------------------- script steps


@dataclass(frozen=True)
class Step:
    """What the scripted model does on one turn."""

    directive: str
    label: str = ""


def _no_bracket(text: str, what: str) -> str:
    if "]" in text:
        raise ValueError(f"{what} cannot contain ']' (the mock directive grammar ends an argument at the first ']')")
    return text


def tool(name: str, args: Mapping[str, Any] | None = None) -> Step:
    """The model calls `name` with `args`. Arrays in `args` are not expressible in mock directives."""
    raw = json.dumps(dict(args or {}), separators=(",", ":"))
    raw = _STRING_LITERAL.sub(lambda m: m.group(0).replace("]", "\\u005d"), raw)
    _no_bracket(raw, "tool arguments (JSON arrays)")
    return Step(f"[[mock:tool {name} {raw}]]", label=f"tool:{name}")


def reply(text: str) -> Step:
    """The model answers with exactly `text` (ends the loop)."""
    return Step(f"[[mock:reply {_no_bracket(text, 'reply text')}]]", label="reply")


def reasoning(text: str) -> Step:
    """Reply that also carries a reasoning trace + logprobs (egress-hygiene tests)."""
    return Step(f"[[mock:reasoning {_no_bracket(text, 'reasoning text')}]]", label="reasoning")


def repeat_text(n: int, text: str) -> Step:
    """Endless-generation stand-in: `text` repeated `n` times."""
    return Step(f"[[mock:repeat {n} {_no_bracket(text, 'repeat text')}]]", label="repeat")


def raw(directive: str) -> Step:
    return Step(directive, label="raw")


def repeated(step: Step, n: int) -> list[Step]:
    """The same step n times (repeat-call detector, loop budgets)."""
    return [step] * n


# ---------------------------------------------------------------- tools the agent can run


@dataclass
class ToolExecution:
    name: str
    arguments: dict[str, Any]
    result: str


class ToolBox:
    """Fake environment: tool name -> function(args) -> result text. Records what was actually executed."""

    def __init__(self, tools: Mapping[str, ToolFn | str] | None = None, *, default: str = "ok") -> None:
        self.tools: dict[str, ToolFn | str] = dict(tools or {})
        self.default = default
        self.executed: list[ToolExecution] = []

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        impl = self.tools.get(name, self.default)
        result = impl(arguments) if callable(impl) else impl
        if inspect.isawaitable(result):
            result = await result
        self.executed.append(ToolExecution(name, arguments, str(result)))
        return str(result)

    def names(self) -> list[str]:
        return [e.name for e in self.executed]


def http_fetch_tool(allowed_hosts: frozenset[str] = LOOPBACK, timeout: float = 5.0) -> ToolFn:
    """A `web.fetch`-style tool that REALLY performs the request, so an attacker sink can prove exfiltration.

    Refuses any host outside `allowed_hosts` (loopback by default): a test must never reach the internet.
    """

    async def _fetch(args: dict[str, Any]) -> str:
        url = str(args.get("url", ""))
        host = urlsplit(url).hostname or ""
        if host not in allowed_hosts and f"[{host}]" not in allowed_hosts:
            return f"error: host {host!r} not allowed in tests"
        async with httpx.AsyncClient(timeout=timeout) as c:
            method = str(args.get("method", "POST" if args.get("body") else "GET")).upper()
            r = await c.request(method, url, content=args.get("body"))
            return r.text

    return _fetch


# ---------------------------------------------------------------- trace


@dataclass
class AgentTurn:
    step: Step | None
    status_code: int
    body: Any  # parsed JSON (or text for non-JSON errors)
    message: dict[str, Any] | None = None  # the assistant message when status == 200
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AgentTrace:
    task: str
    turns: list[AgentTurn] = field(default_factory=list)
    executed: list[ToolExecution] = field(default_factory=list)
    final_text: str | None = None
    stop_reason: str = ""  # final | error | script_exhausted | max_steps

    @property
    def status_code(self) -> int:
        return self.turns[-1].status_code if self.turns else 0

    @property
    def error(self) -> Any | None:
        last = self.turns[-1] if self.turns else None
        return last.body if last and last.status_code >= 400 else None

    @property
    def blocked(self) -> bool:
        """The gateway refused a turn (4xx policy refusal, not auth or rate limiting)."""
        return self.stop_reason == "error" and self.status_code in (400, 403, 409, 422, 451)

    @property
    def tool_names(self) -> list[str]:
        return [e.name for e in self.executed]

    def error_text(self) -> str:
        """Lower-cased JSON text of the error body, for `'forbidden_model' in trace.error_text()`."""
        return json.dumps(self.error, ensure_ascii=False).lower() if self.error is not None else ""

    def all_text(self) -> list[Any]:
        """Everything the agent saw or produced, for a leak-oracle scan."""
        return [self.final_text, [t.body for t in self.turns], [(e.arguments, e.result) for e in self.executed]]


# ---------------------------------------------------------------- the agent


class ScriptedAgent:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        model: str = "auto",
        toolbox: ToolBox | None = None,
        headers: Mapping[str, str] | None = None,
        path: str = "/v1/chat/completions",
        max_steps: int = 10,
        system: str | None = None,
        stream: bool = False,
        directive_channel: str = "user",
        extra_body: Mapping[str, Any] | None = None,
    ) -> None:
        """`directive_channel`: where the next step's directive is delivered after a tool result --
        a separate `user` message (the tool result stays exactly as the tool returned it) or inside the
        `tool` message content."""
        self.client = client
        self.model = model
        self.toolbox = toolbox or ToolBox()
        self.headers = dict(headers or {})
        self.path = path
        self.max_steps = max_steps
        self.system = system
        self.stream = stream
        self.directive_channel = directive_channel
        self.extra_body = dict(extra_body or {})

    async def run(self, task: str, script: Sequence[Step]) -> AgentTrace:
        trace = AgentTrace(task=task)
        messages: list[dict[str, Any]] = []
        if self.system:
            messages.append({"role": "system", "content": self.system})
        steps = list(script)
        if not steps:
            messages.append({"role": "user", "content": task})
        else:
            messages.append({"role": "user", "content": f"{task}\n{steps[0].directive}"})
        for idx in range(self.max_steps):  # one script step is played per request
            turn = await self._post(messages, steps[idx] if idx < len(steps) else None)
            trace.turns.append(turn)
            if turn.status_code >= 400 or turn.message is None:
                trace.stop_reason = "error"
                break
            messages.append(turn.message)
            if not turn.tool_calls:
                trace.final_text = turn.message.get("content")
                trace.stop_reason = "final"
                break
            for call in turn.tool_calls:
                fn = call.get("function", {})
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {"_raw": fn.get("arguments")}
                result = await self.toolbox.call(fn.get("name", ""), args)
                trace.executed.append(self.toolbox.executed[-1])
                messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": result})
            if idx + 1 >= len(steps):
                trace.stop_reason = "script_exhausted"
                break
            directive = steps[idx + 1].directive
            if self.directive_channel == "tool":
                messages[-1]["content"] = messages[-1]["content"] + "\n" + directive
            else:
                messages.append({"role": "user", "content": directive})
        else:
            trace.stop_reason = "max_steps"
        return trace

    async def _post(self, messages: list[dict[str, Any]], step: Step | None) -> AgentTurn:
        body = {"model": self.model, "messages": messages, "stream": self.stream, **self.extra_body}
        if self.stream:
            return await self._post_stream(body, step)
        r = await self.client.post(self.path, json=body, headers=self.headers)
        try:
            data: Any = r.json()
        except ValueError:
            data = r.text
        turn = AgentTurn(step=step, status_code=r.status_code, body=data, headers=dict(r.headers))
        if r.status_code == 200 and isinstance(data, dict) and data.get("choices"):
            msg = data["choices"][0].get("message") or {}
            turn.message = msg
            turn.tool_calls = list(msg.get("tool_calls") or [])
        return turn

    async def _post_stream(self, body: dict[str, Any], step: Step | None) -> AgentTurn:
        content: list[str] = []
        calls: dict[int, dict[str, Any]] = {}
        chunks: list[Any] = []
        async with self.client.stream("POST", self.path, json=body, headers=self.headers) as r:
            if r.status_code != 200:
                text = (await r.aread()).decode("utf-8", errors="replace")
                try:
                    data: Any = json.loads(text)
                except ValueError:
                    data = text
                return AgentTurn(step=step, status_code=r.status_code, body=data, headers=dict(r.headers))
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                chunk = json.loads(payload)
                chunks.append(chunk)
                for choice in chunk.get("choices") or []:
                    delta = choice.get("delta") or {}
                    if delta.get("content"):
                        content.append(delta["content"])
                    for tc in delta.get("tool_calls") or []:
                        slot = calls.setdefault(tc.get("index", 0), {"id": "", "type": "function", "function": {}})
                        slot["id"] = tc.get("id") or slot["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["function"]["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["function"]["arguments"] = slot["function"].get("arguments", "") + fn["arguments"]
        msg: dict[str, Any] = {"role": "assistant", "content": "".join(content) or None}
        tool_calls = [calls[i] for i in sorted(calls)]
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return AgentTurn(
            step=step, status_code=200, body=chunks, message=msg, tool_calls=tool_calls, headers=dict(r.headers)
        )
