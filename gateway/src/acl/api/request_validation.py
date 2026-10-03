"""Fail-closed validation of `/v1` request bodies (CP1 review finding).

Only data the pipeline inspects may leave the gateway. Unknown body keys used to pass straight through
to the upstream model (`prediction`, `functions`, `audio`, ...) and non-text content parts were never
inspected, so a PESEL or an AWS key could reach a cloud model with decision `allow`. Therefore:

  * request keys are allowlisted per endpoint; anything else → 400 `unsupported_parameter` (`param` = key);
  * message keys, tool-call keys, tool-definition keys and content-part keys are allowlisted too;
  * only `type: text` content parts are accepted (vision/audio/files are out of scope) → 400
    `unsupported_content_part`;
  * every forwarded free-text value is reachable by `acl.engine.text.iter_texts` (tools, message names,
    params), the rest is type-checked scalars;
  * any JSON string with a lone UTF-16 surrogate → 400 `invalid_unicode`, before any processing.

Error messages never echo request values.
"""

from __future__ import annotations

import math
import re
from typing import Any

from acl.api.errors import GatewayError

CHAT_KEYS = frozenset(
    {
        "model",
        "messages",
        "stream",
        "stream_options",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "n",
        "stop",
        "presence_penalty",
        "frequency_penalty",
        "seed",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "response_format",
        "user",
    }
)
# Consumed by the gateway itself; everything else in CHAT_KEYS is forwarded (as inspected `params`).
CHAT_GATEWAY_KEYS = frozenset({"model", "messages", "tools", "stream", "stream_options", "user"})
EMBEDDINGS_KEYS = frozenset({"model", "input", "encoding_format", "dimensions", "user"})

MESSAGE_KEYS = frozenset({"role", "content", "name", "tool_calls", "tool_call_id"})
# Never forwarded: the gateway strips reasoning from responses, so a client echoing it back in the
# history would otherwise smuggle data upstream.
MESSAGE_DROPPED_KEYS = frozenset({"reasoning_content", "reasoning", "reasoning_details"})
TOOL_CALL_KEYS = frozenset({"id", "type", "function", "index"})
FUNCTION_CALL_KEYS = frozenset({"name", "arguments"})
TOOL_KEYS = frozenset({"type", "function"})
FUNCTION_DEF_KEYS = frozenset({"name", "description", "parameters", "strict"})
TEXT_PART_KEYS = frozenset({"type", "text"})
TOOL_CHOICE_MODES = frozenset({"none", "auto", "required"})
RESPONSE_FORMAT_TYPES = frozenset({"text", "json_object", "json_schema"})
JSON_SCHEMA_FORMAT_KEYS = frozenset({"name", "description", "schema", "strict"})

MAX_BODY_DEPTH = 32
MAX_STOP = 4
# Keys inside free-form JSON (tool parameter schemas, response schemas) are forwarded but are not text
# leaves; keep them to schema-like identifiers so they cannot carry free text.
_SCHEMA_KEY = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.\-]{0,127}$")
_SURROGATE = re.compile("[\ud800-\udfff]")


# ------------------------------------------------------------------ errors


def _bad(code: str, param: str | None, message: str) -> GatewayError:
    return GatewayError(400, "invalid_request_error", message, code=code, param=param)


def unsupported(param: str) -> GatewayError:
    return _bad("unsupported_parameter", param, f"unsupported parameter: {param!r}")


def invalid(param: str, message: str) -> GatewayError:
    return _bad("invalid_value", param, f"invalid value for {param!r}: {message}")


# ------------------------------------------------------------------ whole-body hygiene


def check_body(body: Any) -> None:
    """Reject lone surrogates in any key or string value, and absurd nesting (iterative: no recursion)."""
    stack: list[tuple[Any, int, str | None]] = [(body, 0, None)]
    while stack:
        obj, depth, top = stack.pop()
        if depth > MAX_BODY_DEPTH:
            raise _bad("nesting_too_deep", top, "request body is nested too deeply")
        if isinstance(obj, str):
            if _SURROGATE.search(obj):
                raise _bad("invalid_unicode", top, "request contains invalid Unicode (lone UTF-16 surrogate)")
        elif isinstance(obj, dict):
            for k, v in obj.items():
                key_top = top if top is not None else str(k)
                if isinstance(k, str) and _SURROGATE.search(k):
                    raise _bad("invalid_unicode", top, "request contains invalid Unicode (lone UTF-16 surrogate)")
                stack.append((v, depth + 1, key_top))
        elif isinstance(obj, list):
            stack.extend((v, depth + 1, top) for v in obj)
        elif isinstance(obj, float) and not math.isfinite(obj):
            raise invalid(top or "body", "non-finite number")


# ------------------------------------------------------------------ scalar helpers


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _number(key: str, v: Any, lo: float, hi: float) -> None:
    if not (isinstance(v, int | float) and not isinstance(v, bool)) or not lo <= v <= hi:
        raise invalid(key, f"expected a number in [{lo}, {hi}]")


def _schema_keys(obj: Any, param: str) -> None:
    stack = [obj]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            for k, v in o.items():
                if not _SCHEMA_KEY.match(k):
                    raise invalid(param, "schema keys must be identifiers")
                stack.append(v)
        elif isinstance(o, list):
            stack.extend(o)


def _keys(obj: dict[str, Any], allowed: frozenset[str], prefix: str) -> dict[str, Any]:
    """Allowlisted keys of `obj`; unknown keys with a null value are dropped, others are rejected."""
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if k in allowed:
            out[k] = v
        elif v is not None:
            raise unsupported(f"{prefix}.{k}")
    return out


# ------------------------------------------------------------------ chat


def _content(content: Any, prefix: str) -> Any:
    if content is None or isinstance(content, str):
        return content
    if not isinstance(content, list):
        raise invalid(prefix, "expected a string or a list of content parts")
    parts = []
    for j, part in enumerate(content):
        p = f"{prefix}[{j}]"
        if not isinstance(part, dict):
            raise invalid(p, "expected a content part object")
        if part.get("type") != "text":
            raise _bad(
                "unsupported_content_part",
                f"{p}.type",
                "only text content parts are supported (images, audio and files cannot be inspected)",
            )
        part = _keys(part, TEXT_PART_KEYS, p)
        if not isinstance(part.get("text"), str):
            raise invalid(f"{p}.text", "expected a string")
        parts.append(part)
    return parts


def _tool_calls(calls: Any, prefix: str) -> Any:
    if calls is None:
        return None
    if not isinstance(calls, list):
        raise invalid(prefix, "expected a list")
    out = []
    for k, tc in enumerate(calls):
        p = f"{prefix}[{k}]"
        if not isinstance(tc, dict):
            raise invalid(p, "expected an object")
        tc = _keys(tc, TOOL_CALL_KEYS, p)
        if tc.get("type", "function") != "function":
            raise invalid(f"{p}.type", "only function tool calls are supported")
        if "index" in tc and not _is_int(tc["index"]):
            raise invalid(f"{p}.index", "expected an integer")
        fn = tc.get("function")
        if not isinstance(fn, dict):
            raise invalid(f"{p}.function", "expected an object")
        tc["function"] = _keys(fn, FUNCTION_CALL_KEYS, f"{p}.function")
        out.append(tc)
    return out


def _message(m: Any, i: int) -> dict[str, Any]:
    prefix = f"messages[{i}]"
    if not isinstance(m, dict):
        raise invalid(prefix, "expected a message object")
    kept = {k: v for k, v in m.items() if k not in MESSAGE_DROPPED_KEYS}
    msg = _keys(kept, MESSAGE_KEYS, prefix)
    if "content" in msg:
        msg["content"] = _content(msg["content"], f"{prefix}.content")
    if "tool_calls" in msg:
        msg["tool_calls"] = _tool_calls(msg["tool_calls"], f"{prefix}.tool_calls")
    for key in ("name", "tool_call_id"):
        if msg.get(key) is not None and not isinstance(msg[key], str):
            raise invalid(f"{prefix}.{key}", "expected a string")
    return msg


def _tools(tools: Any) -> list[dict[str, Any]] | None:
    if tools is None:
        return None
    if not isinstance(tools, list):
        raise invalid("tools", "expected a list")
    out = []
    for i, tool in enumerate(tools):
        p = f"tools[{i}]"
        if not isinstance(tool, dict):
            raise invalid(p, "expected an object")
        tool = _keys(tool, TOOL_KEYS, p)
        if tool.get("type") != "function":
            raise invalid(f"{p}.type", "only function tools are supported")
        fn = tool.get("function")
        if not isinstance(fn, dict):
            raise invalid(f"{p}.function", "expected an object")
        fn = _keys(fn, FUNCTION_DEF_KEYS, f"{p}.function")
        if not isinstance(fn.get("name"), str) or not fn["name"]:
            raise invalid(f"{p}.function.name", "expected a non-empty string")
        if fn.get("description") is not None and not isinstance(fn["description"], str):
            raise invalid(f"{p}.function.description", "expected a string")
        if fn.get("parameters") is not None:
            if not isinstance(fn["parameters"], dict):
                raise invalid(f"{p}.function.parameters", "expected an object")
            _schema_keys(fn["parameters"], f"{p}.function.parameters")
        if fn.get("strict") is not None and not isinstance(fn["strict"], bool):
            raise invalid(f"{p}.function.strict", "expected a boolean")
        out.append({"type": "function", "function": fn})
    return out


def _tool_choice(v: Any) -> None:
    if isinstance(v, str):
        if v not in TOOL_CHOICE_MODES:
            raise invalid("tool_choice", "expected none, auto, required or a function choice")
        return
    if not isinstance(v, dict):
        raise invalid("tool_choice", "expected a string or an object")
    choice = _keys(v, frozenset({"type", "function"}), "tool_choice")
    fn = choice.get("function")
    if choice.get("type") != "function" or not isinstance(fn, dict):
        raise invalid("tool_choice", "expected {type: function, function: {name}}")
    fn = _keys(fn, frozenset({"name"}), "tool_choice.function")
    if not isinstance(fn.get("name"), str):
        raise invalid("tool_choice.function.name", "expected a string")


def _response_format(v: Any) -> None:
    if not isinstance(v, dict):
        raise invalid("response_format", "expected an object")
    rf = _keys(v, frozenset({"type", "json_schema"}), "response_format")
    if rf.get("type") not in RESPONSE_FORMAT_TYPES:
        raise invalid("response_format.type", "expected text, json_object or json_schema")
    js = rf.get("json_schema")
    if js is not None:
        if not isinstance(js, dict):
            raise invalid("response_format.json_schema", "expected an object")
        js = _keys(js, JSON_SCHEMA_FORMAT_KEYS, "response_format.json_schema")
        for key in ("name", "description"):
            if js.get(key) is not None and not isinstance(js[key], str):
                raise invalid(f"response_format.json_schema.{key}", "expected a string")
        if js.get("schema") is not None:
            if not isinstance(js["schema"], dict):
                raise invalid("response_format.json_schema.schema", "expected an object")
            _schema_keys(js["schema"], "response_format.json_schema.schema")


def _chat_param(key: str, v: Any) -> None:
    if key in ("max_tokens", "max_completion_tokens"):
        if not _is_int(v) or v < 1:
            raise invalid(key, "expected a positive integer")
    elif key == "temperature":
        _number(key, v, 0.0, 2.0)
    elif key == "top_p":
        _number(key, v, 0.0, 1.0)
    elif key in ("presence_penalty", "frequency_penalty"):
        _number(key, v, -2.0, 2.0)
    elif key == "seed":
        if not _is_int(v):
            raise invalid(key, "expected an integer")
    elif key == "stop":
        stops = [v] if isinstance(v, str) else v
        if not isinstance(stops, list) or len(stops) > MAX_STOP or not all(isinstance(s, str) for s in stops):
            raise invalid(key, f"expected a string or up to {MAX_STOP} strings")
    elif key == "parallel_tool_calls":
        if not isinstance(v, bool):
            raise invalid(key, "expected a boolean")
    elif key == "tool_choice":
        _tool_choice(v)
    elif key == "response_format":
        _response_format(v)


def validate_chat_body(
    body: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None, dict[str, Any]]:
    """(messages, tools, forwarded params) of a `/v1/chat/completions` body, or a 400 GatewayError.

    `model` / `messages` presence and `n` are checked by the caller (existing error codes).
    """
    for key in body:
        if key not in CHAT_KEYS:
            raise unsupported(key)
    if body.get("stream") is not None and not isinstance(body["stream"], bool):
        raise invalid("stream", "expected a boolean")
    so = body.get("stream_options")
    if so is not None:
        if not isinstance(so, dict):
            raise invalid("stream_options", "expected an object")
        so = _keys(so, frozenset({"include_usage"}), "stream_options")
        if so.get("include_usage") is not None and not isinstance(so["include_usage"], bool):
            raise invalid("stream_options.include_usage", "expected a boolean")
    if body.get("user") is not None and not isinstance(body["user"], str):
        raise invalid("user", "expected a string")
    messages = [_message(m, i) for i, m in enumerate(body.get("messages") or [])]
    tools = _tools(body.get("tools"))
    params: dict[str, Any] = {}
    for key, v in body.items():
        if key in CHAT_GATEWAY_KEYS or key == "n" or v is None:
            continue
        _chat_param(key, v)
        params[key] = v
    return messages, tools, params


# ------------------------------------------------------------------ embeddings


def validate_embeddings_body(body: dict[str, Any]) -> dict[str, Any]:
    """Forwarded embedding params (`dimensions`), or a 400 GatewayError. `input`/`model` are checked by the caller."""
    for key in body:
        if key not in EMBEDDINGS_KEYS:
            raise unsupported(key)
    fmt = body.get("encoding_format")
    if fmt is not None and fmt != "float":
        raise _bad("unsupported_value", "encoding_format", "only encoding_format 'float' is supported")
    if body.get("user") is not None and not isinstance(body["user"], str):
        raise invalid("user", "expected a string")
    params: dict[str, Any] = {}
    dims = body.get("dimensions")
    if dims is not None:
        if not _is_int(dims) or dims < 1:
            raise invalid("dimensions", "expected a positive integer")
        params["dimensions"] = dims
    return params


__all__ = [
    "CHAT_KEYS",
    "EMBEDDINGS_KEYS",
    "check_body",
    "unsupported",
    "validate_chat_body",
    "validate_embeddings_body",
]
