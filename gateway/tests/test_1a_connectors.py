"""1A: openai_compatible / ollama connectors (respx), usage metering, registry and kill switch."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from acl.contracts.common import ConnectorTier
from acl.policy.loader import load_policy_dir
from acl.routing.connectors.base import ConnectorError
from acl.routing.connectors.mock import MockConnector
from acl.routing.connectors.ollama import OllamaConnector
from acl.routing.connectors.openai_compatible import OpenAICompatibleConnector, parse_usage
from acl.routing.metering import compute_usage
from acl.routing.registry import ConnectorRegistry

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
REQ = {"messages": [{"role": "user", "content": "hi"}], "temperature": 0.2}


def sse_body(*chunks: dict | str) -> bytes:
    lines = [c if isinstance(c, str) else f"data: {json.dumps(c)}" for c in chunks]
    return ("\n\n".join(lines) + "\n\n").encode()


# ------------------------------------------------------------------ openai_compatible


@respx.mock
async def test_openai_chat_sends_auth_and_maps_usage() -> None:
    route = respx.post("https://up.example/v1/chat/completions").respond(
        200,
        json={
            "id": "x",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "yo"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 30},
        },
    )
    c = OpenAICompatibleConnector("gemini", "https://up.example/v1/", api_key="sekret", headers={"X-Org": "acme"})
    out = await c.chat("gemini-x", REQ)
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer sekret" and sent.headers["x-org"] == "acme"
    body = json.loads(sent.content)
    assert body["model"] == "gemini-x" and body["stream"] is False and body["temperature"] == 0.2
    assert out.body["choices"][0]["message"]["content"] == "yo"
    # Gemini hides reasoning tokens outside completion_tokens: output = max(completion, total - prompt)
    assert (out.usage.input_tokens, out.usage.output_tokens, out.usage.reasoning_tokens) == (10, 20, 16)
    await c.aclose()


def test_parse_usage_variants() -> None:
    assert parse_usage({"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}).output_tokens == 7
    assert parse_usage({"prompt_tokens": 5, "completion_tokens": 7}).output_tokens == 7  # no total reported
    assert parse_usage(None).output_tokens == 0
    u = parse_usage(
        {
            "prompt_tokens": 1,
            "completion_tokens": 2,
            "total_tokens": 3,
            "completion_tokens_details": {"reasoning_tokens": 1},
        }
    )
    assert u.reasoning_tokens == 1


@respx.mock
@pytest.mark.parametrize(
    ("status", "retryable"), [(400, False), (401, False), (404, False), (429, True), (500, True), (503, True)]
)
async def test_openai_maps_http_errors(status: int, retryable: bool) -> None:
    respx.post("https://up.example/v1/chat/completions").respond(status, json={"error": {"message": "nope"}})
    c = OpenAICompatibleConnector("x", "https://up.example/v1")
    with pytest.raises(ConnectorError) as exc:
        await c.chat("m", REQ)
    assert exc.value.status == status and exc.value.retryable is retryable
    with pytest.raises(ConnectorError) as exc:
        async for _ in c.chat_stream("m", REQ):
            pass
    assert exc.value.status == status


@respx.mock
async def test_openai_maps_transport_errors() -> None:
    respx.post("https://up.example/v1/chat/completions").mock(side_effect=httpx.ConnectTimeout("slow"))
    c = OpenAICompatibleConnector("x", "https://up.example/v1")
    with pytest.raises(ConnectorError) as exc:
        await c.chat("m", REQ)
    assert exc.value.status == 504 and exc.value.retryable
    respx.post("https://up.example/v1/chat/completions").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(ConnectorError) as exc:
        await c.chat("m", REQ)
    assert exc.value.status == 502


@respx.mock
async def test_openai_streaming_parses_sse_and_usage_last() -> None:
    def chunk(delta: dict, finish: str | None = None) -> dict:
        return {"id": "c", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}

    route = respx.post("https://up.example/v1/chat/completions").respond(
        200,
        content=sse_body(
            ": keep-alive",
            chunk({"role": "assistant"}),
            chunk({"content": "Hel"}),
            "data: {not json",
            chunk({"content": "lo"}),
            chunk({}, "stop"),
            {"choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}},
            "data: [DONE]",
        ),
        headers={"content-type": "text/event-stream"},
    )
    c = OpenAICompatibleConnector("x", "https://up.example/v1")
    chunks = [ch async for ch in c.chat_stream("m", REQ)]
    sent = json.loads(route.calls.last.request.content)
    assert sent["stream"] is True and sent["stream_options"] == {"include_usage": True}
    text = "".join(ch.body["choices"][0]["delta"].get("content", "") for ch in chunks if ch.body["choices"])
    assert text == "Hello"
    assert chunks[-1].usage is not None and chunks[-1].usage.output_tokens == 2 and chunks[-1].usage.upstream_ms >= 0
    assert all(ch.usage is None for ch in chunks[:-1])


@respx.mock
async def test_openai_streaming_in_stream_error_object() -> None:
    respx.post("https://up.example/v1/chat/completions").respond(
        200, content=sse_body({"error": {"message": "overloaded"}}), headers={"content-type": "text/event-stream"}
    )
    c = OpenAICompatibleConnector("x", "https://up.example/v1")
    with pytest.raises(ConnectorError):
        async for _ in c.chat_stream("m", REQ):
            pass


@respx.mock
async def test_openai_embeddings() -> None:
    respx.post("https://up.example/v1/embeddings").respond(
        200, json={"data": [{"index": 0, "embedding": [0.1]}], "usage": {"prompt_tokens": 4, "total_tokens": 4}}
    )
    out = await OpenAICompatibleConnector("x", "https://up.example/v1").embeddings("e", {"input": ["a"]})
    assert out.usage.input_tokens == 4 and out.usage.output_tokens == 0


# ------------------------------------------------------------------ ollama


@respx.mock
async def test_ollama_chat_meters_gpu_seconds() -> None:
    route = respx.post("http://gpu:11434/api/chat").respond(
        200,
        json={
            "model": "qwen3",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "mail.send", "arguments": {"to": "a@b.c"}}}],
            },
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 11,
            "eval_count": 7,
            "eval_duration": 2_000_000_000,
            "prompt_eval_duration": 500_000_000,
        },
    )
    c = OllamaConnector("ollama", "http://gpu:11434/v1")  # a trailing /v1 is tolerated
    req = {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 50, "temperature": 0.1, "stop": "x"}
    out = await c.chat("qwen3", req)
    sent = json.loads(route.calls.last.request.content)
    assert sent["stream"] is False and sent["options"] == {"temperature": 0.1, "num_predict": 50, "stop": ["x"]}
    assert out.usage.gpu_seconds == pytest.approx(2.5) and out.usage.input_tokens == 11 and out.usage.output_tokens == 7
    msg = out.body["choices"][0]["message"]
    assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"to": "a@b.c"}
    assert out.body["choices"][0]["finish_reason"] == "tool_calls"


@respx.mock
async def test_ollama_stream_and_history_tool_args_become_objects() -> None:
    ndjson = "\n".join(
        json.dumps(x)
        for x in (
            {"message": {"role": "assistant", "content": "Hel"}, "done": False},
            {"message": {"role": "assistant", "content": "lo"}, "done": False},
            {
                "message": {"role": "assistant", "content": ""},
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 4,
                "eval_count": 2,
                "eval_duration": 1_000_000_000,
            },
        )
    )
    route = respx.post("http://gpu:11434/api/chat").respond(200, content=ndjson.encode())
    c = OllamaConnector("ollama", "http://gpu:11434")
    history = {
        "messages": [
            {"role": "user", "content": "q"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "1", "function": {"name": "f", "arguments": '{"a": 1}'}}],
            },
            {"role": "tool", "content": "r", "name": "f"},
        ]
    }
    chunks = [ch async for ch in c.chat_stream("qwen3", history)]
    sent = json.loads(route.calls.last.request.content)
    assert sent["messages"][1]["tool_calls"][0]["function"]["arguments"] == {"a": 1}
    text = "".join(ch.body["choices"][0]["delta"].get("content", "") for ch in chunks)
    assert text == "Hello"
    assert chunks[-1].usage is not None and chunks[-1].usage.gpu_seconds == pytest.approx(1.0)
    assert chunks[-1].body["choices"][0]["finish_reason"] == "stop"


@respx.mock
async def test_ollama_embeddings_and_errors() -> None:
    respx.post("http://gpu:11434/api/embed").respond(200, json={"embeddings": [[0.1, 0.2]], "prompt_eval_count": 3})
    c = OllamaConnector("ollama", "http://gpu:11434")
    out = await c.embeddings("bge", {"input": "a"})
    assert out.body["data"][0]["embedding"] == [0.1, 0.2] and out.usage.input_tokens == 3
    respx.post("http://gpu:11434/api/chat").respond(500, text="boom")
    with pytest.raises(ConnectorError) as exc:
        await c.chat("m", REQ)
    assert exc.value.retryable


# ------------------------------------------------------------------ metering


def test_usage_cost_and_gpu_estimates() -> None:
    policy = load_policy_dir(POLICY_DIR).policy
    models = policy.model_by_id()
    from acl.routing.connectors.base import UpstreamUsage

    cloud = compute_usage(models["gemini/flash"], UpstreamUsage(input_tokens=1000, output_tokens=2000))
    assert cloud.usd == pytest.approx(0.0003 + 2 * 0.0025) and cloud.gpu_seconds == 0
    local_est = compute_usage(models["local/general"], UpstreamUsage(input_tokens=500, output_tokens=500))
    assert local_est.gpu_seconds == pytest.approx(0.5)  # gpu_seconds_per_1k_tokens estimate
    assert local_est.usd == pytest.approx(0.5 * 0.0006)
    local_real = compute_usage(models["local/general"], UpstreamUsage(output_tokens=1, gpu_seconds=10.0))
    assert local_real.gpu_seconds == 10.0  # upstream timings win over the estimate


# ------------------------------------------------------------------ registry


def test_registry_deterministic_keeps_policy_tier() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    reg = ConnectorRegistry(deterministic=True)
    table = reg.table_for(loaded.policy, loaded.version)
    assert all(isinstance(h.connector, MockConnector) for h in table.connectors.values())
    assert table.connectors["gemini"].config.tier == ConnectorTier.cloud
    assert table.connectors["local"].config.tier == ConnectorTier.local
    assert table.models["gemini/flash"].upstream_model == "gemini/flash"  # stable names, env not needed
    assert table.model_problem("gemini/flash") is None
    assert reg.table_for(loaded.policy, loaded.version) is table  # cached per policy version


def test_registry_unset_env_makes_models_unavailable_not_an_error() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    reg = ConnectorRegistry(
        environ={
            "LOCAL_LLM_BASE_URL": "http://gpu:8000/v1",
            "LOCAL_GENERAL_MODEL": "qwen3:8b",
            "GEMINI_MODEL": "gemini-x",
        }
    )
    table = reg.table_for(loaded.policy, loaded.version)
    assert table.model_problem("local/general") is None
    assert table.models["local/general"].upstream_model == "qwen3:8b"
    assert "LOCAL_PL_MODEL" in (table.model_problem("local/pl") or "")  # model env unset
    assert "GEMINI_API_KEY" in (table.model_problem("gemini/flash") or "")  # cloud connector without a key
    assert isinstance(table.connectors["local"].connector, OpenAICompatibleConnector)  # local works without a key
    assert table.connectors["gemini"].connector is None


def test_registry_kill_switch_survives_new_tables_and_reuses_instances() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    reg = ConnectorRegistry(deterministic=True)
    t1 = reg.table_for(loaded.policy, "v1")
    reg.set_kill_switch("gemini", True, "incident", by="anna")
    t2 = reg.table_for(loaded.policy, "v2")
    assert t2 is not t1
    assert (
        t2.connector_problem("gemini") == "kill switch engaged"
        and t1.connector_problem("gemini") == "kill switch engaged"
    )
    assert t2.model_problem("gemini/flash") == "kill switch engaged" and t2.model_problem("local/general") is None
    assert t1.connectors["gemini"].connector is t2.connectors["gemini"].connector  # instance reused
    reg.set_kill_switch("gemini", False, "ok")
    assert t2.connector_problem("gemini") is None


def test_registry_disabled_connector_and_model() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    policy = loaded.policy.model_copy(deep=True)
    policy.connectors["gemini"].enabled = False
    policy.models[-1].enabled = False
    reg = ConnectorRegistry(deterministic=True)
    table = reg.table_for(policy, "x")
    assert table.connector_problem("gemini") == "connector disabled"
    assert table.model_problem("gemini/flash") == "model disabled"
