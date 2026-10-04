"""live_compare.py is for the integrator: here only import, argument parsing and the missing-env exit (no network)."""

from __future__ import annotations

import pytest
from perf import live_compare as lc


def test_missing_environment_is_named_and_nothing_is_sent(capsys: pytest.CaptureFixture[str], tmp_path) -> None:  # type: ignore[no-untyped-def]
    rc = lc.main(["--json", str(tmp_path / "x.json"), "--md", str(tmp_path / "x.md")], env={})
    err = capsys.readouterr().err
    assert rc == 2
    for name in lc.REQUIRED_ENV:
        assert name in err
    assert not (tmp_path / "x.json").exists()


def test_missing_env_lists_only_what_is_unset() -> None:
    env = {"LOCAL_LLM_BASE_URL": "http://x/v1", "LOCAL_LLM_API_KEY": "  ", "LOCAL_GENERAL_MODEL": "m"}
    assert lc.missing_env(env) == ["LOCAL_LLM_API_KEY", "ACL_API_KEY"]


def test_argument_parsing_defaults_and_flags() -> None:
    a = lc.parse_args([])
    assert (a.requests, a.warmup, a.stream, a.max_tokens) == (30, 3, False, 64)
    b = lc.parse_args(["-n", "5", "--stream", "--max-tokens", "16", "--prompt", "hi"])
    assert (b.requests, b.stream, b.max_tokens, b.prompt) == (5, True, 16, "hi")
    with pytest.raises(SystemExit):
        lc.parse_args(["--requests", "0"])


def test_targets_use_the_documented_urls_models_and_keys() -> None:
    env = {
        "LOCAL_LLM_BASE_URL": "http://gpu:8000/v1/",
        "LOCAL_LLM_API_KEY": "k1",
        "LOCAL_GENERAL_MODEL": "qwen",
        "ACL_API_KEY": "k2",
    }
    direct, gateway = lc.targets(env)
    assert direct.url == "http://gpu:8000/v1/chat/completions" and direct.model == "qwen"
    assert gateway.url == "http://localhost:8080/v1/chat/completions" and gateway.model == "local"
    assert direct.headers["Authorization"] == "Bearer k1" and gateway.headers["Authorization"] == "Bearer k2"
    assert lc.targets({**env, "ACL_GATEWAY_URL": "https://gw.example/"})[1].url.startswith("https://gw.example/v1/")


class _Resp:
    status_code = 200


class _FakeClient:
    """Stands in for httpx.Client so the interleaving logic is exercised without any network."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def post(self, url, json=None, headers=None):  # type: ignore[no-untyped-def]
        self.urls.append(url)
        return _Resp()


def test_rounds_alternate_direct_and_gateway_and_swap_the_first_target() -> None:
    env = {
        "LOCAL_LLM_BASE_URL": "http://d/v1",
        "LOCAL_LLM_API_KEY": "a",
        "LOCAL_GENERAL_MODEL": "m",
        "ACL_API_KEY": "b",
    }
    client = _FakeClient()
    result = lc.run(lc.parse_args(["-n", "4", "--warmup", "0"]), env, client)
    kinds = ["direct" if u.startswith("http://d/") else "gateway" for u in client.urls]
    assert kinds == ["direct", "gateway", "gateway", "direct", "direct", "gateway", "gateway", "direct"]
    assert result["direct"]["n"] == result["gateway"]["n"] == 4
    assert result["errors"] == {"direct": 0, "gateway": 0}
    assert "gateway overhead" in lc.render_markdown(result)
