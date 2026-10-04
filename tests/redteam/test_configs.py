"""The garak and promptfoo configs parse, target an environment-configurable gateway URL and carry no secrets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from redteam.garak import render as garak_render
from ruamel.yaml import YAML

HERE = Path(__file__).resolve().parent
GARAK = HERE / "garak"
PROMPTFOO = HERE / "promptfoo"
GARAK_FAMILIES = {"promptinject", "dan", "encoding", "latentinjection", "xss", "malwaregen", "packagehallucination"}
PLUGINS = {"pii", "prompt-extraction", "hijacking", "indirect-prompt-injection", "excessive-agency", "rbac", "bola"}
STRATEGIES = {"jailbreak", "prompt-injection", "base64", "leetspeak", "rot13", "multilingual"}


def load(path: Path, text: str | None = None) -> dict[str, Any]:
    data = YAML(typ="safe", pure=True).load(text if text is not None else path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def rendered(name: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    path = GARAK / name
    return load(path, garak_render.render(path.read_text(encoding="utf-8"), env or {}))


def families(probe_spec: str) -> set[str]:
    return {p.split(".")[0] for p in probe_spec.split(",") if p}


# ---------------------------------------------------------------- garak


@pytest.mark.parametrize("name", ["config.yaml", "quick.yaml"])
def test_garak_templates_render_with_defaults_and_parse(name: str) -> None:
    cfg = rendered(name)
    plugins = cfg["plugins"]
    assert plugins["model_type"] == "openai.OpenAICompatible"
    gen = plugins["generators"]["openai"]["OpenAICompatible"]
    assert gen["uri"] == "http://localhost:8080/v1"  # default only; the real URL comes from ACL_GATEWAY_URL
    assert plugins["model_name"] == "local" and gen["model"] == "local"
    assert cfg["reporting"]["report_dir"] == "reports/redteam/garak"
    assert cfg["run"]["generations"] >= 1


def test_garak_full_config_lists_the_expected_probe_families() -> None:
    spec = rendered("config.yaml")["plugins"]["probe_spec"]
    assert families(spec) >= GARAK_FAMILIES
    assert "goodside.Tag" in spec.split(",")
    assert "leakreplay" not in families(spec)  # excluded on purpose (documented in the template)


def test_garak_quick_config_stays_inside_the_full_config_families() -> None:
    quick = families(rendered("quick.yaml")["plugins"]["probe_spec"])
    full = families(rendered("config.yaml")["plugins"]["probe_spec"])
    assert quick <= full and len(quick) >= 6


def test_garak_gateway_url_and_model_follow_the_environment() -> None:
    env = {"ACL_GATEWAY_URL": "https://gateway.example.test/", "GARAK_MODEL": "smart", "GARAK_REPORT_DIR": "out/g"}
    cfg = rendered("config.yaml", env)
    gen = cfg["plugins"]["generators"]["openai"]["OpenAICompatible"]
    assert gen["uri"] == "https://gateway.example.test/v1"  # trailing slash of the base URL is normalised
    assert cfg["plugins"]["model_name"] == "smart" and gen["model"] == "smart"
    assert cfg["reporting"]["report_dir"] == "out/g"


def test_garak_render_refuses_secret_placeholders_and_missing_required_variables() -> None:
    with pytest.raises(garak_render.RenderError, match="secret"):
        garak_render.render("api_key: ${ACL_API_KEY}", {"ACL_API_KEY": "x"})
    with pytest.raises(garak_render.RenderError, match="required"):
        garak_render.render("uri: ${SOMETHING_UNSET}", {})
    assert garak_render.render("m: ${A:-fallback}", {}) == "m: fallback"
    assert [n for n, _ in garak_render.placeholders((GARAK / "config.yaml").read_text(encoding="utf-8"))] == [
        "GARAK_MODEL",
        "ACL_GATEWAY_URL",
        "GARAK_MODEL",
        "GARAK_REPORT_DIR",
    ]


def test_garak_render_cli_writes_the_file(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "rendered.yaml"
    assert garak_render.main([str(GARAK / "quick.yaml"), "--out", str(out)], env={"GARAK_MODEL": "local-coder"}) == 0
    assert load(out)["plugins"]["model_name"] == "local-coder"


# ---------------------------------------------------------------- promptfoo


def test_promptfoo_provider_points_at_the_gateway_through_the_environment() -> None:
    cfg = load(PROMPTFOO / "promptfooconfig.yaml")
    (provider,) = cfg["providers"]
    assert provider["id"].startswith("openai:chat:")
    base = provider["config"]["apiBaseUrl"]
    assert "env.ACL_GATEWAY_URL" in base and base.endswith("/v1")
    assert provider["config"]["apiKeyEnvar"] == "ACL_API_KEY"
    assert "apiKey" not in provider["config"]


def test_promptfoo_redteam_lists_the_expected_plugins_and_strategies() -> None:
    red = load(PROMPTFOO / "promptfooconfig.yaml")["redteam"]
    plugin_ids = {p["id"] if isinstance(p, dict) else p for p in red["plugins"]}
    assert plugin_ids >= PLUGINS
    assert any(p.startswith("harmful:") for p in plugin_ids)
    strategies = {s["id"] if isinstance(s, dict) else s: s for s in red["strategies"]}
    assert set(strategies) >= STRATEGIES
    assert "pl" in strategies["multilingual"]["config"]["languages"]
    assert red["purpose"].strip()


def test_promptfoo_plain_tests_assert_what_the_guard_must_do() -> None:
    tests = load(PROMPTFOO / "promptfooconfig.yaml")["tests"]
    assert len(tests) >= 3 and all(t.get("assert") for t in tests)
    forbidden = {a["value"] for t in tests for a in t["assert"] if a["type"] == "not-contains"}
    assert "44051401359" in forbidden  # the PESEL must not be echoed
    assert any("![" in v for v in forbidden)  # the markdown image must be stripped
    # the PESEL used is the synthetic checksum-valid one from the case files, never a real identifier
    prompts = " ".join(t["vars"]["prompt"] for t in tests)
    assert "44051401359" in prompts


# ---------------------------------------------------------------- secrets


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),  # OpenAI-style key
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"Bearer\s+[A-Za-z0-9._-]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),  # Google API key
]


def _config_files() -> list[Path]:
    return sorted(p for d in (GARAK, PROMPTFOO) for p in d.iterdir() if p.suffix in (".yaml", ".yml", ".md", ".py"))


def test_no_secret_shaped_values_in_the_red_team_files() -> None:
    files = _config_files()
    assert len(files) >= 6
    for path in files:
        text = path.read_text(encoding="utf-8")
        for pat in SECRET_PATTERNS:
            assert not pat.search(text), f"{path.name}: secret-shaped value ({pat.pattern})"


def test_no_literal_api_key_assignment_in_the_yaml_configs() -> None:
    for path in [*GARAK.glob("*.yaml"), *PROMPTFOO.glob("*.yaml")]:
        for line in path.read_text(encoding="utf-8").splitlines():
            code = line.split("#", 1)[0]
            m = re.search(r"api_?key\s*:\s*(\S+)", code, re.IGNORECASE)
            if m:  # only an environment-variable name (apiKeyEnvar) or a placeholder may follow
                assert re.fullmatch(r"[A-Z][A-Z0-9_]*|\$\{[A-Z0-9_:-]+\}", m.group(1)), f"{path.name}: {line.strip()}"
