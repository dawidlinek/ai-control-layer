"""Runs `tests/cases/routing/polish_legal.yaml` (router cases: Polish legal text → local/bielik) against the real
Router, the seed policy and mock connectors. See the header of the YAML file for the case format."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from acl.contracts.common import DataClass
from acl.policy.loader import load_policy_dir
from acl.routing.dev_access import PermissiveAccess
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import Route, Router, RouteRequest

ROOT = Path(__file__).resolve().parents[2]
CASES_FILE = ROOT / "tests" / "cases" / "routing" / "polish_legal.yaml"
BIELIK = "local/bielik"
ENV_NO_BIELIK = {
    "LOCAL_LLM_BASE_URL": "http://gpu:8000/v1",
    "LOCAL_GENERAL_MODEL": "qwen3:8b",
    "GEMINI_API_KEY": "k",
    "GEMINI_MODEL": "g",
}

CASES: list[dict[str, Any]] = YAML(typ="safe", pure=True).load(CASES_FILE.read_text(encoding="utf-8")) or []


def _cells(case: dict[str, Any]) -> list[tuple[DataClass, str | None]]:
    if case.get("matrix"):
        return [(DataClass(k), v) for k, v in case["matrix"].items()]
    return [(DataClass(case.get("data_class", "public")), (case.get("expect") or {}).get("model"))]


PARAMS = [pytest.param(c, dc, model, id=f"{c['id']}[{dc.value}]") for c in CASES for dc, model in _cells(c)]


async def _route(case: dict[str, Any], data_class: DataClass) -> Route:
    loaded = load_policy_dir(ROOT / "policy")
    policy = loaded.policy
    if case.get("bielik") == "unavailable":
        table = ConnectorRegistry(environ=ENV_NO_BIELIK).table_for(policy, "no-bielik")
    else:
        table = ConnectorRegistry(deterministic=True).table_for(policy, loaded.version)
    usable = await PermissiveAccess(lambda: policy).usable_models(None)  # type: ignore[arg-type]
    if (case.get("principal") or {}).get("bielik") is False:
        usable.pop(BIELIK)
    request = RouteRequest(requested="auto", data_class=data_class, usable=usable, prompt=case["input"])
    return Router(policy, table).route(request)


@pytest.mark.parametrize(("case", "data_class", "model"), PARAMS)
async def test_polish_legal_routing_case(case: dict[str, Any], data_class: DataClass, model: str | None) -> None:
    route = await _route(case, data_class)
    expect = case.get("expect") or {}
    if model is not None:
        assert route.info.model == model, route.info.reason
    if "tier" in expect:
        assert route.info.tier.value == expect["tier"], route.info.reason
    via_specialist = route.info.factors.get("specialist") == BIELIK
    assert via_specialist == bool(expect.get("specialist")), route.info.reason
    if via_specialist:
        assert route.info.factors["specialist_method"] in {"detector", "knn"}
    assert case["input"] not in route.info.reason  # the trace never carries the prompt
    if data_class in (DataClass.confidential, DataClass.restricted):
        assert route.info.tier.value == "local", route.info.reason  # confidential data never reaches the cloud


def test_cases_are_paired_and_numerous_enough() -> None:
    ids = {c["id"] for c in CASES}
    assert len(ids) == len(CASES)
    caught = [c for c in CASES if c["kind"] == "negative"]
    passed = [c for c in CASES if c["kind"] == "positive"]
    assert len(caught) >= 5 and len(passed) >= 5
    by_id = {c["id"]: c for c in CASES}
    for c in CASES:
        assert c["pair"] in ids and by_id[c["pair"]]["kind"] != c["kind"], c["id"]
        assert c["control"] == "ROUTE-PL-LEGAL" and (c.get("matrix") or c.get("expect"))
